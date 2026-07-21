using System.Buffers;
using System.Text;

namespace TlsClient;

internal readonly record struct HpackHeader(string Name, string Value, bool Sensitive = false);

internal static class HpackStaticTable
{
    public static readonly HpackHeader[] Entries =
    [
        new(":authority", ""),
        new(":method", "GET"),
        new(":method", "POST"),
        new(":path", "/"),
        new(":path", "/index.html"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "200"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "304"),
        new(":status", "400"),
        new(":status", "404"),
        new(":status", "500"),
        new("accept-charset", ""),
        new("accept-encoding", "gzip, deflate"),
        new("accept-language", ""),
        new("accept-ranges", ""),
        new("accept", ""),
        new("access-control-allow-origin", ""),
        new("age", ""),
        new("allow", ""),
        new("authorization", ""),
        new("cache-control", ""),
        new("content-disposition", ""),
        new("content-encoding", ""),
        new("content-language", ""),
        new("content-length", ""),
        new("content-location", ""),
        new("content-range", ""),
        new("content-type", ""),
        new("cookie", ""),
        new("date", ""),
        new("etag", ""),
        new("expect", ""),
        new("expires", ""),
        new("from", ""),
        new("host", ""),
        new("if-match", ""),
        new("if-modified-since", ""),
        new("if-none-match", ""),
        new("if-range", ""),
        new("if-unmodified-since", ""),
        new("last-modified", ""),
        new("link", ""),
        new("location", ""),
        new("max-forwards", ""),
        new("proxy-authenticate", ""),
        new("proxy-authorization", ""),
        new("range", ""),
        new("referer", ""),
        new("refresh", ""),
        new("retry-after", ""),
        new("server", ""),
        new("set-cookie", ""),
        new("strict-transport-security", ""),
        new("transfer-encoding", ""),
        new("user-agent", ""),
        new("vary", ""),
        new("via", ""),
        new("www-authenticate", ""),
    ];
}

internal sealed class HpackEncoder
{
    private readonly List<HpackHeader> _dynamicTable = [];
    private int _dynamicTableSize;
    private uint _maximumDynamicTableSize = 4096;
    private bool _pendingDynamicTableSizeUpdate;

    public void SetMaximumDynamicTableSize(uint value)
    {
        var boundedValue = Math.Min(value, 16U * 1024 * 1024);
        if (_maximumDynamicTableSize == boundedValue)
        {
            return;
        }
        _maximumDynamicTableSize = boundedValue;
        _pendingDynamicTableSizeUpdate = true;
        Evict();
    }

    public byte[] Encode(IEnumerable<HpackHeader> headers)
    {
        var output = new ArrayBufferWriter<byte>();
        if (_pendingDynamicTableSizeUpdate)
        {
            WriteInteger(output, checked((int)_maximumDynamicTableSize), 5, 0x20);
            _pendingDynamicTableSizeUpdate = false;
        }
        foreach (var header in headers)
        {
            ValidateHeader(header);
            var exactIndex = FindExact(header.Name, header.Value);
            if (exactIndex != 0)
            {
                WriteInteger(output, exactIndex, 7, 0x80);
                continue;
            }

            var nameIndex = FindName(header.Name);
            if (header.Sensitive)
            {
                WriteInteger(output, nameIndex, 4, 0x10);
            }
            else
            {
                WriteInteger(output, nameIndex, 6, 0x40);
            }
            if (nameIndex == 0)
            {
                WriteString(output, header.Name);
            }
            WriteString(output, header.Value);
            if (!header.Sensitive)
            {
                Add(header);
            }
        }
        return output.WrittenSpan.ToArray();
    }

    private int FindExact(string name, string value)
    {
        for (var index = 0; index < HpackStaticTable.Entries.Length; index++)
        {
            var header = HpackStaticTable.Entries[index];
            if (header.Name == name && header.Value == value)
            {
                return index + 1;
            }
        }
        for (var index = 0; index < _dynamicTable.Count; index++)
        {
            var header = _dynamicTable[index];
            if (header.Name == name && header.Value == value)
            {
                return HpackStaticTable.Entries.Length + index + 1;
            }
        }
        return 0;
    }

    private int FindName(string name)
    {
        for (var index = 0; index < HpackStaticTable.Entries.Length; index++)
        {
            if (HpackStaticTable.Entries[index].Name == name)
            {
                return index + 1;
            }
        }
        for (var index = 0; index < _dynamicTable.Count; index++)
        {
            if (_dynamicTable[index].Name == name)
            {
                return HpackStaticTable.Entries.Length + index + 1;
            }
        }
        return 0;
    }

    private void Add(HpackHeader header)
    {
        var size = HeaderSize(header);
        if (size > _maximumDynamicTableSize)
        {
            _dynamicTable.Clear();
            _dynamicTableSize = 0;
            return;
        }
        _dynamicTable.Insert(0, header);
        _dynamicTableSize += size;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTableSize > _maximumDynamicTableSize && _dynamicTable.Count != 0)
        {
            var last = _dynamicTable[^1];
            _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
            _dynamicTableSize -= HeaderSize(last);
        }
    }

    private static int HeaderSize(HpackHeader header) =>
        checked(32 + Encoding.UTF8.GetByteCount(header.Name) + Encoding.UTF8.GetByteCount(header.Value));

    private static void ValidateHeader(HpackHeader header)
    {
        if (header.Name.Length == 0 || header.Name.Any(character =>
                character is >= 'A' and <= 'Z' || character is '\0' or '\r' or '\n'))
        {
            throw new HttpRequestException("HTTP/2 header names must be lowercase tokens.");
        }
        if (header.Value.Any(character => character is '\0' or '\r' or '\n'))
        {
            throw new HttpRequestException("HTTP/2 header values cannot contain NUL, CR, or LF.");
        }
    }

    private static void WriteInteger(
        IBufferWriter<byte> output,
        int value,
        int prefixBits,
        byte prefixMask)
    {
        var maximumPrefixValue = (1 << prefixBits) - 1;
        if (value < maximumPrefixValue)
        {
            WriteByte(output, (byte)(prefixMask | value));
            return;
        }

        WriteByte(output, (byte)(prefixMask | maximumPrefixValue));
        value -= maximumPrefixValue;
        while (value >= 128)
        {
            WriteByte(output, (byte)((value & 0x7f) | 0x80));
            value >>= 7;
        }
        WriteByte(output, (byte)value);
    }

    private static void WriteString(IBufferWriter<byte> output, string value)
    {
        var source = Encoding.UTF8.GetBytes(value);
        var encodedBitLength = 0;
        foreach (var item in source)
        {
            encodedBitLength = checked(encodedBitLength + HpackHuffman.Encode(item).bitLength);
        }
        var encodedByteLength = (encodedBitLength + 7) / 8;
        if (encodedByteLength >= source.Length)
        {
            WriteInteger(output, source.Length, 7, 0);
            output.Write(source);
            return;
        }

        WriteInteger(output, encodedByteLength, 7, 0x80);
        ulong accumulator = 0;
        var bits = 0;
        foreach (var item in source)
        {
            var (encoded, bitLength) = HpackHuffman.Encode(item);
            accumulator = accumulator << bitLength | encoded >> (32 - bitLength);
            bits += bitLength;
            while (bits >= 8)
            {
                bits -= 8;
                WriteByte(output, (byte)(accumulator >> bits));
                accumulator &= bits == 0 ? 0 : (1UL << bits) - 1;
            }
        }
        if (bits != 0)
        {
            var padding = 8 - bits;
            WriteByte(output, (byte)(accumulator << padding | (uint)((1 << padding) - 1)));
        }
    }

    private static void WriteByte(IBufferWriter<byte> output, byte value)
    {
        var span = output.GetSpan(1);
        span[0] = value;
        output.Advance(1);
    }
}

internal sealed class HpackDecoder
{
    private readonly List<HpackHeader> _dynamicTable = [];
    private readonly uint _configuredMaximumDynamicTableSize;
    private uint _maximumDynamicTableSize;
    private int _dynamicTableSize;

    public HpackDecoder(uint maximumDynamicTableSize)
    {
        _configuredMaximumDynamicTableSize = maximumDynamicTableSize;
        _maximumDynamicTableSize = Math.Min(maximumDynamicTableSize, 4096);
    }

    public IReadOnlyList<HpackHeader> Decode(ReadOnlySpan<byte> block, uint maximumHeaderListSize)
    {
        var headers = new List<HpackHeader>();
        var offset = 0;
        long headerListSize = 0;
        var mayResize = true;
        while (offset < block.Length)
        {
            var first = block[offset];
            HpackHeader header;
            if ((first & 0x80) != 0)
            {
                var index = ReadInteger(block, ref offset, 7);
                if (index == 0)
                {
                    throw new TlsHttpProtocolException("HPACK indexed field used index zero.");
                }
                header = Get(index);
            }
            else if ((first & 0x40) != 0)
            {
                var name = ReadName(block, ref offset, 6);
                var value = ReadString(block, ref offset);
                header = new HpackHeader(name, value);
                Add(header);
            }
            else if ((first & 0x20) != 0)
            {
                if (!mayResize)
                {
                    throw new TlsHttpProtocolException(
                        "An HPACK table-size update appeared after a header field.");
                }
                var size = ReadInteger(block, ref offset, 5);
                if ((uint)size > _configuredMaximumDynamicTableSize)
                {
                    throw new TlsHttpProtocolException(
                        "The peer exceeded the advertised HPACK table size.");
                }
                _maximumDynamicTableSize = (uint)size;
                Evict();
                continue;
            }
            else
            {
                var sensitive = (first & 0x10) != 0;
                var name = ReadName(block, ref offset, 4);
                var value = ReadString(block, ref offset);
                header = new HpackHeader(name, value, sensitive);
            }

            mayResize = false;
            headerListSize = checked(
                headerListSize + 32 + Encoding.UTF8.GetByteCount(header.Name) +
                Encoding.UTF8.GetByteCount(header.Value));
            if (headerListSize > maximumHeaderListSize)
            {
                throw new TlsHttpProtocolException("The decoded HTTP/2 header list is too large.");
            }
            headers.Add(header);
        }
        return headers;
    }

    private string ReadName(ReadOnlySpan<byte> block, ref int offset, int prefixBits)
    {
        var index = ReadInteger(block, ref offset, prefixBits);
        return index == 0 ? ReadString(block, ref offset) : Get(index).Name;
    }

    private static int ReadInteger(ReadOnlySpan<byte> source, ref int offset, int prefixBits)
    {
        if ((uint)offset >= (uint)source.Length)
        {
            throw new TlsHttpProtocolException("The HPACK block ended inside an integer.");
        }
        var maximumPrefixValue = (1 << prefixBits) - 1;
        var value = source[offset++] & maximumPrefixValue;
        if (value < maximumPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            if ((uint)offset >= (uint)source.Length || shift > 28)
            {
                throw new TlsHttpProtocolException("The HPACK integer is truncated or too large.");
            }
            var next = source[offset++];
            try
            {
                value = checked(value + ((next & 0x7f) << shift));
            }
            catch (OverflowException exception)
            {
                throw new TlsHttpProtocolException("The HPACK integer is too large.", exception);
            }
            if ((next & 0x80) == 0)
            {
                return value;
            }
            shift += 7;
        }
    }

    private static string ReadString(ReadOnlySpan<byte> block, ref int offset)
    {
        if ((uint)offset >= (uint)block.Length)
        {
            throw new TlsHttpProtocolException("The HPACK block ended before a string.");
        }
        var huffman = (block[offset] & 0x80) != 0;
        var length = ReadInteger(block, ref offset, 7);
        if (length < 0 || length > block.Length - offset)
        {
            throw new TlsHttpProtocolException("The HPACK string length exceeds its header block.");
        }
        var source = block.Slice(offset, length);
        offset += length;
        if (!huffman)
        {
            return DecodeUtf8(source);
        }

        var destination = new byte[Math.Max(32, checked(length * 2))];
        var decodedLength = HpackHuffman.Decode(source, ref destination);
        return DecodeUtf8(destination.AsSpan(0, decodedLength));
    }

    private static string DecodeUtf8(ReadOnlySpan<byte> value)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(value);
        }
        catch (DecoderFallbackException exception)
        {
            throw new TlsHttpProtocolException("An HPACK string is not valid UTF-8.", exception);
        }
    }

    private HpackHeader Get(int index)
    {
        if (index <= HpackStaticTable.Entries.Length)
        {
            return HpackStaticTable.Entries[index - 1];
        }
        var dynamicIndex = index - HpackStaticTable.Entries.Length - 1;
        if ((uint)dynamicIndex >= (uint)_dynamicTable.Count)
        {
            throw new TlsHttpProtocolException("The HPACK index is outside the header table.");
        }
        return _dynamicTable[dynamicIndex];
    }

    private void Add(HpackHeader header)
    {
        var size = HeaderSize(header);
        if (size > _maximumDynamicTableSize)
        {
            _dynamicTable.Clear();
            _dynamicTableSize = 0;
            return;
        }
        _dynamicTable.Insert(0, header);
        _dynamicTableSize += size;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTableSize > _maximumDynamicTableSize && _dynamicTable.Count != 0)
        {
            var last = _dynamicTable[^1];
            _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
            _dynamicTableSize -= HeaderSize(last);
        }
    }

    private static int HeaderSize(HpackHeader header) =>
        checked(32 + Encoding.UTF8.GetByteCount(header.Name) + Encoding.UTF8.GetByteCount(header.Value));
}
