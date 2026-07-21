using System.Text;

namespace TlsClient;

internal sealed class BufferedHttpReader
{
    private readonly Stream _stream;
    private readonly byte[] _buffer = new byte[8192];
    private int _offset;
    private int _count;

    public BufferedHttpReader(Stream stream)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    public async ValueTask<HttpLine?> ReadLineAsync(
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var line = new MemoryStream(Math.Min(maximumBytes, 256));
        var previousWasCarriageReturn = false;
        while (true)
        {
            var value = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (value < 0)
            {
                if (line.Length == 0 && !previousWasCarriageReturn)
                {
                    return null;
                }
                throw new EndOfStreamException("The HTTP stream ended in the middle of a line.");
            }

            if (previousWasCarriageReturn)
            {
                if (value != '\n')
                {
                    throw new TlsHttpProtocolException("HTTP lines must end with CRLF.");
                }
                return new HttpLine(Encoding.Latin1.GetString(line.ToArray()), checked((int)line.Length + 2));
            }

            if (value == '\r')
            {
                previousWasCarriageReturn = true;
                continue;
            }
            if (value == '\n')
            {
                throw new TlsHttpProtocolException("A bare LF is not a valid HTTP/1.1 line ending.");
            }
            if (line.Length >= maximumBytes)
            {
                throw new TlsHttpProtocolException("An HTTP line exceeded the configured limit.");
            }
            line.WriteByte((byte)value);
        }
    }

    public async ValueTask ReadExactlyAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var written = 0;
        while (written < destination.Length)
        {
            var read = await ReadAsync(destination[written..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The HTTP body ended before its declared length.");
            }
            written += read;
        }
    }

    public async ValueTask<int> ReadAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        if (destination.IsEmpty)
        {
            return 0;
        }
        if (_offset < _count)
        {
            var available = Math.Min(destination.Length, _count - _offset);
            _buffer.AsMemory(_offset, available).CopyTo(destination);
            _offset += available;
            return available;
        }

        return await _stream.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        if (_offset == _count)
        {
            _count = await _stream.ReadAsync(_buffer, cancellationToken).ConfigureAwait(false);
            _offset = 0;
            if (_count == 0)
            {
                return -1;
            }
        }

        return _buffer[_offset++];
    }
}

internal sealed record HttpLine(string Text, int WireLength);
