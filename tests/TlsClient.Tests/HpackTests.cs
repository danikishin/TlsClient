using System.Text;

namespace TlsClient.Tests;

public sealed class HpackTests
{
    [Fact]
    public void HuffmanDecoder_DecodesRfc7541Vector()
    {
        var source = Convert.FromHexString("f1e3c2e5f23a6ba0ab90f4ff");
        var destination = new byte[32];

        var length = HpackHuffman.Decode(source, ref destination);

        Assert.Equal("www.example.com", Encoding.ASCII.GetString(destination, 0, length));
    }

    [Fact]
    public void Decoder_PreservesDynamicTableAcrossRfc7541RequestBlocks()
    {
        var decoder = new HpackDecoder(4096);

        var first = decoder.Decode(
            Convert.FromHexString("828684410f7777772e6578616d706c652e636f6d"),
            16 * 1024);
        var second = decoder.Decode(
            Convert.FromHexString("828684be58086e6f2d6361636865"),
            16 * 1024);

        Assert.Collection(
            first,
            header => Assert.Equal(new HpackHeader(":method", "GET"), header),
            header => Assert.Equal(new HpackHeader(":scheme", "http"), header),
            header => Assert.Equal(new HpackHeader(":path", "/"), header),
            header => Assert.Equal(new HpackHeader(":authority", "www.example.com"), header));
        Assert.Contains(second, header =>
            header.Name == ":authority" && header.Value == "www.example.com");
        Assert.Contains(second, header =>
            header.Name == "cache-control" && header.Value == "no-cache");
    }

    [Fact]
    public void Encoder_RoundTripsHuffmanAndSensitiveFields()
    {
        var encoder = new HpackEncoder();
        var decoder = new HpackDecoder(4096);
        HpackHeader[] expected =
        [
            new(":method", "GET"),
            new(":scheme", "https"),
            new(":authority", "www.example.com"),
            new(":path", "/resource?q=managed"),
            new("authorization", "Bearer secret", Sensitive: true),
        ];

        var block = encoder.Encode(expected);
        var actual = decoder.Decode(block, 16 * 1024);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Decoder_RejectsTableResizeAfterHeaderField()
    {
        var decoder = new HpackDecoder(4096);

        Assert.Throws<TlsHttpProtocolException>(() =>
            decoder.Decode([0x82, 0x20], 16 * 1024));
    }

    [Fact]
    public void Encoder_EmitsDynamicTableSizeChangesAtBlockStart()
    {
        var encoder = new HpackEncoder();
        var decoder = new HpackDecoder(4096);
        _ = decoder.Decode(encoder.Encode([new("x-state", "one")]), 16 * 1024);

        encoder.SetMaximumDynamicTableSize(0);
        var reduced = encoder.Encode([new HpackHeader("x-state", "two")]);
        var reducedHeaders = decoder.Decode(reduced, 16 * 1024);
        encoder.SetMaximumDynamicTableSize(4096);
        var restored = encoder.Encode([new HpackHeader("x-state", "three")]);
        var restoredHeaders = decoder.Decode(restored, 16 * 1024);

        Assert.Equal(0x20, reduced[0]);
        Assert.Equal(0x20, restored[0] & 0xe0);
        Assert.Equal("two", Assert.Single(reducedHeaders).Value);
        Assert.Equal("three", Assert.Single(restoredHeaders).Value);
    }
}
