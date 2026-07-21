using System.Text;

namespace TlsClient.Tests;

public sealed class Http11ResponseReaderTests
{
    [Fact]
    public async Task ReadAsync_ParsesInformationalAndFixedResponse()
    {
        var parsed = await ParseAsync(
            "HTTP/1.1 100 Continue\r\nX-Ignored: yes\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello");

        Assert.Equal(200, (int)parsed.StatusCode);
        Assert.Equal("hello", Encoding.ASCII.GetString(parsed.Body));
        Assert.Equal("yes", parsed.Headers["x-test"]);
        Assert.True(parsed.Reusable);
    }

    [Fact]
    public async Task ReadAsync_ParsesChunkedBodyAndTrailers()
    {
        var parsed = await ParseAsync(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
            "5\r\nhello\r\n6;ext=yes\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n");

        Assert.Equal("hello world", Encoding.ASCII.GetString(parsed.Body));
        Assert.Equal("done", parsed.Trailers["x-trailer"]);
    }

    [Fact]
    public async Task ReadAsync_RejectsConflictingContentLengths()
    {
        await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await ParseAsync(
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"));
    }

    [Fact]
    public async Task ReadAsync_RejectsBodyOverLimit()
    {
        await Assert.ThrowsAsync<TlsHttpProtocolException>(async () =>
            await ParseAsync(
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n123456",
                maximumBodyBytes: 5));
    }

    private static async Task<ParsedHttpResponse> ParseAsync(
        string wire,
        int maximumBodyBytes = 1024)
    {
        await using var stream = new MemoryStream(Encoding.Latin1.GetBytes(wire));
        return await Http11ResponseReader.ReadAsync(
            new BufferedHttpReader(stream),
            "GET",
            16 * 1024,
            100,
            maximumBodyBytes,
            CancellationToken.None);
    }
}
