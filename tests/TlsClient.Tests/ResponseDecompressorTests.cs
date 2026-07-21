using System.IO.Compression;
using System.Text;

namespace TlsClient.Tests;

public sealed class ResponseDecompressorTests
{
    [Fact]
    public async Task DecodeAsync_DecodesGzip()
    {
        var input = Encoding.UTF8.GetBytes("managed all the way down");
        byte[] compressed;
        using (var output = new MemoryStream())
        {
            await using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                await gzip.WriteAsync(input);
            }
            compressed = output.ToArray();
        }
        var headers = new TlsHeaders();
        headers.Set("Content-Encoding", "gzip");

        var (body, decoded) = await ResponseDecompressor.DecodeAsync(
            compressed,
            headers,
            1024,
            CancellationToken.None);

        Assert.True(decoded);
        Assert.Equal(input, body);
    }
}
