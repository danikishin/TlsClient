using System.Net;

namespace TlsClient.Tests;

public sealed class Http3EvaluationTests
{
    [Fact]
    public async Task Http3Request_IsRejectedInsteadOfSilentlyDowngraded()
    {
        await using var session = new TlsSession();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/")
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        var exception = await Assert.ThrowsAsync<NotSupportedException>(
            () => session.SendAsync(request));

        Assert.Contains("HTTP/1.1 and HTTP/2", exception.Message, StringComparison.Ordinal);
    }
}
