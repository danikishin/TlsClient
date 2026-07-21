using System.Text;

namespace TlsClient.Tests;

public sealed class Http11RequestWriterTests
{
    [Fact]
    public void SerializeHeaders_UsesOriginFormAndPreferredOrder()
    {
        var request = new BufferedRequest(
            "POST",
            new Uri("https://example.com:8443/a%20b?q=1#ignored"),
            [new HeaderEntry("X-Test", ["request"])],
            [1, 2, 3],
            HasContent: true);

        var bytes = Http11RequestWriter.SerializeHeaders(
            request,
            [new HeaderEntry("Accept", ["*/*"]), new HeaderEntry("X-Test", ["default"])],
            ["Host", "X-Test", "Accept"],
            "sid=abc");
        var text = Encoding.Latin1.GetString(bytes);

        Assert.StartsWith(
            "POST /a%20b?q=1 HTTP/1.1\r\n" +
            "Host: example.com:8443\r\n" +
            "X-Test: request\r\n" +
            "Accept: */*\r\n",
            text,
            StringComparison.Ordinal);
        Assert.Contains("Cookie: sid=abc\r\n", text, StringComparison.Ordinal);
        Assert.Contains("Content-Length: 3\r\n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ignored", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Redirect_StripsOriginBoundHeadersWhenOriginChanges()
    {
        var request = new BufferedRequest(
            "GET",
            new Uri("https://first.example/"),
            [
                new HeaderEntry("Authorization", ["Bearer secret"]),
                new HeaderEntry("Cookie", ["sid=secret"]),
                new HeaderEntry("Host", ["first.example"]),
                new HeaderEntry("Accept", ["*/*"]),
            ],
            [],
            HasContent: false);

        var redirected = request.Redirect(
            new Uri("https://second.example/"),
            "GET",
            dropBody: false,
            originChanged: true);

        Assert.Equal(["Accept"], redirected.Headers.Select(header => header.Name));
    }

    [Fact]
    public void Redirect_StripsOriginBoundSessionHeadersWhenOriginChanges()
    {
        var request = new BufferedRequest(
            "GET",
            new Uri("https://first.example/"),
            [],
            [],
            HasContent: false);
        var redirected = request.Redirect(
            new Uri("https://second.example/"),
            "GET",
            dropBody: false,
            originChanged: true);

        var headers = Http11RequestWriter.MergeHeaders(
            redirected,
            [
                new HeaderEntry("Authorization", ["Bearer default-secret"]),
                new HeaderEntry("Cookie", ["manual=secret"]),
                new HeaderEntry("Host", ["first.example"]),
                new HeaderEntry("Accept", ["*/*"]),
            ],
            "target=safe");

        Assert.DoesNotContain(headers, header => header.Name == "Authorization");
        Assert.DoesNotContain(headers, header => header.Values.Contains("manual=secret"));
        Assert.Contains(headers, header => header.Name == "Host" &&
            header.Values.SequenceEqual(["second.example"]));
        Assert.Contains(headers, header => header.Name == "Cookie" &&
            header.Values.SequenceEqual(["target=safe"]));
        Assert.Contains(headers, header => header.Name == "Accept");
    }
}
