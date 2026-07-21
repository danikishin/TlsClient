namespace TlsClient.Tests;

public sealed class TlsHeadersTests
{
    [Fact]
    public void Set_IsCaseInsensitiveAndPreservesPosition()
    {
        var headers = new TlsHeaders();
        headers.Set("User-Agent", "first");
        headers.Set("Accept", "*/*");
        headers.Set("user-agent", "second");

        Assert.Equal(2, headers.Count);
        Assert.Equal("second", headers["USER-AGENT"]);
        Assert.Equal(["user-agent", "Accept"], headers.Select(header => header.Key));
    }

    [Fact]
    public void Add_PreservesMultipleValues()
    {
        var headers = new TlsHeaders();
        headers.Add("Accept", "text/html");
        headers.Add("Accept", "application/json");

        Assert.True(headers.TryGetValues("accept", out var values));
        Assert.Equal(["text/html", "application/json"], values);
    }

    [Theory]
    [InlineData("Bad Header", "value")]
    [InlineData("Good", "one\r\nInjected: yes")]
    public void Set_RejectsHeaderInjection(string name, string value)
    {
        var headers = new TlsHeaders();

        Assert.Throws<ArgumentException>(() => headers.Set(name, value));
    }
}
