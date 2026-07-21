using TlsClient;

var url = args.Length == 0 ? "https://example.com/" : args[0];

await using var session = new TlsSession(TlsPresets.Chrome133);

var response = await session.GetAsync(url);
response.EnsureSuccessStatusCode();

Console.WriteLine(
    $"HTTP/{response.HttpVersion} {(int)response.StatusCode} {response.ReasonPhrase}");
Console.WriteLine(
    $"{response.Tls.ProtocolVersion} / {response.Tls.CipherSuite} / " +
    $"{response.Tls.ApplicationProtocol} / {response.Tls.ClientHelloProfile}");
Console.WriteLine(response.Text);
