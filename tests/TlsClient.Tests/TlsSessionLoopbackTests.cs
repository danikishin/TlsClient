using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsSessionLoopbackTests
{
    [Fact]
    public async Task Session_FollowsRedirectWithCookieOnReusedSharpTlsConnection()
    {
        using var certificates = TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var serverTask = RunServerAsync(
            listener,
            serverCredential,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        using (var publicKey = certificates.Leaf.GetRSAPublicKey()!)
        {
            options.CertificatePins.Add(
                "127.0.0.1",
                Convert.ToBase64String(SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo())));
        }
        await using var session = new TlsSession(options);
        var url = $"https://127.0.0.1:{port}/";

        var response = await session.GetAsync(url, timeout.Token);
        var secondRequest = await serverTask;

        Assert.Equal("two", response.Text);
        Assert.Single(response.History);
        Assert.Equal(HttpStatusCode.Found, response.History[0].StatusCode);
        Assert.Equal(new Uri($"https://127.0.0.1:{port}/next"), response.Url);
        Assert.Contains("Cookie: sid=managed", secondRequest, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("GET /next HTTP/1.1", secondRequest, StringComparison.Ordinal);
        Assert.Equal("http/1.1", response.Tls.ApplicationProtocol);
        Assert.Equal("modern-tls13", response.Tls.ClientHelloProfile);
    }

    [Fact]
    public async Task Session_ExplicitlyBypassesUntrustedServerCertificateValidation()
    {
        Assert.False(new TlsSessionOptions().DangerouslySkipServerCertificateValidation);

        using var certificates = TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var serverTask = RunSingleResponseServerAsync(
            listener,
            serverCredential,
            timeout.Token);
        var configureTlsObservedBypass = false;
        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            DangerouslySkipServerCertificateValidation = true,
            ConfigureTls = tls =>
            {
                configureTlsObservedBypass = tls.CertificateValidation
                    .DangerouslySkipServerCertificateValidation;
            },
        };
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://127.0.0.1:{port}/dangerous-validation-bypass",
            timeout.Token);
        await serverTask;

        Assert.True(configureTlsObservedBypass);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("proxy", response.Text);
    }

    [Fact]
    public async Task Session_TunnelsSharpTlsThroughHttpConnectProxy()
    {
        using var certificates = TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var originListener = new TcpListener(IPAddress.Loopback, 0);
        using var proxyListener = new TcpListener(IPAddress.Loopback, 0);
        originListener.Start();
        proxyListener.Start();
        var originPort = ((IPEndPoint)originListener.LocalEndpoint).Port;
        var proxyPort = ((IPEndPoint)proxyListener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var originTask = RunSingleResponseServerAsync(
            originListener,
            serverCredential,
            timeout.Token);
        var proxyTask = RunProxyAsync(
            proxyListener,
            originPort,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            Proxy = TlsProxy.Http($"http://user:password@127.0.0.1:{proxyPort}"),
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://127.0.0.1:{originPort}/proxy",
            timeout.Token);
        var connectRequest = await proxyTask;
        await originTask;

        Assert.Equal("proxy", response.Text);
        Assert.StartsWith(
            $"CONNECT 127.0.0.1:{originPort} HTTP/1.1",
            connectRequest,
            StringComparison.Ordinal);
        Assert.Contains("Proxy-Authorization: Basic ", connectRequest, StringComparison.Ordinal);
    }

    private static async Task<string> RunServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);

        _ = await ReadRequestHeadersAsync(stream, cancellationToken);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 302 Found\r\n" +
            "Content-Length: 0\r\n" +
            "Location: /next\r\n" +
            "Set-Cookie: sid=managed; Path=/; Secure; HttpOnly\r\n" +
            "Connection: keep-alive\r\n\r\n",
            cancellationToken);

        var secondRequest = await ReadRequestHeadersAsync(stream, cancellationToken);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\n" +
            "Content-Length: 3\r\n" +
            "Connection: close\r\n\r\n" +
            "two",
            cancellationToken);
        listener.Stop();
        return secondRequest;
    }

    private static async Task RunSingleResponseServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        _ = await ReadRequestHeadersAsync(stream, cancellationToken);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\n" +
            "Content-Length: 5\r\n" +
            "Connection: close\r\n\r\n" +
            "proxy",
            cancellationToken);
        listener.Stop();
    }

    private static async Task<string> RunProxyAsync(
        TcpListener listener,
        int originPort,
        CancellationToken cancellationToken)
    {
        using var downstreamClient = await listener.AcceptTcpClientAsync(cancellationToken);
        var downstream = downstreamClient.GetStream();
        var connectRequest = await ReadRequestHeadersAsync(downstream, cancellationToken);

        using var upstreamClient = new TcpClient();
        await upstreamClient.ConnectAsync(IPAddress.Loopback, originPort, cancellationToken);
        var upstream = upstreamClient.GetStream();
        await WriteAsciiAsync(
            downstream,
            "HTTP/1.1 200 Connection Established\r\n\r\n",
            cancellationToken);

        var toOrigin = CopyTunnelAsync(downstream, upstream, cancellationToken);
        var toClient = CopyTunnelAsync(upstream, downstream, cancellationToken);
        await Task.WhenAll(toOrigin, toClient);
        listener.Stop();
        return connectRequest;
    }

    private static async Task CopyTunnelAsync(
        Stream source,
        Stream destination,
        CancellationToken cancellationToken)
    {
        try
        {
            await source.CopyToAsync(destination, cancellationToken);
        }
        catch (IOException) when (!cancellationToken.IsCancellationRequested)
        {
            // Either tunnel endpoint may use a TCP reset for teardown after the response.
        }
    }

    private static async Task<string> ReadRequestHeadersAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var one = new byte[1];
        while (bytes.Length < 64 * 1024)
        {
            var read = await stream.ReadAsync(one, cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("The client closed before finishing its request headers.");
            }
            bytes.WriteByte(one[0]);
            if (bytes.Length >= 4)
            {
                var buffer = bytes.GetBuffer();
                var length = (int)bytes.Length;
                if (buffer[length - 4] == '\r' && buffer[length - 3] == '\n' &&
                    buffer[length - 2] == '\r' && buffer[length - 1] == '\n')
                {
                    return Encoding.Latin1.GetString(buffer, 0, length);
                }
            }
        }
        throw new InvalidDataException("Request headers exceeded the test limit.");
    }

    private static async Task WriteAsciiAsync(
        Stream stream,
        string value,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(value), cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    internal sealed class TestCertificates : IDisposable
    {
        private TestCertificates(X509Certificate2 root, X509Certificate2 leaf)
        {
            Root = root;
            Leaf = leaf;
        }

        public X509Certificate2 Root { get; }

        public X509Certificate2 Leaf { get; }

        public static TestCertificates Create()
        {
            using var rootKey = RSA.Create(2048);
            var rootRequest = new CertificateRequest(
                "CN=TlsClient Test Root",
                rootKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                    true));
            rootRequest.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            var root = rootRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(30));

            using var leafKey = RSA.Create(2048);
            var leafRequest = new CertificateRequest(
                "CN=127.0.0.1",
                leafKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            leafRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));
            leafRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            leafRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new("1.3.6.1.5.5.7.3.1") },
                    true));
            var san = new SubjectAlternativeNameBuilder();
            san.AddIpAddress(IPAddress.Loopback);
            san.AddDnsName("localhost");
            leafRequest.CertificateExtensions.Add(san.Build());
            var serial = RandomNumberGenerator.GetBytes(16);
            using var publicLeaf = leafRequest.Create(
                root,
                DateTimeOffset.UtcNow.AddHours(-1),
                DateTimeOffset.UtcNow.AddDays(7),
                serial);
            var leaf = publicLeaf.CopyWithPrivateKey(leafKey);
            return new TestCertificates(root, leaf);
        }

        public void Dispose()
        {
            Leaf.Dispose();
            Root.Dispose();
        }
    }
}
