using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsClientCertificateTests
{
    [Fact]
    public async Task HostSelection_CompletesMutualTlsAndCertificatePinHelperMatches()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var clientLeaf = CreateClientCertificate(certificates.Root);
        using var clientCredential = new TlsClientCertificate(
            clientLeaf,
            [certificates.Root]);
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = ServeMutualTlsAsync(
            listener,
            serverCredential,
            certificates.Root,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        options.ClientCertificates.Set("LOCALHOST.", clientCredential);
        options.CertificatePins.Add("localhost", certificates.Leaf);
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://localhost:{port}/mtls",
            timeout.Token);
        var peerCertificateCount = await serverTask;

        Assert.Equal("mtls", response.Text);
        Assert.True(peerCertificateCount > 0);
        Assert.StartsWith(
            "sha256/",
            TlsCertificatePins.CreateSha256Pin(certificates.Leaf),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Selector_CannotBeCombinedWithMappings()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var clientLeaf = CreateClientCertificate(certificates.Root);
        using var credential = new TlsClientCertificate(clientLeaf, [certificates.Root]);
        var options = new TlsSessionOptions();
        options.ClientCertificates.Set("localhost", credential);
        options.ClientCertificates.Selector = static (_, _) =>
            ValueTask.FromResult<TlsClientCertificate?>(null);

        Assert.Throws<InvalidOperationException>(() => new TlsSession(options));
    }

    [Fact]
    public void IPv6LiteralMapping_IsNormalizedWithoutBeingRejectedAsAHostPort()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var clientLeaf = CreateClientCertificate(certificates.Root);
        using var credential = new TlsClientCertificate(clientLeaf, [certificates.Root]);
        var options = new TlsSessionOptions();

        options.ClientCertificates.Set("[::1]", credential);

        Assert.Equal(1, options.ClientCertificates.Count);
        using var session = new TlsSession(options);
    }

    private static X509Certificate2 CreateClientCertificate(X509Certificate2 root)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=TlsClient mTLS Client",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.2") },
                true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var publicLeaf = request.Create(
            root,
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(7),
            RandomNumberGenerator.GetBytes(16));
        return publicLeaf.CopyWithPrivateKey(key);
    }

    private static async Task<int> ServeMutualTlsAsync(
        TcpListener listener,
        TlsServerCertificate serverCredential,
        X509Certificate2 clientRoot,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = serverCredential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            ClientAuthentication = TlsServerClientAuthenticationMode.Require,
            ClientCertificateValidation = new CustomTlsCertificateValidationOptions
            {
                CustomTrustRoots = [clientRoot],
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true,
            },
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(client.GetStream(), leaveOpen: false, cancellationToken);
        var peerCertificateCount = server.PeerCertificateChain.Count;
        await using var stream = server.AsStream(leaveServerOpen: true);
        await ReadHeadersAsync(stream, cancellationToken);
        await stream.WriteAsync(
            Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nmtls"),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        return peerCertificateCount;
    }

    private static async Task ReadHeadersAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            length += read;
            if (length >= 4 && buffer.AsSpan(0, length).EndsWith("\r\n\r\n"u8))
            {
                return;
            }
        }
        throw new InvalidDataException("Request headers exceeded the test limit.");
    }
}
