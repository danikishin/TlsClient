using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsSessionPersistenceTests
{
    [Fact]
    public async Task ProtectedState_ResumesAcrossIndependentTlsSessionsAndRotatedKeys()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var serverProtector = new Tls13ServerSessionTicketProtector(
            "server-v1",
            RandomNumberGenerator.GetBytes(32));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var serverTask = ServeConnectionsAsync(
            listener,
            credential,
            serverProtector,
            connectionCount: 2,
            timeout.Token);

        var julyKey = RandomNumberGenerator.GetBytes(32);
        byte[] persisted;
        using (var july = new Tls13SessionStateProtector("2026-07", julyKey))
        {
            await using var first = new TlsSession(CreateOptions(certificates.Root));
            var response = await first.GetAsync(
                $"https://localhost:{port}/first",
                timeout.Token);

            Assert.False(response.Tls.SessionWasResumed);
            Assert.True(first.CachedTls13SessionCount > 0);
            persisted = first.ExportTls13SessionState(july);
        }

        using var august = new Tls13SessionStateProtector(
            "2026-08",
            RandomNumberGenerator.GetBytes(32));
        august.AddDecryptionKey("2026-07", julyKey);
        CryptographicOperations.ZeroMemory(julyKey);

        await using var second = new TlsSession(CreateOptions(certificates.Root));
        second.ImportTls13SessionState(persisted, august);
        Assert.True(second.CachedTls13SessionCount > 0);
        var resumedResponse = await second.GetAsync(
            $"https://localhost:{port}/second",
            timeout.Token);
        var serverResumption = await serverTask;

        Assert.True(resumedResponse.Tls.SessionWasResumed);
        Assert.Equal([false, true], serverResumption);
    }

    [Fact]
    public void ProtectedState_RejectsTamperingWithoutPartialImport()
    {
        using var protector = new Tls13SessionStateProtector(
            "test",
            RandomNumberGenerator.GetBytes(32));
        using var source = new TlsSession();
        var state = source.ExportTls13SessionState(protector);
        state[^1] ^= 0xff;
        using var destination = new TlsSession();

        Assert.ThrowsAny<CryptographicException>(() =>
            destination.ImportTls13SessionState(state, protector));
        Assert.Equal(0, destination.CachedTls13SessionCount);
    }

    private static TlsSessionOptions CreateOptions(X509Certificate2 root) => new()
    {
        Profile = TlsProfiles.Modern,
        HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
        ConfigureTls = tls =>
        {
            tls.CertificateValidation.CustomTrustRoots = [root];
            tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
            tls.CertificateValidation.DisableCertificateDownloads = true;
        },
    };

    private static async Task<bool[]> ServeConnectionsAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Tls13ServerSessionTicketProtector protector,
        int connectionCount,
        CancellationToken cancellationToken)
    {
        var resumed = new bool[connectionCount];
        for (var index = 0; index < connectionCount; index++)
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                AlpnProtocols = ["http/1.1"],
                RequireAlpn = true,
                SessionTicketProtector = protector,
                AutomaticSessionTicketCount = 1,
            });
            await server.AuthenticateAsync(
                client.GetStream(),
                leaveOpen: false,
                cancellationToken);
            resumed[index] = server.SessionWasResumed;
            await using var stream = server.AsStream(leaveServerOpen: true);
            await ReadHeadersAsync(stream, cancellationToken);
            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
                cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        return resumed;
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
