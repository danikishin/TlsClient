using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsProfileRollerTests
{
    [Fact]
    public void RandomizedProfile_IsCoherentAndDeterministicWhenExplicitlyRequestedForTesting()
    {
        var seed = SHA256.HashData("randomized-profile"u8);
        var first = TlsProfiles.CreateRandomizedForTesting("random-a", seed);
        var second = TlsProfiles.CreateRandomizedForTesting("random-b", seed);

        Assert.Equal(
            TlsProfileCatalog.Inspect(first).SpecificationSha256,
            TlsProfileCatalog.Inspect(second).SpecificationSha256);
        Assert.Equal(
            ["http/1.1"],
            first.GetClientHello("example.com", TlsHttpVersionPolicy.Http11Only).Spec.AlpnProtocols);
        Assert.Equal(
            ["h2"],
            first.GetClientHello("example.com", TlsHttpVersionPolicy.Http2Only).Spec.AlpnProtocols);
    }

    [Fact]
    public async Task Roller_ConnectsThroughSharpTlsAndCachesTheSuccessfulOrigin()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = ServeHttp11Async(listener, credential, timeout.Token);

        var candidate = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithAlpn("http/1.1"));
        var roller = new TlsProfileRoller(
            "test-roller",
            new ClientHelloRollerOptions
            {
                MaximumAttempts = 1,
                IncludeRandomizedProfile = false,
                CandidateProfiles = [candidate],
            });
        var options = new TlsSessionOptions
        {
            ProfileRoller = roller,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        TlsClientHelloObservation? observation = null;
        TlsClientHello.Observe(options, value => observation = value);
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://localhost:{port}/roller",
            timeout.Token);
        await serverTask;

        Assert.Equal("roller", response.Text);
        Assert.Equal("test-roller", response.Tls.ClientHelloProfile);
        Assert.Equal("http/1.1", response.Tls.ApplicationProtocol);
        Assert.Equal(1, roller.CachedOriginCount);
        Assert.NotNull(observation);
        Assert.StartsWith("t13d", observation.Fingerprint.Ja4, StringComparison.Ordinal);
        Assert.Equal(TlsClientHelloFlight.Initial, observation.Flight);

        roller.ClearCache();
        Assert.Equal(0, roller.CachedOriginCount);
    }

    [Fact]
    public void Roller_RejectsSessionRoutesItCannotHonor()
    {
        var withProxy = new TlsSessionOptions
        {
            ProfileRoller = new TlsProfileRoller(),
            Proxy = TlsProxy.Http("http://127.0.0.1:8080"),
        };
        var withDns = new TlsSessionOptions
        {
            ProfileRoller = new TlsProfileRoller(),
            DnsResolver = static (_, _) => ValueTask.FromResult<IReadOnlyList<IPAddress>>(
                [IPAddress.Loopback]),
        };
        var withObserver = new TlsSessionOptions
        {
            ProfileRoller = new TlsProfileRoller(),
            ConnectObserver = static _ => { },
        };
        var withExactSessionVersion = new TlsSessionOptions
        {
            ProfileRoller = new TlsProfileRoller(),
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
        };

        Assert.Throws<InvalidOperationException>(() => new TlsSession(withProxy));
        Assert.Throws<InvalidOperationException>(() => new TlsSession(withDns));
        Assert.Throws<InvalidOperationException>(() => new TlsSession(withObserver));
        Assert.Throws<InvalidOperationException>(() => new TlsSession(withExactSessionVersion));
    }

    [Fact]
    public async Task Roller_RejectsExactPerRequestHttpVersionBeforeConnecting()
    {
        var roller = new TlsProfileRoller(
            "exact-version-test",
            new ClientHelloRollerOptions
            {
                MaximumAttempts = 1,
                IncludeRandomizedProfile = false,
                CandidateProfiles = [ClientHelloProfiles.ModernTls13],
            });
        await using var session = new TlsSession(new TlsSessionOptions
        {
            ProfileRoller = roller,
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://127.0.0.1:1/")
        {
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => session.SendAsync(request));

        Assert.Contains("PreferHttp2", exception.Message, StringComparison.Ordinal);
    }

    private static async Task ServeHttp11Async(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(client.GetStream(), leaveOpen: false, cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);

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
                break;
            }
        }

        var response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nroller");
        await stream.WriteAsync(response, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}
