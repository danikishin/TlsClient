using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsEchDnsLoopbackTests
{
    [Fact]
    public async Task Session_CompletesHttpsDiscoveryBeforeDirectFallbackConnection()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var dnsServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var tlsListener = new TcpListener(IPAddress.Loopback, 0);
        tlsListener.Start();
        var dnsEndpoint = (IPEndPoint)dnsServer.Client.LocalEndPoint!;
        var tlsPort = ((IPEndPoint)tlsListener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var dnsTask = AnswerNoDataAsync(dnsServer, timeout.Token);
        var tlsTask = ServeHttp11Async(tlsListener, credential, timeout.Token);
        var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
        {
            NameServers = [dnsEndpoint],
            SupportedAlpnProtocols = ["http/1.1"],
            QueryTimeout = TimeSpan.FromSeconds(3),
        });
        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            EchDnsResolver = resolver,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            DnsResolver = static (_, _) => ValueTask.FromResult<IReadOnlyList<IPAddress>>(
                [IPAddress.Loopback]),
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://localhost:{tlsPort}/ech-discovery",
            timeout.Token);
        var queryName = await dnsTask;
        await tlsTask;

        Assert.Equal("ech-dns", response.Text);
        Assert.False(response.Tls.EncryptedClientHelloAccepted);
        Assert.Equal($"_{tlsPort}._https.localhost", queryName);
    }

    [Fact]
    public void Session_RejectsRoutesThatCannotPreserveEchDiscovery()
    {
        var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
        {
            NameServers = [new IPEndPoint(IPAddress.Loopback, 53)],
            SupportedAlpnProtocols = ["h2", "http/1.1"],
        });
        var withProxy = new TlsSessionOptions
        {
            EchDnsResolver = resolver,
            Proxy = TlsProxy.Http("http://127.0.0.1:8080"),
        };
        var withRoller = new TlsSessionOptions
        {
            EchDnsResolver = resolver,
            ProfileRoller = new TlsProfileRoller(),
        };

        Assert.Throws<InvalidOperationException>(() => new TlsSession(withProxy));
        Assert.Throws<InvalidOperationException>(() => new TlsSession(withRoller));
    }

    private static async Task<string> AnswerNoDataAsync(
        UdpClient server,
        CancellationToken cancellationToken)
    {
        var request = await server.ReceiveAsync(cancellationToken);
        var query = request.Buffer;
        if (query.Length < 17)
        {
            throw new InvalidDataException("DNS query is truncated.");
        }

        var offset = 12;
        var labels = new List<string>();
        while (true)
        {
            var length = query[offset++];
            if (length == 0)
            {
                break;
            }
            if (offset + length > query.Length)
            {
                throw new InvalidDataException("DNS query name is truncated.");
            }
            labels.Add(Encoding.ASCII.GetString(query, offset, length));
            offset += length;
        }
        var questionEnd = checked(offset + 4);
        if (questionEnd > query.Length)
        {
            throw new InvalidDataException("DNS question is truncated.");
        }

        var response = new byte[questionEnd];
        query.AsSpan(0, questionEnd).CopyTo(response);
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
        await server.SendAsync(response, request.RemoteEndPoint, cancellationToken);
        return string.Join('.', labels);
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

        await stream.WriteAsync(
            Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nech-dns"),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}
