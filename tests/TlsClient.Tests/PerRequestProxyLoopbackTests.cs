using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class PerRequestProxyLoopbackTests
{
    [Fact]
    public async Task RequestSpecificSocks5Proxy_UsesSeparatePooledRoute()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var originListener = new TcpListener(IPAddress.Loopback, 0);
        using var proxyListener = new TcpListener(IPAddress.Loopback, 0);
        originListener.Start();
        proxyListener.Start();
        var originPort = ((IPEndPoint)originListener.LocalEndpoint).Port;
        var proxyPort = ((IPEndPoint)proxyListener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var originTask = RunOriginAsync(
            originListener,
            credential,
            timeout.Token);
        var proxyTask = RunSocks5ProxyAsync(
            proxyListener,
            originPort,
            timeout.Token);
        await using var session = new TlsSession(new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        });

        using var directRequest = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://127.0.0.1:{originPort}/direct");
        var direct = await session.SendAsync(directRequest, timeout.Token);

        using var proxiedRequest = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://127.0.0.1:{originPort}/proxied");
        TlsRequestOptions.For(proxiedRequest).Proxy =
            TlsProxy.Socks5($"socks5://127.0.0.1:{proxyPort}");
        var proxied = await session.SendAsync(proxiedRequest, timeout.Token);

        var requestedEndpoint = await proxyTask;
        await originTask;
        Assert.Equal("1", direct.Text);
        Assert.Equal("2", proxied.Text);
        Assert.Equal(IPAddress.Loopback, requestedEndpoint.Address);
        Assert.Equal(originPort, requestedEndpoint.Port);
    }

    private static async Task RunOriginAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        for (var index = 1; index <= 2; index++)
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = credential,
                AlpnProtocols = ["http/1.1"],
                RequireAlpn = true,
                AutomaticSessionTicketCount = 0,
            });
            await server.AuthenticateAsync(client.GetStream(), false, cancellationToken);
            await using var stream = server.AsStream(leaveServerOpen: true);
            _ = await ReadHeadersAsync(stream, cancellationToken);
            await WriteAsciiAsync(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n" + index,
                cancellationToken);
        }
        listener.Stop();
    }

    private static async Task<IPEndPoint> RunSocks5ProxyAsync(
        TcpListener listener,
        int originPort,
        CancellationToken cancellationToken)
    {
        using var downstreamClient = await listener.AcceptTcpClientAsync(cancellationToken);
        var downstream = downstreamClient.GetStream();
        var greetingHeader = new byte[2];
        await ReadExactlyAsync(downstream, greetingHeader, cancellationToken);
        var methods = new byte[greetingHeader[1]];
        await ReadExactlyAsync(downstream, methods, cancellationToken);
        Assert.Equal(5, greetingHeader[0]);
        Assert.Contains((byte)0, methods);
        await downstream.WriteAsync(new byte[] { 5, 0 }, cancellationToken);

        var connectHeader = new byte[4];
        await ReadExactlyAsync(downstream, connectHeader, cancellationToken);
        Assert.Equal([5, 1, 0, 1], connectHeader);
        var addressBytes = new byte[4];
        await ReadExactlyAsync(downstream, addressBytes, cancellationToken);
        var portBytes = new byte[2];
        await ReadExactlyAsync(downstream, portBytes, cancellationToken);
        var requested = new IPEndPoint(
            new IPAddress(addressBytes),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(portBytes));
        Assert.Equal(originPort, requested.Port);

        using var upstreamClient = new TcpClient();
        await upstreamClient.ConnectAsync(IPAddress.Loopback, originPort, cancellationToken);
        var upstream = upstreamClient.GetStream();
        await downstream.WriteAsync(
            new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 },
            cancellationToken);
        await downstream.FlushAsync(cancellationToken);

        var toOrigin = CopyTunnelAsync(downstream, upstream, cancellationToken);
        var toClient = CopyTunnelAsync(upstream, downstream, cancellationToken);
        await Task.WhenAll(toOrigin, toClient);
        listener.Stop();
        return requested;
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

    private static async ValueTask<string> ReadHeadersAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var one = new byte[1];
        while (bytes.Length < 64 * 1024)
        {
            await ReadExactlyAsync(stream, one, cancellationToken);
            bytes.WriteByte(one[0]);
            if (bytes.Length >= 4)
            {
                var buffer = bytes.GetBuffer();
                var length = checked((int)bytes.Length);
                if (buffer[length - 4] == '\r' && buffer[length - 3] == '\n' &&
                    buffer[length - 2] == '\r' && buffer[length - 1] == '\n')
                {
                    return Encoding.Latin1.GetString(buffer, 0, length);
                }
            }
        }
        throw new InvalidDataException("Headers exceeded the test limit.");
    }

    private static async ValueTask ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    private static async ValueTask WriteAsciiAsync(
        Stream stream,
        string text,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(text), cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}
