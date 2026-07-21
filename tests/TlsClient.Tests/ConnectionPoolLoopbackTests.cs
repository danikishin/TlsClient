using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Concurrent;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class ConnectionPoolLoopbackTests
{
    [Fact]
    public async Task ConcurrentHttp11Requests_UseConfiguredConnectionsPerOrigin()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var clientsReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunParallelServerAsync(
            listener,
            credential,
            clientsReceived.Task,
            timeout.Token);

        var options = CreateHttp11Options(certificates.Root);
        options.MaximumConnectionsPerOrigin = 2;
        options.MaximumPooledConnections = 2;
        await using var session = new TlsSession(options);
        var origin = $"https://127.0.0.1:{port}";

        var responses = await Task.WhenAll(
            session.GetAsync($"{origin}/first", timeout.Token),
            session.GetAsync($"{origin}/second", timeout.Token));
        clientsReceived.TrySetResult();
        var acceptedConnections = await serverTask;

        Assert.Equal(2, acceptedConnections);
        Assert.Equal(["1", "2"], responses.Select(response => response.Text).Order());
    }

    [Fact]
    public async Task GlobalLimit_EvictsOldestIdleConnectionBeforeOpeningAnotherOrigin()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var firstListener = new TcpListener(IPAddress.Loopback, 0);
        using var secondListener = new TcpListener(IPAddress.Loopback, 0);
        firstListener.Start();
        secondListener.Start();
        var firstPort = ((IPEndPoint)firstListener.LocalEndpoint).Port;
        var secondPort = ((IPEndPoint)secondListener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var firstClosed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var secondResponseReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var firstServer = RunEvictedServerAsync(
            firstListener,
            credential,
            firstClosed,
            timeout.Token);
        var secondServer = RunReplacementServerAsync(
            secondListener,
            credential,
            firstClosed.Task,
            secondResponseReceived.Task,
            timeout.Token);

        var options = CreateHttp11Options(certificates.Root);
        options.MaximumConnectionsPerOrigin = 1;
        options.MaximumPooledConnections = 1;
        await using var session = new TlsSession(options);

        var first = await session.GetAsync(
            $"https://127.0.0.1:{firstPort}/first",
            timeout.Token);
        var second = await session.GetAsync(
            $"https://127.0.0.1:{secondPort}/second",
            timeout.Token);
        secondResponseReceived.TrySetResult();

        await Task.WhenAll(firstServer, secondServer);
        Assert.Equal("A", first.Text);
        Assert.Equal("B", second.Text);
        Assert.True(firstClosed.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public void Options_RejectGlobalLimitBelowPerOriginLimit()
    {
        var options = new TlsSessionOptions
        {
            MaximumConnectionsPerOrigin = 3,
            MaximumPooledConnections = 2,
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
    }

    [Fact]
    public async Task PooledLifetime_ReplacesIdleConnectionAndReportsConnectTelemetry()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var secondResponseReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunLifetimeServerAsync(
            listener,
            credential,
            secondResponseReceived.Task,
            timeout.Token);
        var events = new ConcurrentQueue<TlsConnectEvent>();
        var resolutions = 0;

        var options = CreateHttp11Options(certificates.Root);
        options.MaximumConnectionsPerOrigin = 1;
        options.PooledConnectionLifetime = TimeSpan.FromMilliseconds(30);
        options.DnsResolver = (_, _) =>
        {
            Interlocked.Increment(ref resolutions);
            return ValueTask.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
        };
        options.ConnectObserver = events.Enqueue;
        await using var session = new TlsSession(options);
        var origin = $"https://localhost:{port}";

        var first = await session.GetAsync($"{origin}/first", timeout.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(80), timeout.Token);
        var second = await session.GetAsync($"{origin}/second", timeout.Token);
        secondResponseReceived.TrySetResult();
        await serverTask;

        Assert.Equal("A", first.Text);
        Assert.Equal("B", second.Text);
        var handshakes = events
            .Where(item => item.Kind == TlsConnectEventKind.TlsHandshakeCompleted)
            .ToArray();
        Assert.Equal(2, handshakes.Length);
        Assert.Equal(2, handshakes.Select(item => item.ConnectionId).Distinct().Count());
        Assert.All(handshakes, item => Assert.Equal("http/1.1", item.ApplicationProtocol));
        Assert.Equal(2, events.Count(item => item.Kind == TlsConnectEventKind.TcpConnected));
        Assert.Equal(1, resolutions);
        Assert.Contains(events, item => item.Kind == TlsConnectEventKind.DnsCacheHit);
    }

    [Fact]
    public void Options_RejectInvalidNetworkTimingValues()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsSessionOptions
        {
            PooledConnectionLifetime = TimeSpan.Zero,
        }.Snapshot());
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsSessionOptions
        {
            DnsRefreshInterval = TimeSpan.Zero,
        }.Snapshot());
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsSessionOptions
        {
            MaximumDnsCacheEntries = 0,
        }.Snapshot());
        Assert.Throws<ArgumentOutOfRangeException>(() => new TlsSessionOptions
        {
            HappyEyeballsDelay = TimeSpan.FromSeconds(6),
        }.Snapshot());
    }

    private static TlsSessionOptions CreateHttp11Options(X509Certificate2 root) => new()
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

    private static async Task<int> RunParallelServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task clientsReceived,
        CancellationToken cancellationToken)
    {
        var bothRequestsArrived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var requestCount = 0;

        async Task ServeAsync(TcpClient client, char body)
        {
            using (client)
            {
                await using var server = CreateServer(credential);
                await server.AuthenticateAsync(
                    client.GetStream(),
                    leaveOpen: false,
                    cancellationToken);
                await using var stream = server.AsStream(leaveServerOpen: true);
                _ = await ReadHeadersAsync(stream, cancellationToken);
                if (Interlocked.Increment(ref requestCount) == 2)
                {
                    bothRequestsArrived.TrySetResult();
                }
                await bothRequestsArrived.Task.WaitAsync(cancellationToken);
                await WriteResponseAsync(stream, body, keepAlive: true, cancellationToken);
                await clientsReceived.WaitAsync(cancellationToken);
            }
        }

        using var first = await listener.AcceptTcpClientAsync(cancellationToken);
        var firstTask = ServeAsync(first, '1');
        using var second = await listener.AcceptTcpClientAsync(cancellationToken);
        var secondTask = ServeAsync(second, '2');
        await Task.WhenAll(firstTask, secondTask);
        listener.Stop();
        return requestCount;
    }

    private static async Task RunEvictedServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        TaskCompletionSource closed,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = CreateServer(credential);
        await server.AuthenticateAsync(client.GetStream(), leaveOpen: false, cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        _ = await ReadHeadersAsync(stream, cancellationToken);
        await WriteResponseAsync(stream, 'A', keepAlive: true, cancellationToken);

        var buffer = new byte[1];
        var read = await stream.ReadAsync(buffer, cancellationToken);
        Assert.Equal(0, read);
        closed.TrySetResult();
        listener.Stop();
    }

    private static async Task RunReplacementServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task firstClosed,
        Task responseReceived,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = CreateServer(credential);
        await server.AuthenticateAsync(client.GetStream(), leaveOpen: false, cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        _ = await ReadHeadersAsync(stream, cancellationToken);
        await firstClosed.WaitAsync(cancellationToken);
        await WriteResponseAsync(stream, 'B', keepAlive: true, cancellationToken);
        await responseReceived.WaitAsync(cancellationToken);
        listener.Stop();
    }

    private static async Task RunLifetimeServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task secondResponseReceived,
        CancellationToken cancellationToken)
    {
        using (var firstClient = await listener.AcceptTcpClientAsync(cancellationToken))
        {
            await using var firstServer = CreateServer(credential);
            await firstServer.AuthenticateAsync(
                firstClient.GetStream(),
                leaveOpen: false,
                cancellationToken);
            await using var firstStream = firstServer.AsStream(leaveServerOpen: true);
            _ = await ReadHeadersAsync(firstStream, cancellationToken);
            await WriteResponseAsync(firstStream, 'A', keepAlive: true, cancellationToken);
            var one = new byte[1];
            Assert.Equal(0, await firstStream.ReadAsync(one, cancellationToken));
        }

        using (var secondClient = await listener.AcceptTcpClientAsync(cancellationToken))
        {
            await using var secondServer = CreateServer(credential);
            await secondServer.AuthenticateAsync(
                secondClient.GetStream(),
                leaveOpen: false,
                cancellationToken);
            await using var secondStream = secondServer.AsStream(leaveServerOpen: true);
            _ = await ReadHeadersAsync(secondStream, cancellationToken);
            await WriteResponseAsync(secondStream, 'B', keepAlive: true, cancellationToken);
            await secondResponseReceived.WaitAsync(cancellationToken);
        }
        listener.Stop();
    }

    private static CustomTlsServer CreateServer(TlsServerCertificate credential) => new(
        new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });

    private static async Task<string> ReadHeadersAsync(
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
                throw new EndOfStreamException();
            }
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
        throw new InvalidDataException("Request headers exceeded the test limit.");
    }

    private static async Task WriteResponseAsync(
        Stream stream,
        char body,
        bool keepAlive,
        CancellationToken cancellationToken)
    {
        var response =
            $"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: " +
            $"{(keepAlive ? "keep-alive" : "close")}\r\n\r\n{body}";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}
