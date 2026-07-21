using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Concurrent;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class RetryPolicyLoopbackTests
{
    [Fact]
    public async Task ConfiguredStatus_RetriesIdempotentBufferedRequest()
    {
        using var fixture = new RetryFixture();
        var serverTask = fixture.RunStatusServerAsync(2, CancellationToken.None);
        var options = fixture.CreateOptions();
        options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(fixture.Url, fixture.Timeout.Token);
        var requests = await serverTask;

        Assert.Equal(2, requests);
        Assert.Equal("final", response.Text);
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 2)]
    public async Task NonIdempotentRetry_RequiresExplicitOptIn(
        bool retryNonIdempotent,
        int expectedRequests)
    {
        using var fixture = new RetryFixture();
        var serverTask = fixture.RunStatusServerAsync(expectedRequests, CancellationToken.None);
        var options = fixture.CreateOptions();
        options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
        options.Retry.RetryNonIdempotentMethods = retryNonIdempotent;
        await using var session = new TlsSession(options);
        using var content = new ByteArrayContent("body"u8.ToArray());

        var response = await session.PostAsync(fixture.Url, content, fixture.Timeout.Token);
        var requests = await serverTask;

        Assert.Equal(expectedRequests, requests);
        Assert.Equal(
            retryNonIdempotent ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable,
            response.StatusCode);
    }

    [Fact]
    public async Task StreamingRetry_RequiresReplayAndDoesNotMixAttemptBodies()
    {
        using var fixture = new RetryFixture();
        var serverTask = fixture.RunStatusServerAsync(2, CancellationToken.None);
        var options = fixture.CreateOptions();
        options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
        await using var session = new TlsSession(options);
        var source = new CountingReadStream("upload"u8.ToArray());
        using var content = new StreamContent(source);
        content.Headers.ContentLength = 6;
        using var request = new HttpRequestMessage(HttpMethod.Put, fixture.Url)
        {
            Content = content,
        };
        TlsRequestOptions.For(request).ReplayPolicy = TlsRequestReplayPolicy.Buffer;
        await using var destination = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            destination,
            cancellationToken: fixture.Timeout.Token);
        var requests = await serverTask;

        Assert.Equal(2, requests);
        Assert.Equal(2, source.ReadCount);
        Assert.Equal("final"u8.ToArray(), destination.ToArray());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PerRequestDisable_OverridesConfiguredStatusRetry()
    {
        using var fixture = new RetryFixture();
        var serverTask = fixture.RunStatusServerAsync(1, CancellationToken.None);
        var options = fixture.CreateOptions();
        options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
        await using var session = new TlsSession(options);
        using var request = new HttpRequestMessage(HttpMethod.Get, fixture.Url);
        TlsRequestOptions.For(request).EnableRetries = false;

        var response = await session.SendAsync(request, fixture.Timeout.Token);
        var requests = await serverTask;

        Assert.Equal(1, requests);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task DefaultPolicy_RecoversIdempotentRequestFromStalePooledConnection()
    {
        using var fixture = new RetryFixture();
        var serverTask = fixture.RunStaleConnectionServerAsync();
        await using var session = new TlsSession(fixture.CreateOptions());

        var warmup = await session.GetAsync(fixture.Url, fixture.Timeout.Token);
        var recovered = await session.GetAsync(fixture.Url, fixture.Timeout.Token);
        var connections = await serverTask;

        Assert.Equal("warm", warmup.Text);
        Assert.Equal("fresh", recovered.Text);
        Assert.Equal(2, connections);
    }

    [Fact]
    public async Task RequestPolicies_WrapEveryRetryInMiddlewareOrder()
    {
        using var fixture = new RetryFixture();
        var serverTask = fixture.RunStatusServerAsync(2, CancellationToken.None);
        var events = new ConcurrentQueue<string>();
        var first = new RecordingPolicy("first", events);
        var second = new RecordingPolicy("second", events);
        var options = fixture.CreateOptions();
        options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
        options.RequestPolicies.Add(first);
        options.RequestPolicies.Add(second);
        await using var session = new TlsSession(options);

        _ = await session.GetAsync(fixture.Url, fixture.Timeout.Token);
        await serverTask;

        Assert.Equal(
        [
            "start:first:1",
            "start:second:1",
            "complete:second:1:503:True",
            "complete:first:1:503:True",
            "start:first:2",
            "start:second:2",
            "complete:second:2:200:False",
            "complete:first:2:200:False",
        ],
            events);
        Assert.All(first.Contexts, context =>
        {
            Assert.True(context.IsIdempotent);
            Assert.True(context.IsReplayable);
            Assert.Null(context.ProxyType);
        });
    }

    [Fact]
    public async Task CircuitPolicyException_PreventsAnyConnectionAttempt()
    {
        var connectEvents = new ConcurrentQueue<TlsConnectEvent>();
        var options = new TlsSessionOptions
        {
            ConnectObserver = connectEvents.Enqueue,
        };
        options.RequestPolicies.Add(new RejectingPolicy());
        await using var session = new TlsSession(options);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            session.GetAsync("https://127.0.0.1:1/"));

        Assert.Equal("circuit open", exception.Message);
        Assert.Empty(connectEvents);
    }

    private sealed class RetryFixture : IDisposable
    {
        private readonly TlsSessionLoopbackTests.TestCertificates _certificates =
            TlsSessionLoopbackTests.TestCertificates.Create();
        private readonly TlsServerCertificate _credential;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

        public RetryFixture()
        {
            _credential = new TlsServerCertificate(
                _certificates.Leaf,
                [_certificates.Root]);
            _listener.Start();
            var port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            Url = $"https://127.0.0.1:{port}/retry";
            Timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        }

        public string Url { get; }

        public CancellationTokenSource Timeout { get; }

        public TlsSessionOptions CreateOptions() => new()
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [_certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };

        public async Task<int> RunStatusServerAsync(
            int expectedRequests,
            CancellationToken cancellationToken)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                Timeout.Token,
                cancellationToken);
            using var client = await _listener.AcceptTcpClientAsync(linked.Token);
            await using var server = new CustomTlsServer(new CustomTlsServerOptions
            {
                ServerCertificate = _credential,
                AlpnProtocols = ["http/1.1"],
                RequireAlpn = true,
                AutomaticSessionTicketCount = 0,
            });
            await server.AuthenticateAsync(client.GetStream(), false, linked.Token);
            await using var stream = server.AsStream(leaveServerOpen: true);
            for (var attempt = 1; attempt <= expectedRequests; attempt++)
            {
                var headers = await ReadHeadersAsync(stream, linked.Token);
                if (TryGetContentLength(headers, out var contentLength))
                {
                    var body = new byte[contentLength];
                    await ReadExactlyAsync(stream, body, linked.Token);
                }
                var final = attempt == 2;
                var bodyText = final ? "final" : "retry";
                await WriteAsciiAsync(
                    stream,
                    $"HTTP/1.1 {(final ? "200 OK" : "503 Service Unavailable")}\r\n" +
                    $"Content-Length: {bodyText.Length}\r\n" +
                    $"Connection: {(attempt == expectedRequests ? "close" : "keep-alive")}\r\n\r\n" +
                    bodyText,
                    linked.Token);
            }
            await WaitForClientCloseAsync(stream, linked.Token);
            _listener.Stop();
            return expectedRequests;
        }

        public async Task<int> RunStaleConnectionServerAsync()
        {
            using (var firstClient = await _listener.AcceptTcpClientAsync(Timeout.Token))
            {
                await using var firstServer = CreateServer();
                await firstServer.AuthenticateAsync(
                    firstClient.GetStream(),
                    false,
                    Timeout.Token);
                await using var firstStream = firstServer.AsStream(leaveServerOpen: true);
                _ = await ReadHeadersAsync(firstStream, Timeout.Token);
                await WriteAsciiAsync(
                    firstStream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n" +
                    "Connection: keep-alive\r\n\r\nwarm",
                    Timeout.Token);
            }

            using var secondClient = await _listener.AcceptTcpClientAsync(Timeout.Token);
            await using var secondServer = CreateServer();
            await secondServer.AuthenticateAsync(
                secondClient.GetStream(),
                false,
                Timeout.Token);
            await using var secondStream = secondServer.AsStream(leaveServerOpen: true);
            _ = await ReadHeadersAsync(secondStream, Timeout.Token);
            await WriteAsciiAsync(
                secondStream,
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
                Timeout.Token);
            _listener.Stop();
            return 2;
        }

        private CustomTlsServer CreateServer() => new(new CustomTlsServerOptions
        {
            ServerCertificate = _credential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });

        public void Dispose()
        {
            _listener.Stop();
            Timeout.Dispose();
            _credential.Dispose();
            _certificates.Dispose();
        }
    }

    private static bool TryGetContentLength(string headers, out int length)
    {
        length = 0;
        var line = headers.Split("\r\n").FirstOrDefault(value =>
            value.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
        return line is not null && int.TryParse(
            line[(line.IndexOf(':') + 1)..],
            System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture,
            out length);
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
        string value,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(value), cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async ValueTask WaitForClientCloseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        try
        {
            while (await stream.ReadAsync(buffer, cancellationToken) != 0)
            {
            }
        }
        catch (IOException)
        {
            // A peer that consumed the response may close without a TLS close_notify.
        }
    }

    private sealed class CountingReadStream(byte[] data) : Stream
    {
        private readonly MemoryStream _inner = new(data, writable: false);

        public int ReadCount { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ReadCount++;
            return await _inner.ReadAsync(buffer, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadCount++;
            return _inner.Read(buffer, offset, count);
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed class RecordingPolicy(
        string name,
        ConcurrentQueue<string> events) : ITlsRequestPolicy
    {
        private readonly object _itemKey = new();

        public ConcurrentQueue<TlsRequestPolicyContext> Contexts { get; } = new();

        public ValueTask OnAttemptStartingAsync(
            TlsRequestPolicyContext context,
            CancellationToken cancellationToken)
        {
            context.Items[_itemKey] = name;
            Contexts.Enqueue(context);
            events.Enqueue($"start:{name}:{context.Attempt}");
            return ValueTask.CompletedTask;
        }

        public ValueTask OnAttemptCompletedAsync(
            TlsRequestPolicyContext context,
            TlsRequestPolicyOutcome outcome)
        {
            Assert.Equal(name, context.Items[_itemKey]);
            events.Enqueue(
                $"complete:{name}:{context.Attempt}:{(int?)outcome.StatusCode}:{outcome.WillRetry}");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RejectingPolicy : ITlsRequestPolicy
    {
        public ValueTask OnAttemptStartingAsync(
            TlsRequestPolicyContext context,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("circuit open");

        public ValueTask OnAttemptCompletedAsync(
            TlsRequestPolicyContext context,
            TlsRequestPolicyOutcome outcome) => ValueTask.CompletedTask;
    }
}
