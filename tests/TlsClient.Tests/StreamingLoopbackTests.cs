using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class StreamingLoopbackTests
{
    [Fact]
    public async Task DownloadAsync_StreamsDecodedFinalRedirectBodyAndPreservesTrailers()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = Encoding.UTF8.GetBytes(string.Concat(
            Enumerable.Repeat("managed streaming response ", 8_000)));
        var serverTask = RunHttp11StreamingServerAsync(
            listener,
            credential,
            expected,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http11Only);
        await using var destination = new TrackingWriteStream();

        var response = await session.DownloadAsync(
            $"https://127.0.0.1:{port}/start",
            destination,
            new TlsStreamingOptions { BufferSize = 4096 },
            timeout.Token);
        await serverTask;

        Assert.Equal(expected, destination.ToArray());
        Assert.InRange(destination.MaximumWriteSize, 1, 4096);
        Assert.True(response.BodyWasStreamed);
        Assert.True(response.WasDecompressed);
        Assert.Empty(response.Body.ToArray());
        Assert.Equal("complete", response.Trailers.GetFirstOrDefault("X-Transfer"));
        Assert.Single(response.History);
        Assert.Equal(new Uri($"https://127.0.0.1:{port}/final"), response.Url);
        Assert.Throws<InvalidOperationException>(() => response.Text);

        await destination.WriteAsync("owned"u8.ToArray(), timeout.Token);
        Assert.Equal("owned"u8.ToArray(), destination.ToArray()[^5..]);
    }

    [Fact]
    public async Task Http2_DoesNotRestoreFlowControlUntilDestinationAcceptsData()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var releaseDestination = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var responseConsumed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        await using var destination = new BlockingWriteStream(releaseDestination.Task);
        var serverTask = RunHttp2BackpressureServerAsync(
            listener,
            credential,
            destination.WriteStarted,
            releaseDestination,
            responseConsumed.Task,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http2Only);

        var responseTask = session.DownloadAsync(
            $"https://127.0.0.1:{port}/large",
            destination,
            cancellationToken: timeout.Token);
        await destination.WriteStarted.WaitAsync(timeout.Token);
        var response = await responseTask;
        responseConsumed.TrySetResult();
        var sawEarlyWindowUpdate = await serverTask.WaitAsync(timeout.Token);

        Assert.False(sawEarlyWindowUpdate);
        Assert.Equal("backpressure"u8.ToArray(), destination.ToArray());
        Assert.True(response.BodyWasStreamed);
        Assert.Equal(HttpVersion.Version20, response.HttpVersion);
    }

    [Fact]
    public async Task Http2_SlowStreamingDestinationDoesNotBlockAnotherStream()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var releaseDestination = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var responsesConsumed = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        await using var destination = new BlockingWriteStream(releaseDestination.Task);
        var serverTask = RunHttp2MultiplexedStreamingServerAsync(
            listener,
            credential,
            destination.WriteStarted,
            releaseDestination.Task,
            responsesConsumed.Task,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http2Only);

        var slowResponse = session.DownloadAsync(
            $"https://127.0.0.1:{port}/slow",
            destination,
            cancellationToken: timeout.Token);
        await destination.WriteStarted.WaitAsync(timeout.Token);
        var fastResponse = await session.GetAsync(
            $"https://127.0.0.1:{port}/fast",
            timeout.Token).WaitAsync(TimeSpan.FromSeconds(2), timeout.Token);

        Assert.Equal("fast", fastResponse.Text);
        Assert.False(slowResponse.IsCompleted);
        releaseDestination.TrySetResult();
        var slow = await slowResponse;
        responsesConsumed.TrySetResult();
        await serverTask;

        Assert.Equal("slow"u8.ToArray(), destination.ToArray());
        Assert.True(slow.BodyWasStreamed);
    }

    [Fact]
    public void StreamingOptions_RejectUnboundedCopyBuffers()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TlsStreamingOptions { BufferSize = 4095 });
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new TlsStreamingOptions { BufferSize = 1024 * 1024 + 1 });
    }

    [Fact]
    public async Task SendStreamingAsync_UsesChunkedHttp11UploadWithoutBufferingSource()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = Enumerable.Range(0, 100_000).Select(index => (byte)index).ToArray();
        var serverTask = RunHttp11UploadServerAsync(
            listener,
            credential,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http11Only);
        var source = new TrackingReadStream(expected);
        using var content = new StreamContent(source);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://127.0.0.1:{port}/upload")
        {
            Content = content,
        };
        await using var responseBody = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            responseBody,
            new TlsStreamingOptions { BufferSize = 4096 },
            timeout.Token);
        var capture = await serverTask;

        Assert.Contains(
            "Transfer-Encoding: chunked",
            capture.Headers,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "Content-Length:",
            capture.Headers,
            StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expected, capture.Body);
        Assert.InRange(source.MaximumReadSize, 1, 4096);
        Assert.False(source.IsDisposed);
        Assert.Equal("OK"u8.ToArray(), responseBody.ToArray());
        Assert.True(response.BodyWasStreamed);
    }

    [Fact]
    public async Task SendStreamingAsync_StreamsHttp2UploadAcrossFlowControlWindow()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = Enumerable.Range(0, 100_000).Select(index => (byte)(index * 31)).ToArray();
        var serverTask = RunHttp2UploadServerAsync(listener, credential, timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http2Only);
        var source = new TrackingReadStream(expected);
        using var content = new StreamContent(source);
        content.Headers.ContentLength = expected.Length;
        using var request = new HttpRequestMessage(
            HttpMethod.Put,
            $"https://127.0.0.1:{port}/upload")
        {
            Content = content,
        };
        await using var responseBody = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            responseBody,
            new TlsStreamingOptions { BufferSize = 4096 },
            timeout.Token);
        var received = await serverTask;

        Assert.Equal(expected, received);
        Assert.InRange(source.MaximumReadSize, 1, 4096);
        Assert.False(source.IsDisposed);
        Assert.Equal("OK"u8.ToArray(), responseBody.ToArray());
        Assert.Equal(HttpVersion.Version20, response.HttpVersion);
    }

    private static TlsSession CreateSession(
        TlsSessionLoopbackTests.TestCertificates certificates,
        TlsHttpVersionPolicy versionPolicy)
    {
        return new TlsSession(new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = versionPolicy,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        });
    }

    private static async Task RunHttp11StreamingServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        byte[] responseBody,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(
            client,
            credential,
            "http/1.1",
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);

        _ = await ReadHttp11HeadersAsync(stream, cancellationToken);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 302 Found\r\n" +
            "Location: /final\r\n" +
            "Content-Length: 18\r\n" +
            "Connection: keep-alive\r\n\r\n" +
            "discard this body!",
            cancellationToken);
        _ = await ReadHttp11HeadersAsync(stream, cancellationToken);

        byte[] encoded;
        using (var compressed = new MemoryStream())
        {
            await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, true))
            {
                await gzip.WriteAsync(responseBody, cancellationToken);
            }
            encoded = compressed.ToArray();
        }
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\n" +
            "Content-Encoding: gzip\r\n" +
            "Transfer-Encoding: chunked\r\n" +
            "Trailer: X-Transfer\r\n" +
            "Connection: close\r\n\r\n",
            cancellationToken);
        for (var offset = 0; offset < encoded.Length; offset += 997)
        {
            var length = Math.Min(997, encoded.Length - offset);
            await WriteAsciiAsync(stream, $"{length:x}\r\n", cancellationToken);
            await stream.WriteAsync(encoded.AsMemory(offset, length), cancellationToken);
            await WriteAsciiAsync(stream, "\r\n", cancellationToken);
        }
        await WriteAsciiAsync(
            stream,
            "0\r\nX-Transfer: complete\r\n\r\n",
            cancellationToken);
        listener.Stop();
    }

    private static async Task<bool> RunHttp2BackpressureServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task writeStarted,
        TaskCompletionSource releaseDestination,
        Task responseConsumed,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(
            client,
            credential,
            "h2",
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(stream, Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var streamId = 0;
        var receivedSettingsAck = false;
        while (streamId == 0 || !receivedSettingsAck)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamId = frame.StreamId;
            }
            else if (frame.Type == Http2FrameType.Settings &&
                (frame.Flags & Http2FrameFlags.Ack) != 0)
            {
                receivedSettingsAck = true;
            }
        }

        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            streamId,
            [0x88],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            0,
            streamId,
            "backpressure"u8.ToArray(),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await writeStarted.WaitAsync(cancellationToken);

        var pendingFrame = ReadFrameAsync(stream, cancellationToken).AsTask();
        var sawEarlyWindowUpdate = await Task.WhenAny(
            pendingFrame,
            Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken)) == pendingFrame;
        releaseDestination.TrySetResult();
        var windowUpdate = await pendingFrame.ConfigureAwait(false);
        Assert.Equal(Http2FrameType.WindowUpdate, windowUpdate.Type);

        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            streamId,
            [],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await responseConsumed.WaitAsync(cancellationToken);
        listener.Stop();
        return sawEarlyWindowUpdate;
    }

    private static async Task RunHttp2MultiplexedStreamingServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task slowWriteStarted,
        Task destinationReleased,
        Task responsesConsumed,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(
            client,
            credential,
            "h2",
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(stream, Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var slowStreamId = 0;
        while (slowStreamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                slowStreamId = frame.StreamId;
            }
        }
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            slowStreamId,
            [0x88],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            0,
            slowStreamId,
            "slow"u8.ToArray(),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await slowWriteStarted.WaitAsync(cancellationToken);

        var fastStreamId = 0;
        while (fastStreamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers && frame.StreamId != slowStreamId)
            {
                fastStreamId = frame.StreamId;
            }
        }
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            fastStreamId,
            [0x88, 0x5c, 0x01, 0x34],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            fastStreamId,
            "fast"u8.ToArray(),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        await destinationReleased.WaitAsync(cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            slowStreamId,
            [],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await responsesConsumed.WaitAsync(cancellationToken);
        listener.Stop();
    }

    private static async Task<Http11UploadCapture> RunHttp11UploadServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(
            client,
            credential,
            "http/1.1",
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var headers = await ReadHttp11HeadersAsync(stream, cancellationToken);
        using var body = new MemoryStream();
        while (true)
        {
            var sizeLine = await ReadAsciiLineAsync(stream, cancellationToken);
            var size = int.Parse(
                sizeLine,
                System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture);
            if (size == 0)
            {
                Assert.Equal(string.Empty, await ReadAsciiLineAsync(stream, cancellationToken));
                break;
            }
            var chunk = new byte[size];
            await ReadExactlyAsync(stream, chunk, cancellationToken);
            body.Write(chunk);
            Assert.Equal(string.Empty, await ReadAsciiLineAsync(stream, cancellationToken));
        }
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            cancellationToken);
        listener.Stop();
        return new Http11UploadCapture(headers, body.ToArray());
    }

    private static async Task<byte[]> RunHttp2UploadServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(
            client,
            credential,
            "h2",
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(stream, Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await stream.FlushAsync(cancellationToken);

        using var body = new MemoryStream();
        var streamId = 0;
        var sentWindowUpdate = false;
        var ended = false;
        while (!ended)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamId = frame.StreamId;
            }
            else if (frame.Type == Http2FrameType.Data)
            {
                body.Write(frame.Payload);
                ended = (frame.Flags & Http2FrameFlags.EndStream) != 0;
                if (!sentWindowUpdate && body.Length == 65_535)
                {
                    var increment = new byte[4];
                    BinaryPrimitives.WriteInt32BigEndian(increment, 65_535);
                    await WriteFrameAsync(
                        stream,
                        Http2FrameType.WindowUpdate,
                        0,
                        0,
                        increment,
                        cancellationToken);
                    await WriteFrameAsync(
                        stream,
                        Http2FrameType.WindowUpdate,
                        0,
                        streamId,
                        increment,
                        cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                    sentWindowUpdate = true;
                }
            }
        }
        Assert.True(sentWindowUpdate);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            streamId,
            [0x88, 0x5c, 0x01, 0x32],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            streamId,
            "OK"u8.ToArray(),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        listener.Stop();
        return body.ToArray();
    }

    private static async ValueTask<CustomTlsServer> AuthenticateAsync(
        TcpClient client,
        TlsServerCertificate credential,
        string alpn,
        CancellationToken cancellationToken)
    {
        var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = [alpn],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        try
        {
            await server.AuthenticateAsync(client.GetStream(), false, cancellationToken);
            return server;
        }
        catch
        {
            await server.DisposeAsync();
            throw;
        }
    }

    private static async ValueTask<string> ReadHttp11HeadersAsync(
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
                var data = bytes.GetBuffer();
                var length = checked((int)bytes.Length);
                if (data[length - 4] == '\r' && data[length - 3] == '\n' &&
                    data[length - 2] == '\r' && data[length - 1] == '\n')
                {
                    return Encoding.Latin1.GetString(data, 0, length);
                }
            }
        }
        throw new InvalidDataException("Request headers exceeded the test limit.");
    }

    private static async ValueTask<string> ReadAsciiLineAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var bytes = new MemoryStream();
        var one = new byte[1];
        while (bytes.Length < 8192)
        {
            await ReadExactlyAsync(stream, one, cancellationToken);
            if (one[0] == '\n')
            {
                var data = bytes.ToArray();
                if (data.Length == 0 || data[^1] != '\r')
                {
                    throw new InvalidDataException("Line did not end with CRLF.");
                }
                return Encoding.ASCII.GetString(data.AsSpan(0, data.Length - 1));
            }
            bytes.WriteByte(one[0]);
        }
        throw new InvalidDataException("Line exceeded the test limit.");
    }

    private static async ValueTask<Http2Frame> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactlyAsync(stream, header, cancellationToken);
        var length = header[0] << 16 | header[1] << 8 | header[2];
        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken);
        return new Http2Frame(
            (Http2FrameType)header[3],
            header[4],
            BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & 0x7fff_ffff,
            payload);
    }

    private static async ValueTask WriteFrameAsync(
        Stream stream,
        Http2FrameType type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
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

    private class TrackingWriteStream : MemoryStream
    {
        public int MaximumWriteSize { get; private set; }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            MaximumWriteSize = Math.Max(MaximumWriteSize, buffer.Length);
            await base.WriteAsync(buffer, cancellationToken);
        }
    }

    private sealed class BlockingWriteStream(Task release) : TrackingWriteStream
    {
        private int _blocked;

        public Task WriteStarted => _writeStarted.Task;

        private readonly TaskCompletionSource _writeStarted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref _blocked, 1) == 0)
            {
                _writeStarted.TrySetResult();
                await release.WaitAsync(cancellationToken);
            }
            await base.WriteAsync(buffer, cancellationToken);
        }
    }

    private sealed class TrackingReadStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes, writable: false);

        public int MaximumReadSize { get; private set; }

        public bool IsDisposed { get; private set; }

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
            MaximumReadSize = Math.Max(MaximumReadSize, buffer.Length);
            return await _inner.ReadAsync(buffer, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            MaximumReadSize = Math.Max(MaximumReadSize, count);
            return _inner.Read(buffer, offset, count);
        }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed record Http11UploadCapture(string Headers, byte[] Body);
}
