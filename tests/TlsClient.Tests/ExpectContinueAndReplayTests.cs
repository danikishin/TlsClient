using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class ExpectContinueAndReplayTests
{
    [Fact]
    public async Task Http11_ExpectContinue_DoesNotReadSourceBeforeContinue()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = StartListener(out var port);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = "request-body"u8.ToArray();
        var serverTask = RunHttp11ContinueServerAsync(
            listener,
            credential,
            expected.Length,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http11Only);
        var source = new CountingReadStream(expected);
        using var content = new StreamContent(source);
        content.Headers.ContentLength = expected.Length;
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://127.0.0.1:{port}/continue")
        {
            Content = content,
        };
        request.Headers.ExpectContinue = true;
        await using var destination = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            destination,
            cancellationToken: timeout.Token);
        var capture = await serverTask;

        Assert.False(capture.BodyArrivedBeforeContinue);
        Assert.Equal(expected, capture.Body);
        Assert.True(source.ReadCount > 0);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Http11_FinalResponseBeforeContinue_DoesNotReadUploadSource()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = StartListener(out var port);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = RunHttp11ExpectationRejectedServerAsync(
            listener,
            credential,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http11Only);
        var source = new CountingReadStream("must-not-send"u8.ToArray());
        using var content = new StreamContent(source);
        content.Headers.ContentLength = 13;
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://127.0.0.1:{port}/reject")
        {
            Content = content,
        };
        request.Headers.ExpectContinue = true;
        await using var destination = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            destination,
            cancellationToken: timeout.Token);
        await serverTask;

        Assert.Equal(HttpStatusCode.ExpectationFailed, response.StatusCode);
        Assert.Equal(0, source.ReadCount);
    }

    [Fact]
    public async Task Http2_ExpectContinue_SendsDataThenTrailingHeaders()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = StartListener(out var port);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = "h2-upload"u8.ToArray();
        var serverTask = RunHttp2ContinueTrailerServerAsync(
            listener,
            credential,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http2Only);
        var source = new CountingReadStream(expected);
        using var content = new StreamContent(source);
        content.Headers.ContentLength = expected.Length;
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://127.0.0.1:{port}/trailers")
        {
            Content = content,
        };
        request.Headers.ExpectContinue = true;
        TlsRequestOptions.For(request).Trailers.Set("X-Checksum", "done");
        await using var destination = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            destination,
            cancellationToken: timeout.Token);
        var capture = await serverTask;

        Assert.Equal(expected, capture.Body);
        Assert.Equal("done", capture.Trailers.Single(header =>
            header.Name == "x-checksum").Value);
        Assert.Contains(capture.InitialHeaders, header =>
            header.Name == "expect" && header.Value == "100-continue");
        Assert.Equal("OK"u8.ToArray(), destination.ToArray());
        Assert.Equal(HttpVersion.Version20, response.HttpVersion);
    }

    [Fact]
    public async Task Http11_RequestTrailers_UseChunkedTerminatorFields()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = StartListener(out var port);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = "chunked-with-trailer"u8.ToArray();
        var serverTask = RunHttp11TrailerServerAsync(
            listener,
            credential,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http11Only);
        var source = new CountingReadStream(expected);
        using var content = new StreamContent(source);
        content.Headers.ContentLength = expected.Length;
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://127.0.0.1:{port}/trailers")
        {
            Content = content,
        };
        TlsRequestOptions.For(request).Trailers.Set("X-Checksum", "complete");
        await using var destination = new MemoryStream();

        _ = await session.SendStreamingAsync(
            request,
            destination,
            cancellationToken: timeout.Token);
        var capture = await serverTask;

        Assert.Equal(expected, capture.Body);
        Assert.Equal("complete", capture.TrailerValue);
        Assert.Contains(
            "Transfer-Encoding: chunked",
            capture.Headers,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Trailer: X-Checksum", capture.Headers, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(TlsRequestReplayPolicy.Never, false)]
    [InlineData(TlsRequestReplayPolicy.Buffer, true)]
    public async Task StreamingRedirect_ReplaysOnlyWithExplicitBufferPolicy(
        TlsRequestReplayPolicy replayPolicy,
        bool shouldReplay)
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var credential = new TlsServerCertificate(certificates.Leaf, [certificates.Root]);
        using var listener = StartListener(out var port);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var expected = "replay-me"u8.ToArray();
        var serverTask = RunReplayRedirectServerAsync(
            listener,
            credential,
            shouldReplay,
            timeout.Token);
        await using var session = CreateSession(certificates, TlsHttpVersionPolicy.Http11Only);
        var source = new CountingReadStream(expected);
        using var content = new StreamContent(source);
        content.Headers.ContentLength = expected.Length;
        using var request = new HttpRequestMessage(
            HttpMethod.Put,
            $"https://127.0.0.1:{port}/first")
        {
            Content = content,
        };
        TlsRequestOptions.For(request).ReplayPolicy = replayPolicy;
        await using var destination = new MemoryStream();

        if (shouldReplay)
        {
            var response = await session.SendStreamingAsync(
                request,
                destination,
                cancellationToken: timeout.Token);
            var bodies = await serverTask;
            Assert.Equal(2, bodies.Length);
            Assert.All(bodies, body => Assert.Equal(expected, body));
            Assert.Single(response.History);
            Assert.Equal("OK"u8.ToArray(), destination.ToArray());
        }
        else
        {
            await Assert.ThrowsAsync<HttpRequestException>(() => session.SendStreamingAsync(
                request,
                destination,
                cancellationToken: timeout.Token));
            var bodies = await serverTask;
            Assert.Single(bodies);
            Assert.Equal(expected, bodies[0]);
        }
    }

    private static async Task<Http11ContinueCapture> RunHttp11ContinueServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        int bodyLength,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(client, credential, "http/1.1", cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var headers = await ReadHeadersAsync(stream, cancellationToken);
        Assert.Contains("Expect: 100-continue", headers, StringComparison.OrdinalIgnoreCase);
        var first = new byte[1];
        var firstRead = stream.ReadAsync(first, cancellationToken).AsTask();
        var arrivedEarly = await Task.WhenAny(
            firstRead,
            Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken)) == firstRead;
        await WriteAsciiAsync(stream, "HTTP/1.1 100 Continue\r\n\r\n", cancellationToken);
        var body = new byte[bodyLength];
        var firstCount = await firstRead;
        Assert.Equal(1, firstCount);
        body[0] = first[0];
        await ReadExactlyAsync(stream, body.AsMemory(1), cancellationToken);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            cancellationToken);
        listener.Stop();
        return new Http11ContinueCapture(arrivedEarly, body);
    }

    private static async Task RunHttp11ExpectationRejectedServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(client, credential, "http/1.1", cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        _ = await ReadHeadersAsync(stream, cancellationToken);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            cancellationToken);
        listener.Stop();
    }

    private static async Task<Http11TrailerCapture> RunHttp11TrailerServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(client, credential, "http/1.1", cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var headers = await ReadHeadersAsync(stream, cancellationToken);
        using var body = new MemoryStream();
        while (true)
        {
            var line = await ReadLineAsync(stream, cancellationToken);
            var length = int.Parse(
                line,
                System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture);
            if (length == 0)
            {
                break;
            }
            var chunk = new byte[length];
            await ReadExactlyAsync(stream, chunk, cancellationToken);
            body.Write(chunk);
            Assert.Equal(string.Empty, await ReadLineAsync(stream, cancellationToken));
        }
        var trailerLine = await ReadLineAsync(stream, cancellationToken);
        Assert.Equal(string.Empty, await ReadLineAsync(stream, cancellationToken));
        var separator = trailerLine.IndexOf(':');
        Assert.True(separator > 0);
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            cancellationToken);
        listener.Stop();
        return new Http11TrailerCapture(
            headers,
            body.ToArray(),
            trailerLine[(separator + 1)..].Trim());
    }

    private static async Task<Http2ContinueCapture> RunHttp2ContinueTrailerServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(client, credential, "h2", cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(stream, Http2FrameType.Settings, 0, 0, [], cancellationToken);
        await stream.FlushAsync(cancellationToken);
        var decoder = new HpackDecoder(4096);
        Http2Frame initial;
        do
        {
            initial = await ReadFrameAsync(stream, cancellationToken);
        }
        while (initial.Type != Http2FrameType.Headers);
        var initialBlock = RemovePriority(initial);
        var initialHeaders = decoder.Decode(initialBlock.Span, 64 * 1024);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            initial.StreamId,
            [0x08, 0x03, 0x31, 0x30, 0x30],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        using var body = new MemoryStream();
        IReadOnlyList<HpackHeader>? trailers = null;
        while (trailers is null)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Data)
            {
                body.Write(frame.Payload);
            }
            else if (frame.Type == Http2FrameType.Headers)
            {
                Assert.NotEqual(0, frame.Flags & Http2FrameFlags.EndStream);
                trailers = decoder.Decode(RemovePriority(frame).Span, 64 * 1024);
            }
        }
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            initial.StreamId,
            [0x88, 0x5c, 0x01, 0x32],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            initial.StreamId,
            "OK"u8.ToArray(),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        listener.Stop();
        return new Http2ContinueCapture(initialHeaders, trailers, body.ToArray());
    }

    private static async Task<byte[][]> RunReplayRedirectServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        bool expectReplay,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = await AuthenticateAsync(client, credential, "http/1.1", cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var bodies = new List<byte[]>();
        var firstHeaders = await ReadHeadersAsync(stream, cancellationToken);
        bodies.Add(await ReadContentLengthBodyAsync(stream, firstHeaders, cancellationToken));
        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /second\r\n" +
            "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            cancellationToken);
        if (expectReplay)
        {
            var secondHeaders = await ReadHeadersAsync(stream, cancellationToken);
            bodies.Add(await ReadContentLengthBodyAsync(stream, secondHeaders, cancellationToken));
            await WriteAsciiAsync(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                cancellationToken);
        }
        listener.Stop();
        return bodies.ToArray();
    }

    private static async ValueTask<byte[]> ReadContentLengthBodyAsync(
        Stream stream,
        string headers,
        CancellationToken cancellationToken)
    {
        var line = headers.Split("\r\n").Single(value =>
            value.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
        var length = int.Parse(
            line[(line.IndexOf(':') + 1)..],
            System.Globalization.CultureInfo.InvariantCulture);
        var body = new byte[length];
        await ReadExactlyAsync(stream, body, cancellationToken);
        return body;
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

    private static TcpListener StartListener(out int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        port = ((IPEndPoint)listener.LocalEndpoint).Port;
        return listener;
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
        await server.AuthenticateAsync(client.GetStream(), false, cancellationToken);
        return server;
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

    private static async ValueTask<string> ReadLineAsync(
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
                    throw new InvalidDataException("Line did not end in CRLF.");
                }
                return Encoding.ASCII.GetString(data.AsSpan(0, data.Length - 1));
            }
            bytes.WriteByte(one[0]);
        }
        throw new InvalidDataException("Line exceeded the test limit.");
    }

    private static ReadOnlyMemory<byte> RemovePriority(Http2Frame frame) =>
        (frame.Flags & Http2FrameFlags.Priority) == 0
            ? frame.Payload
            : frame.Payload.AsMemory(5);

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
        string text,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(text), cancellationToken);
        await stream.FlushAsync(cancellationToken);
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

    private sealed record Http11ContinueCapture(bool BodyArrivedBeforeContinue, byte[] Body);

    private sealed record Http11TrailerCapture(string Headers, byte[] Body, string TrailerValue);

    private sealed record Http2ContinueCapture(
        IReadOnlyList<HpackHeader> InitialHeaders,
        IReadOnlyList<HpackHeader> Trailers,
        byte[] Body);
}
