using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class Http2LoopbackTests
{
    [Fact]
    public async Task Session_MultiplexesRequestsOverOneSharpTlsHttp2Connection()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var responsesReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunServerAsync(
            listener,
            serverCredential,
            responsesReceived.Task,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        options.Http2.HeaderPriority = new TlsHttp2Priority { Weight = 201 };
        var initialPriority = new TlsHttp2PriorityFrame(5);
        initialPriority.Priority.Weight = 101;
        options.Http2.InitialPriorityFrames = [initialPriority];
        options.Http2.PriorityUpdate = "u=3, i";
        await using var session = new TlsSession(options);
        var origin = $"https://127.0.0.1:{port}";

        var responses = await Task.WhenAll(
            session.GetAsync($"{origin}/first", timeout.Token),
            session.GetAsync($"{origin}/second", timeout.Token));
        responsesReceived.TrySetResult();
        var capture = await serverTask;

        Assert.Equal([1, 3], capture.StreamIds.Order());
        Assert.Equal(
            [
                TlsHttp2Setting.HeaderTableSize,
                TlsHttp2Setting.EnablePush,
                TlsHttp2Setting.InitialWindowSize,
                TlsHttp2Setting.MaxHeaderListSize,
            ],
            capture.Settings);
        Assert.Equal(2, capture.PriorityUpdateCount);
        Assert.True(capture.SawInitialPriority);
        Assert.True(capture.AllHeadersHadPriority);
        Assert.All(responses, response =>
        {
            Assert.Equal(HttpVersion.Version20, response.HttpVersion);
            Assert.Equal("h2", response.Tls.ApplicationProtocol);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        });
        Assert.Equal(["1", "3"], responses.Select(response => response.Text).Order());
    }

    [Fact]
    public async Task CancelledStream_IsResetWithoutClosingMultiplexedConnection()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var firstStreamReady = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var streamsReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = RunCancellationServerAsync(
            listener,
            serverCredential,
            firstStreamReady,
            streamsReady,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        await using var session = new TlsSession(options);
        var origin = $"https://127.0.0.1:{port}";
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);

        var cancelledRequest = session.GetAsync($"{origin}/cancel", cancelled.Token);
        await firstStreamReady.Task.WaitAsync(timeout.Token);
        var survivingRequest = session.GetAsync($"{origin}/survive", timeout.Token);
        await streamsReady.Task.WaitAsync(timeout.Token);
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelledRequest);
        var survivingResponse = await survivingRequest;
        var laterResponse = await session.GetAsync($"{origin}/later", timeout.Token);
        var capture = await serverTask;

        Assert.Equal("3", survivingResponse.Text);
        Assert.Equal("5", laterResponse.Text);
        Assert.Equal(1, capture.ResetStreamId);
        Assert.Equal([1, 3, 5], capture.RequestStreamIds.Order());
        Assert.Equal(Http2ErrorCode.Cancel, capture.ResetError);
    }

    [Fact]
    public async Task Upload_ResumesAfterConnectionAndStreamWindowUpdates()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = RunFlowControlServerAsync(
            listener,
            serverCredential,
            timeout.Token);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only,
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
            },
        };
        await using var session = new TlsSession(options);
        var body = Enumerable.Repeat((byte)0x5a, 100_000).ToArray();
        using var content = new ByteArrayContent(body);

        var response = await session.PostAsync(
            $"https://127.0.0.1:{port}/upload",
            content,
            timeout.Token);
        var received = await serverTask;

        Assert.Equal("1", response.Text);
        Assert.Equal(body, received);
    }

    [Fact]
    public async Task EarlyFinalResponse_CancelsFlowControlledUploadWithoutHanging()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = RunEarlyResponseServerAsync(
            listener,
            serverCredential,
            timeout.Token);

        var options = CreateHttp2Options(certificates.Root);
        await using var session = new TlsSession(options);
        using var content = new StreamContent(new BlockingUploadStream());
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://127.0.0.1:{port}/early")
        {
            Content = content,
        };
        await using var destination = new MemoryStream();

        var response = await session.SendStreamingAsync(
            request,
            destination,
            options: null,
            cancellationToken: timeout.Token);
        var resetError = await serverTask;

        Assert.True(response.BodyWasStreamed);
        Assert.Equal([(byte)'1'], destination.ToArray());
        Assert.Equal(Http2ErrorCode.Cancel, resetError);
    }

    [Fact]
    public async Task OversizedCompressedHeaderBlock_FailsBeforeContinuationBufferGrows()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = RunOversizedHeadersServerAsync(
            listener,
            serverCredential,
            timeout.Token);

        var options = CreateHttp2Options(certificates.Root);
        options.MaximumResponseHeaderBytes = 1024;
        await using var session = new TlsSession(options);

        var exception = await Assert.ThrowsAsync<TlsHttpProtocolException>(() =>
            session.GetAsync($"https://127.0.0.1:{port}/headers", timeout.Token));
        await serverTask;

        Assert.Contains("compressed HTTP/2 header block", exception.Message, StringComparison.Ordinal);
    }

    private static TlsSessionOptions CreateHttp2Options(X509Certificate2 trustRoot) => new()
    {
        Profile = TlsProfiles.Modern,
        HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only,
        ConfigureTls = tls =>
        {
            tls.CertificateValidation.CustomTrustRoots = [trustRoot];
            tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
            tls.CertificateValidation.DisableCertificateDownloads = true;
        },
    };

    private static async Task<Http2ErrorCode> RunEarlyResponseServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(tcpClient.GetStream(), leaveOpen: false, cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);

        var settings = new byte[6];
        BinaryPrimitives.WriteUInt16BigEndian(
            settings,
            (ushort)TlsHttp2Setting.InitialWindowSize);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            0,
            0,
            settings,
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var requestStreamId = 0;
        while (requestStreamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                requestStreamId = frame.StreamId;
            }
        }
        await SendOneByteResponseAsync(stream, requestStreamId, cancellationToken);

        while (true)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.RstStream && frame.StreamId == requestStreamId)
            {
                listener.Stop();
                return (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
            }
        }
    }

    private static async Task RunOversizedHeadersServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(tcpClient.GetStream(), leaveOpen: false, cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            0,
            0,
            [],
            cancellationToken);

        var requestStreamId = 0;
        while (requestStreamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                requestStreamId = frame.StreamId;
            }
        }
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            0,
            requestStreamId,
            new byte[800],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Continuation,
            Http2FrameFlags.EndHeaders,
            requestStreamId,
            new byte[800],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await WaitForClientCloseAsync(stream, cancellationToken);
        listener.Stop();
    }

    private static async Task<Http2Capture> RunServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task responsesReceived,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);

        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), preface);

        var clientSettings = await ReadFrameAsync(stream, cancellationToken);
        Assert.Equal(Http2FrameType.Settings, clientSettings.Type);
        Assert.Equal(0, clientSettings.StreamId);
        var settings = new List<TlsHttp2Setting>();
        for (var offset = 0; offset < clientSettings.Payload.Length; offset += 6)
        {
            settings.Add((TlsHttp2Setting)BinaryPrimitives.ReadUInt16BigEndian(
                clientSettings.Payload.AsSpan(offset, 2)));
        }
        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            0,
            0,
            [],
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            Http2FrameFlags.Ack,
            0,
            [],
            cancellationToken);

        var streamIds = new HashSet<int>();
        var sawInitialPriority = false;
        var allHeadersHadPriority = true;
        var priorityUpdateCount = 0;
        while (streamIds.Count < 2 || priorityUpdateCount < 2 || !sawInitialPriority)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                streamIds.Add(frame.StreamId);
                allHeadersHadPriority &= (frame.Flags & Http2FrameFlags.Priority) != 0;
            }
            else if (frame.Type == Http2FrameType.PriorityUpdate)
            {
                priorityUpdateCount++;
                Assert.Equal(0, frame.StreamId);
                Assert.Equal("u=3, i", System.Text.Encoding.ASCII.GetString(frame.Payload.AsSpan(4)));
            }
            else if (frame.Type == Http2FrameType.Priority && frame.StreamId == 5)
            {
                sawInitialPriority = true;
            }
        }

        foreach (var streamId in streamIds.OrderDescending())
        {
            byte[] responseHeaders = [0x88, 0x5c, 0x01, 0x31];
            await WriteFrameAsync(
                stream,
                Http2FrameType.Headers,
                Http2FrameFlags.EndHeaders,
                streamId,
                responseHeaders,
                cancellationToken);
            await WriteFrameAsync(
                stream,
                Http2FrameType.Data,
                Http2FrameFlags.EndStream,
                streamId,
                [(byte)('0' + streamId)],
                cancellationToken);
        }
        await stream.FlushAsync(cancellationToken);
        await DrainConnectionWindowUpdatesAsync(stream, 2, cancellationToken);
        await responsesReceived.WaitAsync(cancellationToken);
        listener.Stop();
        return new Http2Capture(
            streamIds.ToArray(),
            settings.ToArray(),
            priorityUpdateCount,
            sawInitialPriority,
            allHeadersHadPriority);
    }

    private static async Task<Http2CancellationCapture> RunCancellationServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        TaskCompletionSource firstStreamReady,
        TaskCompletionSource streamsReady,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            0,
            0,
            [],
            cancellationToken);

        var requestStreamIds = new HashSet<int>();
        while (requestStreamIds.Count < 2)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers)
            {
                requestStreamIds.Add(frame.StreamId);
                if (requestStreamIds.Count == 1)
                {
                    firstStreamReady.TrySetResult();
                }
            }
        }
        streamsReady.TrySetResult();

        await SendOneByteResponseAsync(stream, 3, cancellationToken);
        Http2Frame reset;
        var observedWindowUpdates = 0;
        do
        {
            reset = await ReadFrameAsync(stream, cancellationToken);
            if (reset.Type == Http2FrameType.WindowUpdate && reset.StreamId == 0)
            {
                observedWindowUpdates++;
            }
        }
        while (reset.Type != Http2FrameType.RstStream);

        var laterStreamId = 0;
        while (laterStreamId == 0)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.Headers && !requestStreamIds.Contains(frame.StreamId))
            {
                laterStreamId = frame.StreamId;
                requestStreamIds.Add(frame.StreamId);
            }
            else if (frame.Type == Http2FrameType.WindowUpdate && frame.StreamId == 0)
            {
                observedWindowUpdates++;
            }
        }
        await SendOneByteResponseAsync(stream, laterStreamId, cancellationToken);
        await DrainConnectionWindowUpdatesAsync(
            stream,
            2 - observedWindowUpdates,
            cancellationToken);
        listener.Stop();
        return new Http2CancellationCapture(
            requestStreamIds.ToArray(),
            reset.StreamId,
            (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(reset.Payload));
    }

    private static async Task<byte[]> RunFlowControlServerAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        _ = await ReadFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            0,
            0,
            [],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        using var received = new MemoryStream();
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
                received.Write(frame.Payload);
                ended = (frame.Flags & Http2FrameFlags.EndStream) != 0;
                if (!sentWindowUpdate && received.Length == 65_535)
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
        await SendOneByteResponseAsync(stream, streamId, cancellationToken);
        await DrainConnectionWindowUpdatesAsync(stream, 1, cancellationToken);
        listener.Stop();
        return received.ToArray();
    }

    private static async ValueTask SendOneByteResponseAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
    {
        byte[] responseHeaders = [0x88, 0x5c, 0x01, 0x31];
        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders,
            streamId,
            responseHeaders,
            cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2FrameType.Data,
            Http2FrameFlags.EndStream,
            streamId,
            [(byte)('0' + streamId)],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async ValueTask DrainConnectionWindowUpdatesAsync(
        Stream stream,
        int expectedCount,
        CancellationToken cancellationToken)
    {
        var count = 0;
        while (count < expectedCount)
        {
            var frame = await ReadFrameAsync(stream, cancellationToken);
            if (frame.Type == Http2FrameType.WindowUpdate && frame.StreamId == 0)
            {
                count++;
            }
        }
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
            // A protocol-error close does not have to include TLS close_notify.
        }
    }

    private sealed record Http2Capture(
        int[] StreamIds,
        TlsHttp2Setting[] Settings,
        int PriorityUpdateCount,
        bool SawInitialPriority,
        bool AllHeadersHadPriority);

    private sealed record Http2CancellationCapture(
        int[] RequestStreamIds,
        int ResetStreamId,
        Http2ErrorCode ResetError);

    private sealed class BlockingUploadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
