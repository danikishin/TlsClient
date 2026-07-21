using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Threading.Channels;

namespace TlsClient;

internal sealed class Http2Connection : IHttpConnection
{
    private static readonly byte[] ClientPreface =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    private readonly SharpTlsTransport _transport;
    private readonly TlsSessionConfiguration _configuration;
    private readonly int _localMaximumFrameSize;
    private readonly int _localInitialWindowSize;
    private readonly HpackEncoder _encoder = new();
    private readonly HpackDecoder _decoder;
    private readonly ConcurrentDictionary<int, Http2StreamState> _streams = new();
    private readonly ConcurrentDictionary<int, byte> _rejectedPushStreams = new();
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly SemaphoreSlim _windowSignal = new(0, int.MaxValue);
    private readonly SemaphoreSlim _streamSlotSignal = new(0, int.MaxValue);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _flowSync = new();
    private Task? _readerTask;
    private int _nextStreamId = -1;
    private int _peerMaximumFrameSize = 16 * 1024;
    private int _peerInitialWindowSize = 65_535;
    private int _peerMaximumConcurrentStreams = int.MaxValue;
    private int _highestPromisedStreamId;
    private int _connectionSendWindow = 65_535;
    private int _connectionReceiveWindow;
    private int _activeStreams;
    private int _hasCompletedRequest;
    private int _isReusable = 1;
    private int _disposed;

    private Http2Connection(
        SharpTlsTransport transport,
        TlsSessionConfiguration configuration)
    {
        _transport = transport;
        _configuration = configuration;
        var settings = configuration.Http2.SettingsOrder;
        _localMaximumFrameSize = settings.Contains(TlsHttp2Setting.MaxFrameSize)
            ? checked((int)configuration.Http2.MaxFrameSize)
            : 16 * 1024;
        _localInitialWindowSize = settings.Contains(TlsHttp2Setting.InitialWindowSize)
            ? checked((int)configuration.Http2.InitialWindowSize)
            : 65_535;
        _decoder = new HpackDecoder(
            settings.Contains(TlsHttp2Setting.HeaderTableSize)
                ? configuration.Http2.HeaderTableSize
                : 4096);
        _connectionReceiveWindow = checked(
            65_535 + (int)configuration.Http2.ConnectionWindowIncrement);
        LastUsed = DateTimeOffset.UtcNow;
    }

    public TlsConnectionInfo TlsInfo => _transport.TlsInfo;

    public DateTimeOffset LastUsed { get; private set; }

    public bool HasCompletedRequest => Volatile.Read(ref _hasCompletedRequest) != 0;

    public bool IsReusable => Volatile.Read(ref _isReusable) != 0;

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public bool HasActiveRequests => !_streams.IsEmpty;

    public int MaximumConcurrentRequests =>
        Math.Max(0, Volatile.Read(ref _peerMaximumConcurrentStreams));

    public static async ValueTask<Http2Connection> CreateAsync(
        SharpTlsTransport transport,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var connection = new Http2Connection(transport, configuration);
        try
        {
            await connection.SendClientPrefaceAsync(cancellationToken).ConfigureAwait(false);
            connection._readerTask = connection.ReadLoopAsync();
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<ParsedHttpResponse> SendAsync(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string? cookieHeader,
        StreamingResponseContext? streamingResponse,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        if (!IsReusable)
        {
            throw new StaleHttpConnectionException(
                "The HTTP/2 connection no longer accepts new streams.");
        }

        await AcquireStreamSlotAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsReusable)
            {
                throw new StaleHttpConnectionException(
                    "The HTTP/2 connection stopped accepting streams.");
            }
            var streamId = Interlocked.Add(ref _nextStreamId, 2);
            if (streamId <= 0)
            {
                Volatile.Write(ref _isReusable, 0);
                throw new HttpRequestException("The HTTP/2 stream identifier space is exhausted.");
            }
            var state = new Http2StreamState(
                streamId,
                request.Method,
                Volatile.Read(ref _peerInitialWindowSize),
                _localInitialWindowSize,
                configuration.MaximumResponseBodyBytes,
                configuration.MaximumResponseHeaderBytes,
                configuration.MaximumResponseHeaderCount,
                streamingResponse,
                RestoreReceiveWindowAsync,
                SignalWindow,
                cancellationToken,
                _lifetime.Token);
            if (!_streams.TryAdd(streamId, state))
            {
                throw new InvalidOperationException("The HTTP/2 stream identifier was reused.");
            }

            try
            {
                try
                {
                    await SendRequestAsync(
                        state,
                        request,
                        sessionHeaders,
                        cookieHeader,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Http2ResponseCompletedException)
                {
                    // A final response can legitimately stop a flow-controlled upload.
                    if (state.FinalResponse.Task.IsCompletedSuccessfully)
                    {
                        await TryResetStreamAsync(streamId, Http2ErrorCode.Cancel)
                            .ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    state.TryFail(exception);
                    if (state.HasStartedRequest)
                    {
                        await TryResetStreamAsync(streamId, Http2ErrorCode.InternalError)
                            .ConfigureAwait(false);
                    }
                    else if (exception is IOException)
                    {
                        Volatile.Write(ref _isReusable, 0);
                        SignalWindow();
                        SignalStreamSlot();
                    }
                    throw;
                }
                var response = await state.Completion.Task.WaitAsync(cancellationToken)
                    .ConfigureAwait(false);
                Interlocked.Exchange(ref _hasCompletedRequest, 1);
                LastUsed = DateTimeOffset.UtcNow;
                return response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                state.TryFail(new OperationCanceledException(cancellationToken));
                await TryResetStreamAsync(streamId, Http2ErrorCode.Cancel).ConfigureAwait(false);
                throw;
            }
            finally
            {
                _streams.TryRemove(streamId, out _);
                state.Dispose();
                if (!IsReusable && _streams.IsEmpty)
                {
                    await DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        finally
        {
            ReleaseStreamSlot();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Volatile.Write(ref _isReusable, 0);
        _lifetime.Cancel();
        FailAll(new ObjectDisposedException(nameof(Http2Connection)));
        await _transport.DisposeAsync().ConfigureAwait(false);
        if (_readerTask is not null)
        {
            try
            {
                await _readerTask.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The read loop reports its failure to active streams.
            }
        }
        _lifetime.Dispose();
        _writeGate.Dispose();
        _windowSignal.Dispose();
        _streamSlotSignal.Dispose();
    }

    private async ValueTask SendClientPrefaceAsync(CancellationToken cancellationToken)
    {
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _transport.Stream.WriteAsync(ClientPreface, cancellationToken)
                .ConfigureAwait(false);

            var settings = _configuration.Http2;
            var payload = new byte[checked(settings.SettingsOrder.Length * 6)];
            var offset = 0;
            foreach (var setting in settings.SettingsOrder)
            {
                BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(offset, 2), (ushort)setting);
                BinaryPrimitives.WriteUInt32BigEndian(
                    payload.AsSpan(offset + 2, 4),
                    GetSettingValue(setting, settings));
                offset += 6;
            }
            await WriteFrameLockedAsync(
                Http2FrameType.Settings,
                0,
                0,
                payload,
                cancellationToken).ConfigureAwait(false);

            if (settings.ConnectionWindowIncrement != 0)
            {
                var windowUpdate = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(
                    windowUpdate,
                    settings.ConnectionWindowIncrement);
                await WriteFrameLockedAsync(
                    Http2FrameType.WindowUpdate,
                    0,
                    0,
                    windowUpdate,
                    cancellationToken).ConfigureAwait(false);
            }
            foreach (var priorityFrame in settings.InitialPriorityFrames)
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.Priority,
                    0,
                    priorityFrame.StreamId,
                    BuildPriorityPayload(priorityFrame.Priority, priorityFrame.StreamId),
                    cancellationToken).ConfigureAwait(false);
            }
            await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async ValueTask SendRequestAsync(
        Http2StreamState state,
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string? cookieHeader,
        CancellationToken cancellationToken)
    {
        var headers = BuildRequestHeaders(request, sessionHeaders, cookieHeader);
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var block = _encoder.Encode(headers);
            if (block.Length > _configuration.MaximumRequestHeaderBytes)
            {
                Volatile.Write(ref _isReusable, 0);
                throw new HttpRequestException(
                    "The compressed HTTP/2 request headers exceed the configured limit.");
            }
            await WriteHeaderBlockLockedAsync(
                state.StreamId,
                block,
                !request.HasPayload || request.ContentLength == 0 && !request.HasTrailers,
                cancellationToken).ConfigureAwait(false);
            state.MarkRequestStarted();
            if (_configuration.Http2.PriorityUpdate is { } priorityUpdate)
            {
                var value = Encoding.ASCII.GetBytes(priorityUpdate);
                var payload = new byte[value.Length + 4];
                BinaryPrimitives.WriteInt32BigEndian(payload, state.StreamId);
                value.CopyTo(payload, 4);
                await WriteFrameLockedAsync(
                    Http2FrameType.PriorityUpdate,
                    0,
                    0,
                    payload,
                    cancellationToken).ConfigureAwait(false);
            }
            await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }

        if (request.HasContent && Http11RequestWriter.Has100Continue(
                request,
                sessionHeaders,
                cookieHeader) &&
            !await ShouldSendExpectedBodyAsync(
                state,
                _configuration.Expect100ContinueTimeout,
                cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        if (request.IsStreaming)
        {
            await SendStreamingRequestBodyAsync(state, request, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var offset = 0;
        while (offset < request.Body.Length)
        {
            var length = await ReserveSendWindowAsync(
                state,
                request.Body.Length - offset,
                cancellationToken).ConfigureAwait(false);
            await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var endStream = !request.HasTrailers && offset + length == request.Body.Length;
                await WriteFrameLockedAsync(
                    Http2FrameType.Data,
                    endStream ? Http2FrameFlags.EndStream : (byte)0,
                    state.StreamId,
                    request.Body.AsMemory(offset, length),
                    cancellationToken).ConfigureAwait(false);
                await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
            offset += length;
        }
        if (request.HasTrailers)
        {
            if (state.FinalResponse.Task.IsCompleted)
            {
                throw new Http2ResponseCompletedException();
            }
            await SendRequestTrailersAsync(state, request, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask SendStreamingRequestBodyAsync(
        Http2StreamState state,
        BufferedRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength == 0 && !request.HasTrailers)
        {
            return;
        }
        using var uploadCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            state.FinalResponseToken);
        var source = await request.OpenStreamingContentAsync(uploadCancellation.Token)
            .ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(request.StreamingBufferSize);
        long total = 0;
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(
                    buffer.AsMemory(0, request.StreamingBufferSize),
                    uploadCancellation.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total = checked(total + read);
                if (total > _configuration.MaximumRequestBodyBytes ||
                    request.ContentLength is { } declaredLength && total > declaredLength)
                {
                    throw new HttpRequestException(
                        "The streaming request body exceeds its declared or configured limit.");
                }
                await SendDataAsync(
                    state,
                    buffer.AsMemory(0, read),
                    endStream: false,
                    uploadCancellation.Token).ConfigureAwait(false);
            }

            if (request.ContentLength is { } expectedLength && total != expectedLength)
            {
                throw new HttpRequestException(
                    $"The streaming request body produced {total} bytes instead of " +
                    $"the declared {expectedLength} bytes.");
            }
            if (request.HasTrailers)
            {
                await SendRequestTrailersAsync(state, request, uploadCancellation.Token)
                    .ConfigureAwait(false);
            }
            else
            {
                await SendDataAsync(
                    state,
                    ReadOnlyMemory<byte>.Empty,
                    endStream: true,
                    uploadCancellation.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (state.FinalResponse.Task.IsCompleted)
        {
            throw new Http2ResponseCompletedException();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async ValueTask SendRequestTrailersAsync(
        Http2StreamState state,
        BufferedRequest request,
        CancellationToken cancellationToken)
    {
        var trailers = new List<HpackHeader>();
        long headerListSize = 0;
        foreach (var trailer in request.Trailers)
        {
            var name = trailer.Name.ToLowerInvariant();
            TlsRequestOptions.ValidateTrailerName(name);
            foreach (var value in trailer.Values)
            {
                Http11RequestWriter.ValidateHeaderValue(value);
                headerListSize = checked(
                    headerListSize + 32 + Encoding.UTF8.GetByteCount(name) +
                    Encoding.UTF8.GetByteCount(value));
                trailers.Add(new HpackHeader(name, value));
            }
        }
        if (headerListSize > _configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The HTTP/2 request trailers exceed the configured header limit.");
        }

        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var block = _encoder.Encode(trailers);
            if (block.Length > _configuration.MaximumRequestHeaderBytes)
            {
                throw new HttpRequestException(
                    "The compressed HTTP/2 request trailers exceed the configured limit.");
            }
            await WriteHeaderBlockLockedAsync(
                state.StreamId,
                block,
                endStream: true,
                cancellationToken,
                includePriority: false).ConfigureAwait(false);
            await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private static async ValueTask<bool> ShouldSendExpectedBodyAsync(
        Http2StreamState state,
        TimeSpan expectTimeout,
        CancellationToken cancellationToken)
    {
        if (expectTimeout == TimeSpan.Zero)
        {
            return true;
        }
        var delay = Task.Delay(expectTimeout, cancellationToken);
        var completed = await Task.WhenAny(
            state.Continue.Task,
            state.FinalResponse.Task,
            state.Completion.Task,
            delay).ConfigureAwait(false);
        if (completed == state.Continue.Task)
        {
            return true;
        }
        if (completed == state.FinalResponse.Task)
        {
            return false;
        }
        if (completed == state.Completion.Task)
        {
            _ = await state.Completion.Task.ConfigureAwait(false);
            return false;
        }
        await delay.ConfigureAwait(false);
        return true;
    }

    private async ValueTask SendDataAsync(
        Http2StreamState state,
        ReadOnlyMemory<byte> data,
        bool endStream,
        CancellationToken cancellationToken)
    {
        if (data.IsEmpty)
        {
            await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.Data,
                    endStream ? Http2FrameFlags.EndStream : (byte)0,
                    state.StreamId,
                    data,
                    cancellationToken).ConfigureAwait(false);
                await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
            return;
        }

        var offset = 0;
        while (offset < data.Length)
        {
            var length = await ReserveSendWindowAsync(
                state,
                data.Length - offset,
                cancellationToken).ConfigureAwait(false);
            await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var isFinalFrame = endStream && offset + length == data.Length;
                await WriteFrameLockedAsync(
                    Http2FrameType.Data,
                    isFinalFrame ? Http2FrameFlags.EndStream : (byte)0,
                    state.StreamId,
                    data.Slice(offset, length),
                    cancellationToken).ConfigureAwait(false);
                await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
            offset += length;
        }
    }

    private List<HpackHeader> BuildRequestHeaders(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string? cookieHeader)
    {
        var regular = Http11RequestWriter.MergeHeaders(request, sessionHeaders, cookieHeader);
        regular = Http11RequestWriter.Order(regular, _configuration.HeaderOrder);
        var host = regular.FirstOrDefault(header =>
            string.Equals(header.Name, "Host", StringComparison.OrdinalIgnoreCase));
        var authority = host?.Values.FirstOrDefault() ?? Http11RequestWriter.FormatAuthority(request.Url);
        string path = request.Url.GetComponents(UriComponents.PathAndQuery, UriFormat.UriEscaped);
        if (path.Length == 0)
        {
            path = "/";
        }

        var pseudoValues = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [":method"] = request.Method,
            [":authority"] = authority,
            [":scheme"] = "https",
            [":path"] = path,
        };
        var output = new List<HpackHeader>();
        foreach (var name in _configuration.Http2.PseudoHeaderOrder)
        {
            output.Add(new HpackHeader(name, pseudoValues[name]));
        }

        foreach (var header in regular)
        {
            var name = header.Name.ToLowerInvariant();
            if (name is "host" or "connection" or "proxy-connection" or "keep-alive" or
                "upgrade" or "transfer-encoding" or "proxy-authorization")
            {
                continue;
            }
            if (name == "te" && header.Values.Any(value =>
                    !string.Equals(value.Trim(), "trailers", StringComparison.OrdinalIgnoreCase)))
            {
                throw new HttpRequestException(
                    "HTTP/2 permits TE only with the value 'trailers'.");
            }
            var sensitive = name is "authorization" or "cookie";
            foreach (var value in header.Values)
            {
                output.Add(new HpackHeader(name, value, sensitive));
            }
        }
        long headerListSize = 0;
        foreach (var header in output)
        {
            headerListSize = checked(
                headerListSize + 32 + Encoding.UTF8.GetByteCount(header.Name) +
                Encoding.UTF8.GetByteCount(header.Value));
        }
        if (headerListSize > _configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The HTTP/2 request header list exceeds the configured limit.");
        }
        return output;
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var frame = await ReadFrameAsync(_lifetime.Token).ConfigureAwait(false);
                await HandleFrameAsync(frame, _lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Volatile.Write(ref _isReusable, 0);
            if (exception is TlsHttpProtocolException)
            {
                await TrySendGoAwayAsync(Http2ErrorCode.ProtocolError).ConfigureAwait(false);
            }
            FailAll(
                exception is TlsHttpProtocolException
                    ? exception
                    : new IOException("The HTTP/2 connection failed.", exception),
                preserveEndedStreams: true);
            SignalStreamSlot();
        }
    }

    private async ValueTask<Http2Frame> ReadFrameAsync(CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var parsed = Http2FrameParser.ParseHeader(header, _localMaximumFrameSize);
        var payload = new byte[parsed.Length];
        await ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return new Http2Frame(parsed.Type, parsed.Flags, parsed.StreamId, payload);
    }

    private async ValueTask HandleFrameAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        switch (frame.Type)
        {
            case Http2FrameType.Data:
                await HandleDataAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.Headers:
                await HandleHeadersAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.Priority:
                ValidateFrame(frame, streamMustBeZero: false, length: 5);
                break;
            case Http2FrameType.RstStream:
                HandleReset(frame);
                break;
            case Http2FrameType.Settings:
                await HandleSettingsAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.PushPromise:
                await HandlePushPromiseAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.Ping:
                await HandlePingAsync(frame, cancellationToken).ConfigureAwait(false);
                break;
            case Http2FrameType.GoAway:
                HandleGoAway(frame);
                break;
            case Http2FrameType.WindowUpdate:
                HandleWindowUpdate(frame);
                break;
            case Http2FrameType.Continuation:
                throw new TlsHttpProtocolException("An unexpected CONTINUATION frame was received.");
            default:
                // Unknown extension frames are ignored as required by RFC 9113.
                break;
        }
    }

    private async ValueTask HandleDataAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException("A DATA frame used stream zero.");
        }
        var payloadLength = frame.Payload.Length;
        Http2StreamState? state;
        lock (_flowSync)
        {
            _connectionReceiveWindow -= payloadLength;
            if (_connectionReceiveWindow < 0)
            {
                throw new TlsHttpProtocolException(
                    "The peer exceeded the HTTP/2 connection receive window.");
            }
            if (_streams.TryGetValue(frame.StreamId, out state))
            {
                state.ReceiveWindow -= payloadLength;
                if (state.ReceiveWindow < 0)
                {
                    throw new TlsHttpProtocolException(
                        "The peer exceeded an HTTP/2 stream receive window.");
                }
            }
        }
        if (state is null)
        {
            if (IsIdleStream(frame.StreamId))
            {
                throw new TlsHttpProtocolException("DATA was received for an idle HTTP/2 stream.");
            }
            await SendWindowUpdateAsync(0, payloadLength, cancellationToken)
                .ConfigureAwait(false);
            lock (_flowSync)
            {
                _connectionReceiveWindow += payloadLength;
            }
            if ((frame.Flags & Http2FrameFlags.EndStream) != 0)
            {
                _rejectedPushStreams.TryRemove(frame.StreamId, out _);
            }
            return;
        }
        var data = RemovePadding(frame);
        var endStream = (frame.Flags & Http2FrameFlags.EndStream) != 0;
        state.EnqueueBody(data, frame.Payload.Length, endStream);
    }

    private async ValueTask HandleHeadersAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException("A HEADERS frame used stream zero.");
        }
        var streamId = frame.StreamId;
        var endStream = (frame.Flags & Http2FrameFlags.EndStream) != 0;
        var fragment = ExtractHeaderFragment(frame);
        using var block = new MemoryStream();
        AppendHeaderFragment(block, fragment);
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame.Type != Http2FrameType.Continuation ||
                frame.StreamId != streamId)
            {
                throw new TlsHttpProtocolException(
                    "A header block was interrupted before END_HEADERS.");
            }
            AppendHeaderFragment(block, frame.Payload);
        }

        var headers = _decoder.Decode(
            block.GetBuffer().AsSpan(0, checked((int)block.Length)),
            Math.Min(
                _configuration.Http2.MaxHeaderListSize,
                (uint)_configuration.MaximumResponseHeaderBytes));
        if (_streams.TryGetValue(streamId, out var state))
        {
            var trailers = state.ApplyHeaders(headers);
            if (trailers && !endStream)
            {
                throw new TlsHttpProtocolException(
                    "HTTP/2 trailers must carry END_STREAM.");
            }
            if (endStream)
            {
                state.EnqueueEnd();
            }
        }
        else if (IsIdleStream(streamId))
        {
            throw new TlsHttpProtocolException("HEADERS was received for an idle HTTP/2 stream.");
        }
        else if (endStream)
        {
            _rejectedPushStreams.TryRemove(streamId, out _);
        }
    }

    private async ValueTask HandlePushPromiseAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (_configuration.Http2.SettingsOrder.Contains(TlsHttp2Setting.EnablePush))
        {
            throw new TlsHttpProtocolException(
                "The peer sent PUSH_PROMISE although server push was disabled.");
        }
        if (frame.StreamId == 0)
        {
            throw new TlsHttpProtocolException("A PUSH_PROMISE frame used stream zero.");
        }

        var associatedStreamId = frame.StreamId;
        var (promisedStreamId, fragment) = ExtractPushPromiseFragment(frame);
        if (promisedStreamId == 0 || (promisedStreamId & 1) != 0)
        {
            throw new TlsHttpProtocolException(
                "A PUSH_PROMISE used an invalid promised stream identifier.");
        }
        if (!_streams.ContainsKey(associatedStreamId))
        {
            throw new TlsHttpProtocolException(
                "A PUSH_PROMISE referenced an idle or closed associated stream.");
        }
        if (promisedStreamId <= _highestPromisedStreamId)
        {
            throw new TlsHttpProtocolException(
                "A PUSH_PROMISE reused or reordered a promised stream identifier.");
        }
        if (_rejectedPushStreams.Count >= 1024)
        {
            throw new TlsHttpProtocolException(
                "Too many rejected HTTP/2 push streams remain outstanding.");
        }
        _highestPromisedStreamId = promisedStreamId;
        using var block = new MemoryStream();
        AppendHeaderFragment(block, fragment);
        while ((frame.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame.Type != Http2FrameType.Continuation ||
                frame.StreamId != associatedStreamId)
            {
                throw new TlsHttpProtocolException(
                    "A PUSH_PROMISE header block was interrupted before END_HEADERS.");
            }
            AppendHeaderFragment(block, frame.Payload);
        }

        _ = _decoder.Decode(
            block.GetBuffer().AsSpan(0, checked((int)block.Length)),
            Math.Min(
                _configuration.Http2.MaxHeaderListSize,
                (uint)_configuration.MaximumResponseHeaderBytes));
        _rejectedPushStreams.TryAdd(promisedStreamId, 0);
        await TryResetStreamAsync(promisedStreamId, Http2ErrorCode.Cancel).ConfigureAwait(false);
    }

    private async ValueTask HandleSettingsAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        if (frame.StreamId != 0 || frame.Payload.Length % 6 != 0)
        {
            throw new TlsHttpProtocolException("A SETTINGS frame is malformed.");
        }
        if ((frame.Flags & Http2FrameFlags.Ack) != 0)
        {
            if (frame.Payload.Length != 0)
            {
                throw new TlsHttpProtocolException("A SETTINGS ACK contained a payload.");
            }
            return;
        }

        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            for (var offset = 0; offset < frame.Payload.Length; offset += 6)
            {
                var identifier = BinaryPrimitives.ReadUInt16BigEndian(
                    frame.Payload.AsSpan(offset, 2));
                var value = BinaryPrimitives.ReadUInt32BigEndian(
                    frame.Payload.AsSpan(offset + 2, 4));
                switch ((TlsHttp2Setting)identifier)
                {
                    case TlsHttp2Setting.HeaderTableSize:
                        _encoder.SetMaximumDynamicTableSize(value);
                        break;
                    case TlsHttp2Setting.EnablePush:
                        throw new TlsHttpProtocolException(
                            "A server must not send SETTINGS_ENABLE_PUSH.");
                    case TlsHttp2Setting.MaxConcurrentStreams:
                        lock (_flowSync)
                        {
                            _peerMaximumConcurrentStreams =
                                value > int.MaxValue ? int.MaxValue : (int)value;
                        }
                        SignalStreamSlot();
                        break;
                    case TlsHttp2Setting.InitialWindowSize:
                        if (value > int.MaxValue)
                        {
                            throw new TlsHttpProtocolException(
                                "SETTINGS_INITIAL_WINDOW_SIZE is invalid.");
                        }
                        ApplyInitialWindowSize((int)value);
                        break;
                    case TlsHttp2Setting.MaxFrameSize:
                        if (value is < 16 * 1024 or > 16_777_215)
                        {
                            throw new TlsHttpProtocolException("SETTINGS_MAX_FRAME_SIZE is invalid.");
                        }
                        Volatile.Write(ref _peerMaximumFrameSize, (int)value);
                        break;
                    case TlsHttp2Setting.EnableConnectProtocol when value > 1:
                    case TlsHttp2Setting.NoRfc7540Priorities when value > 1:
                        throw new TlsHttpProtocolException("A boolean SETTINGS value is invalid.");
                }
            }
            await WriteFrameLockedAsync(
                Http2FrameType.Settings,
                Http2FrameFlags.Ack,
                0,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken).ConfigureAwait(false);
            await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async ValueTask HandlePingAsync(
        Http2Frame frame,
        CancellationToken cancellationToken)
    {
        ValidateFrame(frame, streamMustBeZero: true, length: 8);
        if ((frame.Flags & Http2FrameFlags.Ack) != 0)
        {
            return;
        }
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameLockedAsync(
                Http2FrameType.Ping,
                Http2FrameFlags.Ack,
                0,
                frame.Payload,
                cancellationToken).ConfigureAwait(false);
            await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private void HandleReset(Http2Frame frame)
    {
        ValidateFrame(frame, streamMustBeZero: false, length: 4);
        if (_streams.TryGetValue(frame.StreamId, out var state))
        {
            var error = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
            state.TryFail(new HttpRequestException(
                $"The peer reset HTTP/2 stream {frame.StreamId} with {error}."));
        }
        else if (IsIdleStream(frame.StreamId))
        {
            throw new TlsHttpProtocolException("RST_STREAM was received for an idle stream.");
        }
        _rejectedPushStreams.TryRemove(frame.StreamId, out _);
        SignalWindow();
    }

    private void HandleGoAway(Http2Frame frame)
    {
        if (frame.StreamId != 0 || frame.Payload.Length < 8)
        {
            throw new TlsHttpProtocolException("A GOAWAY frame is malformed.");
        }
        Volatile.Write(ref _isReusable, 0);
        var lastStreamId = BinaryPrimitives.ReadInt32BigEndian(frame.Payload) & 0x7fff_ffff;
        var error = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(4));
        foreach (var pair in _streams)
        {
            if (pair.Key > lastStreamId || error != Http2ErrorCode.NoError)
            {
                pair.Value.TryFail(new HttpRequestException(
                    $"The peer closed the HTTP/2 connection with {error}."));
            }
        }
        SignalWindow();
        SignalStreamSlot();
    }

    private void HandleWindowUpdate(Http2Frame frame)
    {
        if (frame.Payload.Length != 4)
        {
            throw new TlsHttpProtocolException("A WINDOW_UPDATE frame is malformed.");
        }
        var increment = BinaryPrimitives.ReadInt32BigEndian(frame.Payload) & 0x7fff_ffff;
        if (increment == 0)
        {
            throw new TlsHttpProtocolException("A WINDOW_UPDATE increment was zero.");
        }
        lock (_flowSync)
        {
            if (frame.StreamId == 0)
            {
                _connectionSendWindow = checked(_connectionSendWindow + increment);
            }
            else if (_streams.TryGetValue(frame.StreamId, out var state))
            {
                state.SendWindow = checked(state.SendWindow + increment);
            }
            else if (IsIdleStream(frame.StreamId))
            {
                throw new TlsHttpProtocolException(
                    "WINDOW_UPDATE was received for an idle stream.");
            }
        }
        SignalWindow();
    }

    private void ApplyInitialWindowSize(int value)
    {
        lock (_flowSync)
        {
            var delta = value - _peerInitialWindowSize;
            foreach (var state in _streams.Values)
            {
                state.SendWindow = checked(state.SendWindow + delta);
            }
            Volatile.Write(ref _peerInitialWindowSize, value);
        }
        SignalWindow();
    }

    private async ValueTask<int> ReserveSendWindowAsync(
        Http2StreamState state,
        int requested,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            if (state.Completion.Task.IsCompleted)
            {
                throw new Http2ResponseCompletedException();
            }
            lock (_flowSync)
            {
                var length = Math.Min(
                    requested,
                    Math.Min(
                        Volatile.Read(ref _peerMaximumFrameSize),
                        Math.Min(_connectionSendWindow, state.SendWindow)));
                if (length > 0)
                {
                    _connectionSendWindow -= length;
                    state.SendWindow -= length;
                    return length;
                }
            }
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            try
            {
                await _windowSignal.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                _lifetime.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new ObjectDisposedException(nameof(Http2Connection));
            }
            if (state.Completion.Task.IsCompleted)
            {
                throw new Http2ResponseCompletedException();
            }
        }
    }

    private async ValueTask AcquireStreamSlotAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (!IsReusable)
            {
                SignalStreamSlot();
                throw new StaleHttpConnectionException(
                    "The HTTP/2 connection stopped accepting streams.");
            }
            var acquired = false;
            var wakeAnotherWaiter = false;
            lock (_flowSync)
            {
                if (_activeStreams < _peerMaximumConcurrentStreams)
                {
                    _activeStreams++;
                    acquired = true;
                    wakeAnotherWaiter = _activeStreams < _peerMaximumConcurrentStreams;
                }
            }
            if (acquired)
            {
                if (wakeAnotherWaiter)
                {
                    SignalStreamSlot();
                }
                return;
            }
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            try
            {
                await _streamSlotSignal.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                _lifetime.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new ObjectDisposedException(nameof(Http2Connection));
            }
        }
    }

    private void ReleaseStreamSlot()
    {
        lock (_flowSync)
        {
            _activeStreams--;
        }
        SignalStreamSlot();
    }

    private async ValueTask SendWindowUpdateAsync(
        int streamId,
        int increment,
        CancellationToken cancellationToken)
    {
        if (increment == 0)
        {
            return;
        }
        var payload = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(payload, increment);
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameLockedAsync(
                Http2FrameType.WindowUpdate,
                0,
                streamId,
                payload,
                cancellationToken).ConfigureAwait(false);
            await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async ValueTask RestoreReceiveWindowAsync(
        Http2StreamState state,
        int increment,
        bool endStream,
        CancellationToken cancellationToken)
    {
        if (increment == 0)
        {
            return;
        }
        try
        {
            await SendWindowUpdateAsync(0, increment, cancellationToken).ConfigureAwait(false);
            lock (_flowSync)
            {
                _connectionReceiveWindow += increment;
            }
            if (endStream)
            {
                return;
            }
            await SendWindowUpdateAsync(state.StreamId, increment, cancellationToken)
                .ConfigureAwait(false);
            lock (_flowSync)
            {
                state.ReceiveWindow += increment;
            }
        }
        catch (Exception exception) when (
            state.HasReceivedEndStream && exception is not OperationCanceledException)
        {
            // The full response is already queued locally and the peer closed the connection.
            Volatile.Write(ref _isReusable, 0);
        }
    }

    private async ValueTask TryResetStreamAsync(int streamId, Http2ErrorCode errorCode)
    {
        if (IsDisposed || !IsReusable)
        {
            return;
        }
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, (uint)errorCode);
        try
        {
            await _writeGate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
            try
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.RstStream,
                    0,
                    streamId,
                    payload,
                    _lifetime.Token).ConfigureAwait(false);
                await _transport.Stream.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
        }
        catch (Exception) when (_lifetime.IsCancellationRequested)
        {
        }
    }

    private async ValueTask TrySendGoAwayAsync(Http2ErrorCode errorCode)
    {
        if (IsDisposed || _lifetime.IsCancellationRequested)
        {
            return;
        }
        var payload = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(
            payload,
            Math.Max(0, Volatile.Read(ref _nextStreamId)));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4), (uint)errorCode);
        try
        {
            await _writeGate.WaitAsync(_lifetime.Token).ConfigureAwait(false);
            try
            {
                await WriteFrameLockedAsync(
                    Http2FrameType.GoAway,
                    0,
                    0,
                    payload,
                    _lifetime.Token).ConfigureAwait(false);
                await _transport.Stream.FlushAsync(_lifetime.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeGate.Release();
            }
        }
        catch (Exception)
        {
            // The protocol error may have arrived with an already-failed transport.
        }
    }

    private async ValueTask WriteHeaderBlockLockedAsync(
        int streamId,
        byte[] block,
        bool endStream,
        CancellationToken cancellationToken,
        bool includePriority = true)
    {
        var maximumFrameSize = Volatile.Read(ref _peerMaximumFrameSize);
        var offset = 0;
        var first = true;
        do
        {
            var priority = first && includePriority ? _configuration.Http2.HeaderPriority : null;
            var priorityLength = priority is null ? 0 : 5;
            var length = Math.Min(maximumFrameSize - priorityLength, block.Length - offset);
            var last = offset + length == block.Length;
            var flags = last ? Http2FrameFlags.EndHeaders : (byte)0;
            if (first && endStream)
            {
                flags |= Http2FrameFlags.EndStream;
            }
            ReadOnlyMemory<byte> payload;
            if (priority is not null)
            {
                flags |= Http2FrameFlags.Priority;
                var priorityPayload = new byte[length + 5];
                BuildPriorityPayload(priority, streamId).CopyTo(priorityPayload, 0);
                block.AsSpan(offset, length).CopyTo(priorityPayload.AsSpan(5));
                payload = priorityPayload;
            }
            else
            {
                payload = block.AsMemory(offset, length);
            }
            await WriteFrameLockedAsync(
                first ? Http2FrameType.Headers : Http2FrameType.Continuation,
                flags,
                streamId,
                payload,
                cancellationToken).ConfigureAwait(false);
            first = false;
            offset += length;
        }
        while (offset < block.Length);
    }

    private async ValueTask WriteFrameLockedAsync(
        Http2FrameType type,
        byte flags,
        int streamId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (payload.Length > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(nameof(payload));
        }
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId & 0x7fff_ffff);
        await _transport.Stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        if (payload.Length != 0)
        {
            await _transport.Stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask ReadExactlyAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await _transport.Stream.ReadAsync(destination[offset..], cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The HTTP/2 connection closed unexpectedly.");
            }
            offset += read;
        }
    }

    private static ReadOnlyMemory<byte> RemovePadding(Http2Frame frame)
    {
        if ((frame.Flags & Http2FrameFlags.Padded) == 0)
        {
            return frame.Payload;
        }
        if (frame.Payload.Length == 0 || frame.Payload[0] >= frame.Payload.Length)
        {
            throw new TlsHttpProtocolException("An HTTP/2 padding length is invalid.");
        }
        return frame.Payload.AsMemory(1, frame.Payload.Length - frame.Payload[0] - 1);
    }

    private static ReadOnlyMemory<byte> ExtractHeaderFragment(Http2Frame frame)
    {
        var offset = 0;
        var padding = 0;
        if ((frame.Flags & Http2FrameFlags.Padded) != 0)
        {
            if (frame.Payload.Length == 0)
            {
                throw new TlsHttpProtocolException("A padded HEADERS frame is empty.");
            }
            padding = frame.Payload[offset++];
        }
        if ((frame.Flags & Http2FrameFlags.Priority) != 0)
        {
            offset += 5;
        }
        if (offset > frame.Payload.Length || padding > frame.Payload.Length - offset)
        {
            throw new TlsHttpProtocolException("A HEADERS frame has invalid padding or priority.");
        }
        return frame.Payload.AsMemory(offset, frame.Payload.Length - offset - padding);
    }

    private void AppendHeaderFragment(MemoryStream block, ReadOnlyMemory<byte> fragment)
    {
        if (block.Length + fragment.Length > _configuration.MaximumResponseHeaderBytes)
        {
            throw new TlsHttpProtocolException(
                "The compressed HTTP/2 header block exceeded the configured limit.");
        }
        block.Write(fragment.Span);
    }

    private bool IsIdleStream(int streamId) => (streamId & 1) != 0
        ? streamId > Volatile.Read(ref _nextStreamId)
        : streamId > _highestPromisedStreamId;

    private static (int PromisedStreamId, ReadOnlyMemory<byte> Fragment)
        ExtractPushPromiseFragment(Http2Frame frame)
    {
        var offset = 0;
        var padding = 0;
        if ((frame.Flags & Http2FrameFlags.Padded) != 0)
        {
            if (frame.Payload.Length == 0)
            {
                throw new TlsHttpProtocolException("A padded PUSH_PROMISE frame is empty.");
            }
            padding = frame.Payload[offset++];
        }
        if (frame.Payload.Length - offset < 4)
        {
            throw new TlsHttpProtocolException("A PUSH_PROMISE frame is truncated.");
        }
        var promisedStreamId = BinaryPrimitives.ReadInt32BigEndian(
            frame.Payload.AsSpan(offset, 4)) & 0x7fff_ffff;
        offset += 4;
        if (padding > frame.Payload.Length - offset)
        {
            throw new TlsHttpProtocolException("A PUSH_PROMISE padding length is invalid.");
        }
        return (
            promisedStreamId,
            frame.Payload.AsMemory(offset, frame.Payload.Length - offset - padding));
    }

    private static void ValidateFrame(Http2Frame frame, bool streamMustBeZero, int length)
    {
        if ((streamMustBeZero ? frame.StreamId != 0 : frame.StreamId == 0) ||
            frame.Payload.Length != length)
        {
            throw new TlsHttpProtocolException($"A {frame.Type} frame is malformed.");
        }
    }

    private static uint GetSettingValue(
        TlsHttp2Setting setting,
        TlsHttp2Configuration configuration) => setting switch
        {
            TlsHttp2Setting.HeaderTableSize => configuration.HeaderTableSize,
            TlsHttp2Setting.EnablePush => 0,
            TlsHttp2Setting.MaxConcurrentStreams => configuration.MaxConcurrentStreams,
            TlsHttp2Setting.InitialWindowSize => configuration.InitialWindowSize,
            TlsHttp2Setting.MaxFrameSize => configuration.MaxFrameSize,
            TlsHttp2Setting.MaxHeaderListSize => configuration.MaxHeaderListSize,
            TlsHttp2Setting.EnableConnectProtocol => configuration.EnableConnectProtocol ? 1U : 0,
            TlsHttp2Setting.NoRfc7540Priorities =>
                configuration.DisableRfc7540Priorities ? 1U : 0,
            _ => throw new ArgumentOutOfRangeException(nameof(setting)),
        };

    private static byte[] BuildPriorityPayload(
        TlsHttp2PriorityConfiguration priority,
        int streamId)
    {
        if (priority.StreamDependency == streamId)
        {
            throw new HttpRequestException("An HTTP/2 stream cannot depend on itself.");
        }
        var payload = new byte[5];
        var dependency = priority.StreamDependency;
        if (priority.Exclusive)
        {
            dependency |= int.MinValue;
        }
        BinaryPrimitives.WriteInt32BigEndian(payload, dependency);
        payload[4] = (byte)(priority.Weight - 1);
        return payload;
    }

    private void FailAll(Exception exception, bool preserveEndedStreams = false)
    {
        foreach (var stream in _streams.Values)
        {
            if (!preserveEndedStreams || !stream.HasReceivedEndStream)
            {
                stream.TryFail(exception);
            }
        }
        SignalWindow();
    }

    private void SignalWindow()
    {
        try
        {
            _windowSignal.Release();
        }
        catch (SemaphoreFullException)
        {
        }
        catch (ObjectDisposedException)
        {
            // A final stream may race the connection's deterministic shutdown.
        }
    }

    private void SignalStreamSlot()
    {
        try
        {
            _streamSlotSignal.Release();
        }
        catch (SemaphoreFullException)
        {
        }
        catch (ObjectDisposedException)
        {
            // A final stream may race the connection's deterministic shutdown.
        }
    }
}

internal sealed class Http2StreamState : IDisposable
{
    private readonly MemoryStream _body = new();
    private readonly int _maximumBodyBytes;
    private readonly int _maximumHeaderBytes;
    private readonly int _maximumHeaderCount;
    private readonly StreamingResponseContext? _streamingResponse;
    private readonly Func<Http2StreamState, int, bool, CancellationToken, ValueTask>
        _restoreReceiveWindow;
    private readonly Action _signalStateChange;
    private readonly CancellationTokenSource _responseCancellation;
    private readonly CancellationTokenSource _finalResponseCancellation = new();
    private readonly Channel<QueuedHttp2Data> _incoming = Channel.CreateUnbounded<QueuedHttp2Data>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false,
        });
    private readonly Task _bodyPump;
    private TlsHeaders? _headers;
    private TlsHeaders? _trailers;
    private HttpStatusCode? _statusCode;
    private int _headerBytes;
    private long _bodyLength;
    private long _receivedBodyLength;
    private int _completed;
    private int _endReceived;
    private int _stateChangeSignaled;
    private int _requestStarted;

    public Http2StreamState(
        int streamId,
        string requestMethod,
        int sendWindow,
        int receiveWindow,
        int maximumBodyBytes,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        StreamingResponseContext? streamingResponse,
        Func<Http2StreamState, int, bool, CancellationToken, ValueTask> restoreReceiveWindow,
        Action signalStateChange,
        CancellationToken requestCancellation,
        CancellationToken connectionCancellation)
    {
        StreamId = streamId;
        RequestMethod = requestMethod;
        SendWindow = sendWindow;
        ReceiveWindow = receiveWindow;
        _maximumBodyBytes = maximumBodyBytes;
        _maximumHeaderBytes = maximumHeaderBytes;
        _maximumHeaderCount = maximumHeaderCount;
        _streamingResponse = streamingResponse;
        _restoreReceiveWindow = restoreReceiveWindow;
        _signalStateChange = signalStateChange;
        _responseCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            requestCancellation,
            connectionCancellation);
        _bodyPump = PumpBodyAsync();
    }

    public int StreamId { get; }

    public string RequestMethod { get; }

    public int SendWindow { get; set; }

    public int ReceiveWindow { get; set; }

    public bool HasReceivedEndStream => Volatile.Read(ref _endReceived) != 0;

    public bool HasStartedRequest => Volatile.Read(ref _requestStarted) != 0;

    public CancellationToken FinalResponseToken => _finalResponseCancellation.Token;

    public TaskCompletionSource<ParsedHttpResponse> Completion { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource Continue { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource FinalResponse { get; } = new(
        TaskCreationOptions.RunContinuationsAsynchronously);

    public void MarkRequestStarted() => Interlocked.Exchange(ref _requestStarted, 1);

    public bool ApplyHeaders(IReadOnlyList<HpackHeader> fields)
    {
        var pseudoEnded = false;
        string? status = null;
        var regular = new List<HpackHeader>();
        foreach (var field in fields)
        {
            if (field.Name.Any(character => character is >= 'A' and <= 'Z'))
            {
                throw new TlsHttpProtocolException("HTTP/2 header names must be lowercase.");
            }
            if (field.Name.StartsWith(':'))
            {
                if (pseudoEnded || field.Name != ":status" || status is not null)
                {
                    throw new TlsHttpProtocolException("The HTTP/2 response pseudo-headers are invalid.");
                }
                status = field.Value;
            }
            else
            {
                pseudoEnded = true;
                if (field.Name is "connection" or "proxy-connection" or "keep-alive" or
                    "upgrade" or "transfer-encoding")
                {
                    throw new TlsHttpProtocolException(
                        $"The HTTP/2 response contains forbidden header '{field.Name}'.");
                }
                if (field.Name == "te" && !string.Equals(
                        field.Value.Trim(),
                        "trailers",
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new TlsHttpProtocolException("The HTTP/2 TE header is invalid.");
                }
                regular.Add(field);
            }
        }

        if (_headers is null)
        {
            if (status is null || status.Length != 3 ||
                !int.TryParse(status, NumberStyles.None, CultureInfo.InvariantCulture, out var code) ||
                code is < 100 or > 999)
            {
                throw new TlsHttpProtocolException("The HTTP/2 response has no valid :status.");
            }
            if (code is >= 100 and < 200)
            {
                if (code == 101)
                {
                    throw new TlsHttpProtocolException(
                        "HTTP/2 does not permit a 101 Switching Protocols response.");
                }
                if (code == 100)
                {
                    Continue.TrySetResult();
                }
                return false;
            }
            _statusCode = (HttpStatusCode)code;
            _headers = BuildHeaders(regular);
            FinalResponse.TrySetResult();
            _finalResponseCancellation.Cancel();
            _streamingResponse?.Begin(_statusCode.Value, _headers);
        }
        else
        {
            if (status is not null)
            {
                throw new TlsHttpProtocolException("HTTP/2 trailers contained :status.");
            }
            _trailers = BuildHeaders(regular);
            return true;
        }
        return false;
    }

    public async ValueTask AppendBodyAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        if (_headers is null)
        {
            throw new TlsHttpProtocolException("HTTP/2 DATA arrived before response headers.");
        }
        var bodyLength = checked(_bodyLength + data.Length);
        if (bodyLength > _maximumBodyBytes)
        {
            throw new TlsHttpProtocolException(
                "The HTTP/2 response body exceeds the configured limit.");
        }
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _responseCancellation.Token);
        if (_streamingResponse is null)
        {
            await _body.WriteAsync(data, linkedCancellation.Token).ConfigureAwait(false);
        }
        else
        {
            await _streamingResponse.WriteAsync(data, linkedCancellation.Token)
                .ConfigureAwait(false);
        }
        _bodyLength = bodyLength;
    }

    public void EnqueueBody(ReadOnlyMemory<byte> data, int flowControlledLength, bool endStream)
    {
        if (Volatile.Read(ref _endReceived) != 0)
        {
            throw new TlsHttpProtocolException("HTTP/2 DATA arrived after END_STREAM.");
        }
        if (_headers is null)
        {
            throw new TlsHttpProtocolException("HTTP/2 DATA arrived before response headers.");
        }
        var receivedLength = checked(_receivedBodyLength + data.Length);
        if (receivedLength > _maximumBodyBytes)
        {
            throw new TlsHttpProtocolException(
                "The HTTP/2 response body exceeds the configured limit.");
        }
        _receivedBodyLength = receivedLength;
        if (endStream)
        {
            Interlocked.Exchange(ref _endReceived, 1);
        }
        if (!_incoming.Writer.TryWrite(new QueuedHttp2Data(
                data,
                flowControlledLength,
                endStream)))
        {
            throw new IOException("The HTTP/2 response body queue was closed.");
        }
    }

    public void EnqueueEnd()
    {
        if (Interlocked.Exchange(ref _endReceived, 1) != 0)
        {
            throw new TlsHttpProtocolException("HTTP/2 END_STREAM was received twice.");
        }
        if (!_incoming.Writer.TryWrite(new QueuedHttp2Data(
                ReadOnlyMemory<byte>.Empty,
                0,
                true)))
        {
            throw new IOException("The HTTP/2 response body queue was closed.");
        }
    }

    public async ValueTask CompleteAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _completed, 1) != 0)
        {
            return;
        }
        if (_headers is null || _statusCode is null)
        {
            TryFail(new TlsHttpProtocolException(
                "The HTTP/2 stream ended before final response headers."));
            return;
        }
        try
        {
            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _responseCancellation.Token);
            if (_streamingResponse is not null)
            {
                await _streamingResponse.CompleteAsync(linkedCancellation.Token)
                    .ConfigureAwait(false);
            }
            var hasBody = RequestMethod != "HEAD" &&
                (int)_statusCode is not (>= 100 and < 200) and not 204 and not 304;
            var body = hasBody && _streamingResponse is null
                ? _body.ToArray()
                : [];
            ValidateContentLength(hasBody ? _bodyLength : 0);
            Completion.TrySetResult(new ParsedHttpResponse(
                HttpVersion.Version20,
                _statusCode.Value,
                string.Empty,
                _headers,
                _trailers ?? new TlsHeaders(),
                body,
                true,
                _headerBytes));
            SignalStateChange();
        }
        catch (Exception exception)
        {
            TryFail(exception);
            throw;
        }
    }

    public void TryFail(Exception exception)
    {
        Interlocked.Exchange(ref _completed, 1);
        _incoming.Writer.TryComplete(exception);
        _streamingResponse?.Abort(exception);
        _responseCancellation.Cancel();
        _finalResponseCancellation.Cancel();
        Completion.TrySetException(exception);
        SignalStateChange();
    }

    public void Dispose()
    {
        _incoming.Writer.TryComplete();
        _responseCancellation.Dispose();
        _finalResponseCancellation.Dispose();
        _body.Dispose();
    }

    private async Task PumpBodyAsync()
    {
        try
        {
            await foreach (var item in _incoming.Reader.ReadAllAsync(
                _responseCancellation.Token).ConfigureAwait(false))
            {
                await AppendBodyAsync(item.Data, _responseCancellation.Token)
                    .ConfigureAwait(false);
                await _restoreReceiveWindow(
                    this,
                    item.FlowControlledLength,
                    item.EndStream,
                    _responseCancellation.Token).ConfigureAwait(false);
                if (item.EndStream)
                {
                    await CompleteAsync(_responseCancellation.Token).ConfigureAwait(false);
                    _incoming.Writer.TryComplete();
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (_responseCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            TryFail(exception);
        }
    }

    private TlsHeaders BuildHeaders(List<HpackHeader> fields)
    {
        if (fields.Count > _maximumHeaderCount)
        {
            throw new TlsHttpProtocolException("Too many HTTP/2 response headers were received.");
        }
        var headers = new TlsHeaders();
        foreach (var field in fields)
        {
            _headerBytes = checked(_headerBytes + field.Name.Length + field.Value.Length + 2);
            if (_headerBytes > _maximumHeaderBytes)
            {
                throw new TlsHttpProtocolException(
                    "The HTTP/2 response headers exceeded the configured limit.");
            }
            headers.Add(field.Name, field.Value);
        }
        return headers;
    }

    private void ValidateContentLength(long bodyLength)
    {
        if (_headers is null || !_headers.TryGetValues("Content-Length", out var values))
        {
            return;
        }
        if (values.Count != 1 || !long.TryParse(
                values[0],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var declared) || declared < 0 ||
            RequestMethod != "HEAD" && declared != bodyLength)
        {
            throw new TlsHttpProtocolException("The HTTP/2 Content-Length is invalid.");
        }
    }

    private void SignalStateChange()
    {
        if (Interlocked.Exchange(ref _stateChangeSignaled, 1) == 0)
        {
            _signalStateChange();
        }
    }
}

internal sealed class Http2ResponseCompletedException : Exception;

internal readonly record struct QueuedHttp2Data(
    ReadOnlyMemory<byte> Data,
    int FlowControlledLength,
    bool EndStream);

internal readonly record struct Http2Frame(
    Http2FrameType Type,
    byte Flags,
    int StreamId,
    byte[] Payload);

internal readonly record struct Http2FrameHeader(
    int Length,
    Http2FrameType Type,
    byte Flags,
    int StreamId);

internal static class Http2FrameParser
{
    public static Http2FrameHeader ParseHeader(
        ReadOnlySpan<byte> header,
        int maximumFrameSize)
    {
        if (header.Length != 9)
        {
            throw new TlsHttpProtocolException("An HTTP/2 frame header must be exactly 9 bytes.");
        }
        if (maximumFrameSize is < 16_384 or > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFrameSize));
        }

        var length = header[0] << 16 | header[1] << 8 | header[2];
        if (length > maximumFrameSize)
        {
            throw new TlsHttpProtocolException("An HTTP/2 frame exceeded SETTINGS_MAX_FRAME_SIZE.");
        }
        var streamId = BinaryPrimitives.ReadInt32BigEndian(header[5..]) & 0x7fff_ffff;
        return new Http2FrameHeader(
            length,
            (Http2FrameType)header[3],
            header[4],
            streamId);
    }
}

internal enum Http2FrameType : byte
{
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    PriorityUpdate = 0x10,
}

internal static class Http2FrameFlags
{
    public const byte EndStream = 0x1;
    public const byte Ack = 0x1;
    public const byte EndHeaders = 0x4;
    public const byte Padded = 0x8;
    public const byte Priority = 0x20;
}

internal enum Http2ErrorCode : uint
{
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}
