using System.Buffers;
using System.Globalization;
using System.Text;

namespace TlsClient;

internal sealed class Http11Connection : IHttpConnection
{
    private readonly SharpTlsTransport _transport;
    private readonly BufferedHttpReader _reader;
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private int _disposed;

    public Http11Connection(SharpTlsTransport transport)
    {
        _transport = transport;
        _reader = new BufferedHttpReader(transport.Stream);
        LastUsed = DateTimeOffset.UtcNow;
        IsReusable = true;
    }

    public TlsConnectionInfo TlsInfo => _transport.TlsInfo;

    public DateTimeOffset LastUsed { get; private set; }

    public bool HasCompletedRequest { get; private set; }

    public bool IsReusable { get; private set; }

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public bool HasActiveRequests => false;

    public int MaximumConcurrentRequests => 1;

    public async ValueTask<ParsedHttpResponse> SendAsync(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        string? cookieHeader,
        StreamingResponseContext? streamingResponse,
        TlsSessionConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        var serializedHeaders = Http11RequestWriter.SerializeHeaders(
            request,
            sessionHeaders,
            configuration.HeaderOrder,
            cookieHeader);
        if (serializedHeaders.Length > configuration.MaximumRequestHeaderBytes)
        {
            throw new HttpRequestException(
                "The serialized request headers exceed the configured session limit.");
        }

        await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if (!IsReusable)
            {
                throw new StaleHttpConnectionException(
                    "The HTTP connection became unavailable before the request was written.");
            }

            await _transport.Stream.WriteAsync(serializedHeaders, cancellationToken)
                .ConfigureAwait(false);
            ParsedHttpResponse response;
            var expectContinue = request.HasContent && Http11RequestWriter.Has100Continue(
                request,
                sessionHeaders,
                cookieHeader);
            if (expectContinue)
            {
                await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                var gate = new ExpectContinueGate();
                var responseTask = Http11ResponseReader.ReadExpectContinueAsync(
                    _reader,
                    request.Method,
                    configuration.MaximumResponseHeaderBytes,
                    configuration.MaximumResponseHeaderCount,
                    configuration.MaximumResponseBodyBytes,
                    streamingResponse,
                    gate,
                    cancellationToken).AsTask();
                if (await ShouldSendExpectedBodyAsync(
                        gate,
                        responseTask,
                        configuration.Expect100ContinueTimeout,
                        cancellationToken).ConfigureAwait(false))
                {
                    await WriteRequestBodyAsync(
                        request,
                        configuration.MaximumRequestBodyBytes,
                        configuration.MaximumRequestHeaderBytes,
                        cancellationToken).ConfigureAwait(false);
                    await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                response = await responseTask.ConfigureAwait(false);
            }
            else
            {
                await WriteRequestBodyAsync(
                    request,
                    configuration.MaximumRequestBodyBytes,
                    configuration.MaximumRequestHeaderBytes,
                    cancellationToken).ConfigureAwait(false);
                await _transport.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                response = streamingResponse is null
                    ? await Http11ResponseReader.ReadAsync(
                        _reader,
                        request.Method,
                        configuration.MaximumResponseHeaderBytes,
                        configuration.MaximumResponseHeaderCount,
                        configuration.MaximumResponseBodyBytes,
                        cancellationToken).ConfigureAwait(false)
                    : await Http11ResponseReader.ReadStreamingAsync(
                        _reader,
                        request.Method,
                        configuration.MaximumResponseHeaderBytes,
                        configuration.MaximumResponseHeaderCount,
                        configuration.MaximumResponseBodyBytes,
                        streamingResponse,
                        cancellationToken).ConfigureAwait(false);
            }
            HasCompletedRequest = true;
            IsReusable = response.Reusable;
            LastUsed = DateTimeOffset.UtcNow;
            return response;
        }
        catch (Exception exception)
        {
            IsReusable = false;
            streamingResponse?.Abort(exception);
            throw;
        }
        finally
        {
            _sendGate.Release();
        }
    }

    private async ValueTask WriteRequestBodyAsync(
        BufferedRequest request,
        int maximumBodyBytes,
        int maximumTrailerBytes,
        CancellationToken cancellationToken)
    {
        if (request.IsStreaming)
        {
            await WriteStreamingRequestBodyAsync(
                request,
                maximumBodyBytes,
                maximumTrailerBytes,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        if (request.HasTrailers)
        {
            if (request.Body.Length != 0)
            {
                var chunkHeader = Encoding.ASCII.GetBytes(
                    request.Body.Length.ToString("x", CultureInfo.InvariantCulture) + "\r\n");
                await _transport.Stream.WriteAsync(chunkHeader, cancellationToken)
                    .ConfigureAwait(false);
                await _transport.Stream.WriteAsync(request.Body, cancellationToken)
                    .ConfigureAwait(false);
                await _transport.Stream.WriteAsync("\r\n"u8.ToArray(), cancellationToken)
                    .ConfigureAwait(false);
            }
            await WriteChunkTerminatorAsync(request, maximumTrailerBytes, cancellationToken)
                .ConfigureAwait(false);
        }
        else if (request.Body.Length != 0)
        {
            await _transport.Stream.WriteAsync(request.Body, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask WriteStreamingRequestBodyAsync(
        BufferedRequest request,
        int maximumBodyBytes,
        int maximumTrailerBytes,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength == 0 && !request.HasTrailers)
        {
            return;
        }
        var source = await request.OpenStreamingContentAsync(cancellationToken)
            .ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(request.StreamingBufferSize);
        long total = 0;
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(
                    buffer.AsMemory(0, request.StreamingBufferSize),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total = checked(total + read);
                if (total > maximumBodyBytes ||
                    request.ContentLength is { } declaredLength && total > declaredLength)
                {
                    throw new HttpRequestException(
                        "The streaming request body exceeds its declared or configured limit.");
                }

                if (request.ContentLength is null || request.HasTrailers)
                {
                    var chunkHeader = Encoding.ASCII.GetBytes(
                        read.ToString("x", CultureInfo.InvariantCulture) + "\r\n");
                    await _transport.Stream.WriteAsync(chunkHeader, cancellationToken)
                        .ConfigureAwait(false);
                }
                await _transport.Stream.WriteAsync(
                    buffer.AsMemory(0, read),
                    cancellationToken).ConfigureAwait(false);
                if (request.ContentLength is null || request.HasTrailers)
                {
                    await _transport.Stream.WriteAsync("\r\n"u8.ToArray(), cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            if (request.ContentLength is { } expectedLength && total != expectedLength)
            {
                throw new HttpRequestException(
                    $"The streaming request body produced {total} bytes instead of " +
                    $"the declared {expectedLength} bytes.");
            }
            if (request.ContentLength is null || request.HasTrailers)
            {
                await WriteChunkTerminatorAsync(
                    request,
                    maximumTrailerBytes,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async ValueTask WriteChunkTerminatorAsync(
        BufferedRequest request,
        int maximumTrailerBytes,
        CancellationToken cancellationToken)
    {
        var trailers = request.HasTrailers
            ? Http11RequestWriter.SerializeTrailers(request)
            : "0\r\n\r\n"u8.ToArray();
        if (trailers.Length > maximumTrailerBytes)
        {
            throw new HttpRequestException(
                "The serialized request trailers exceed the configured header limit.");
        }
        await _transport.Stream.WriteAsync(trailers, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<bool> ShouldSendExpectedBodyAsync(
        ExpectContinueGate gate,
        Task<ParsedHttpResponse> responseTask,
        TimeSpan expectTimeout,
        CancellationToken cancellationToken)
    {
        if (expectTimeout == TimeSpan.Zero)
        {
            return true;
        }
        var delay = Task.Delay(expectTimeout, cancellationToken);
        var completed = await Task.WhenAny(
            gate.Continue.Task,
            gate.FinalResponse.Task,
            responseTask,
            delay).ConfigureAwait(false);
        if (completed == gate.Continue.Task)
        {
            return true;
        }
        if (completed == gate.FinalResponse.Task)
        {
            return false;
        }
        if (completed == responseTask)
        {
            _ = await responseTask.ConfigureAwait(false);
            return false;
        }
        await delay.ConfigureAwait(false);
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _sendGate.WaitAsync().ConfigureAwait(false);
        try
        {
            IsReusable = false;
            await _transport.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _sendGate.Release();
            _sendGate.Dispose();
        }
    }
}

internal sealed class StaleHttpConnectionException : IOException
{
    public StaleHttpConnectionException(string message) : base(message)
    {
    }
}
