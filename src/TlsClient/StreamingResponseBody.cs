using System.Buffers;
using System.IO.Compression;
using System.Net;
using System.Threading.Channels;

namespace TlsClient;

internal sealed class StreamingResponseContext : IDisposable
{
    private readonly Stream _destination;
    private readonly TlsStreamingConfiguration _configuration;
    private readonly int _maximumBytes;
    private readonly Func<HttpStatusCode, TlsHeaders, bool>? _discardBody;
    private StreamingResponseBody? _body;
    private long _bytesWritten;

    public StreamingResponseContext(
        Stream destination,
        TlsStreamingConfiguration configuration,
        int maximumBytes,
        Func<HttpStatusCode, TlsHeaders, bool>? discardBody = null)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("The response destination must be writable.", nameof(destination));
        }
        _destination = destination;
        _configuration = configuration;
        _maximumBytes = maximumBytes;
        _discardBody = discardBody;
    }

    public int BufferSize => _configuration.BufferSize;

    public long BytesWritten => Interlocked.Read(ref _bytesWritten);

    public bool WasDecompressed { get; private set; }

    public void Begin(HttpStatusCode statusCode, TlsHeaders headers)
    {
        if (_body is not null)
        {
            throw new InvalidOperationException("The streaming response body was initialized twice.");
        }
        var discard = _discardBody?.Invoke(statusCode, headers) == true;
        _body = new StreamingResponseBody(
            discard ? Stream.Null : _destination,
            headers,
            discard ? _configuration with { AutomaticDecompression = false } : _configuration,
            _maximumBytes,
            discard ? static _ => { }
        : AddBytesWritten);
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        (_body ?? throw new InvalidOperationException("Response headers were not received."))
            .WriteAsync(data, cancellationToken);

    public async ValueTask CompleteAsync(CancellationToken cancellationToken)
    {
        var body = _body ?? throw new InvalidOperationException(
            "Response headers were not received.");
        await body.CompleteAsync(cancellationToken).ConfigureAwait(false);
        WasDecompressed = body.WasDecompressed;
    }

    public void Abort(Exception exception) => _body?.Abort(exception);

    public void Dispose() => _body?.Dispose();

    private void AddBytesWritten(int count) => Interlocked.Add(ref _bytesWritten, count);
}

internal sealed class StreamingResponseBody : IDisposable
{
    private readonly Stream _destination;
    private readonly int _bufferSize;
    private readonly int _maximumBytes;
    private readonly Action<int> _reportWrite;
    private readonly string[] _encodings;
    private readonly CancellationTokenSource _lifetime = new();
    private ProducerConsumerReadStream? _producer;
    private Task? _pump;
    private long _encodedBytes;
    private long _decodedBytes;
    private int _completed;
    private int _disposed;

    public StreamingResponseBody(
        Stream destination,
        TlsHeaders headers,
        TlsStreamingConfiguration configuration,
        int maximumBytes,
        Action<int> reportWrite)
    {
        _destination = destination;
        _bufferSize = configuration.BufferSize;
        _maximumBytes = maximumBytes;
        _reportWrite = reportWrite;
        _encodings = configuration.AutomaticDecompression
            ? GetSupportedEncodings(headers)
            : [];
    }

    public bool WasDecompressed => _encodings.Length != 0 && _decodedBytes != 0;

    public async ValueTask WriteAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _completed) != 0, this);
        var encoded = checked(_encodedBytes + data.Length);
        if (encoded > _maximumBytes)
        {
            throw new TlsHttpProtocolException(
                "The encoded streaming response exceeded the configured limit.");
        }
        _encodedBytes = encoded;
        if (data.IsEmpty)
        {
            return;
        }

        if (_encodings.Length == 0)
        {
            await WriteDecodedAsync(data, cancellationToken).ConfigureAwait(false);
            return;
        }

        EnsurePumpStarted();
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _lifetime.Token);
        await _producer!.WriteAsync(data, linkedCancellation.Token).ConfigureAwait(false);
    }

    public async ValueTask CompleteAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _completed, 1) != 0)
        {
            return;
        }
        if (_pump is null)
        {
            Dispose();
            return;
        }
        _producer!.Complete();
        try
        {
            await _pump.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await _lifetime.CancelAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            Dispose();
        }
    }

    public void Abort(Exception exception)
    {
        if (Interlocked.Exchange(ref _completed, 1) != 0)
        {
            return;
        }
        _producer?.Complete(exception);
        _lifetime.Cancel();
        Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        if (Interlocked.Exchange(ref _completed, 1) == 0)
        {
            _producer?.Complete(new ObjectDisposedException(nameof(StreamingResponseBody)));
            _lifetime.Cancel();
        }
        _producer?.Dispose();
        _lifetime.Dispose();
    }

    private void EnsurePumpStarted()
    {
        if (_pump is not null)
        {
            return;
        }
        _producer = new ProducerConsumerReadStream();
        _pump = PumpDecodedAndSignalAsync(_producer, _lifetime.Token);
    }

    private async Task PumpDecodedAndSignalAsync(
        Stream encoded,
        CancellationToken cancellationToken)
    {
        try
        {
            await PumpDecodedAsync(encoded, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await _lifetime.CancelAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task PumpDecodedAsync(Stream encoded, CancellationToken cancellationToken)
    {
        Stream decoded = encoded;
        try
        {
            for (var index = _encodings.Length - 1; index >= 0; index--)
            {
                decoded = _encodings[index] switch
                {
                    "gzip" => new GZipStream(decoded, CompressionMode.Decompress),
                    "deflate" => new ZLibStream(decoded, CompressionMode.Decompress),
                    "br" => new BrotliStream(decoded, CompressionMode.Decompress),
                    _ => throw new InvalidOperationException("Unsupported content encoding."),
                };
            }

            var buffer = ArrayPool<byte>.Shared.Rent(_bufferSize);
            try
            {
                while (true)
                {
                    var read = await decoded.ReadAsync(
                        buffer.AsMemory(0, _bufferSize),
                        cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        return;
                    }
                    await WriteDecodedAsync(
                        buffer.AsMemory(0, read),
                        cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        finally
        {
            await decoded.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask WriteDecodedAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken)
    {
        var decoded = checked(_decodedBytes + data.Length);
        if (decoded > _maximumBytes)
        {
            throw new TlsHttpProtocolException(
                "The decoded streaming response exceeded the configured limit.");
        }
        await _destination.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        _decodedBytes = decoded;
        _reportWrite(data.Length);
    }

    private static string[] GetSupportedEncodings(TlsHeaders headers)
    {
        if (!headers.TryGetValues("Content-Encoding", out var values))
        {
            return [];
        }
        var encodings = values
            .SelectMany(value => value.Split(','))
            .Select(value => value.Trim().ToLowerInvariant())
            .Where(value => value is not "" and not "identity")
            .ToArray();
        return encodings.Any(value => value is not "gzip" and not "deflate" and not "br")
            ? []
            : encodings;
    }
}

internal sealed class ProducerConsumerReadStream : Stream
{
    private readonly Channel<byte[]> _channel = Channel.CreateBounded<byte[]>(
        new BoundedChannelOptions(4)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true,
        });
    private byte[]? _current;
    private int _offset;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default) =>
        _channel.Writer.WriteAsync(data.ToArray(), cancellationToken);

    public void Complete(Exception? exception = null) => _channel.Writer.TryComplete(exception);

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        while (_current is null || _offset == _current.Length)
        {
            if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
            if (!_channel.Reader.TryRead(out _current))
            {
                continue;
            }
            _offset = 0;
        }
        var length = Math.Min(buffer.Length, _current.Length - _offset);
        _current.AsMemory(_offset, length).CopyTo(buffer);
        _offset += length;
        return length;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();
}
