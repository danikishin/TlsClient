using System.IO.Compression;
using System.Net;

namespace TlsClient.Tests;

public sealed class StreamingResponseBodyTests
{
    [Fact]
    public async Task DecodedBodyLimit_IsEnforcedBeforeOversizedWrite()
    {
        var decoded = Enumerable.Repeat((byte)'a', 10_000).ToArray();
        byte[] encoded;
        using (var output = new MemoryStream())
        {
            await using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, true))
            {
                await gzip.WriteAsync(decoded);
            }
            encoded = output.ToArray();
        }
        Assert.True(encoded.Length < 1024);
        var headers = new TlsHeaders();
        headers.Set("Content-Encoding", "gzip");
        await using var destination = new MemoryStream();
        using var context = new StreamingResponseContext(
            destination,
            new TlsStreamingConfiguration(4096, true),
            1024);
        context.Begin(HttpStatusCode.OK, headers);

        var exception = await Record.ExceptionAsync(async () =>
        {
            await context.WriteAsync(encoded, CancellationToken.None);
            await context.CompleteAsync(CancellationToken.None);
        });

        Assert.IsType<TlsHttpProtocolException>(exception);
        Assert.Empty(destination.ToArray());
    }

    [Fact]
    public async Task DestinationCancellation_InterruptsStreamingWrite()
    {
        await using var destination = new CancellationBlockingStream();
        using var context = new StreamingResponseContext(
            destination,
            new TlsStreamingConfiguration(4096, false),
            1024);
        context.Begin(HttpStatusCode.OK, new TlsHeaders());
        using var cancelled = new CancellationTokenSource();

        var write = context.WriteAsync("body"u8.ToArray(), cancelled.Token).AsTask();
        await destination.WriteStarted;
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => write);
    }

    [Fact]
    public async Task UnsupportedEncoding_IsDeliveredWithoutClaimingDecompression()
    {
        var headers = new TlsHeaders();
        headers.Set("Content-Encoding", "zstd");
        await using var destination = new MemoryStream();
        using var context = new StreamingResponseContext(
            destination,
            new TlsStreamingConfiguration(4096, true),
            1024);
        context.Begin(HttpStatusCode.OK, headers);

        await context.WriteAsync("wire"u8.ToArray(), CancellationToken.None);
        await context.CompleteAsync(CancellationToken.None);

        Assert.Equal("wire"u8.ToArray(), destination.ToArray());
        Assert.False(context.WasDecompressed);
    }

    private sealed class CancellationBlockingStream : Stream
    {
        private readonly TaskCompletionSource _writeStarted = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task WriteStarted => _writeStarted.Task;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            _writeStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }
}
