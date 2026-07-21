using System.IO.Compression;

namespace TlsClient;

internal static class ResponseDecompressor
{
    public static async ValueTask<(byte[] Body, bool WasDecompressed)> DecodeAsync(
        byte[] body,
        TlsHeaders headers,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (body.Length == 0 || !headers.TryGetValues("Content-Encoding", out var values))
        {
            return (body, false);
        }

        var encodings = values
            .SelectMany(value => value.Split(','))
            .Select(value => value.Trim().ToLowerInvariant())
            .Where(value => value is not "" and not "identity")
            .ToArray();
        if (encodings.Any(encoding => encoding is not "gzip" and not "deflate" and not "br"))
        {
            return (body, false);
        }

        var decoded = body;
        for (var index = encodings.Length - 1; index >= 0; index--)
        {
            decoded = await DecodeOneAsync(
                decoded,
                encodings[index],
                maximumBytes,
                cancellationToken).ConfigureAwait(false);
        }
        return (decoded, encodings.Length != 0);
    }

    private static async ValueTask<byte[]> DecodeOneAsync(
        byte[] source,
        string encoding,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (encoding == "deflate")
        {
            try
            {
                return await DecodeWithFactoryAsync(
                    source,
                    static stream => new ZLibStream(stream, CompressionMode.Decompress),
                    maximumBytes,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidDataException)
            {
                return await DecodeWithFactoryAsync(
                    source,
                    static stream => new DeflateStream(stream, CompressionMode.Decompress),
                    maximumBytes,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        return await DecodeWithFactoryAsync(
            source,
            encoding == "gzip"
                ? static stream => new GZipStream(stream, CompressionMode.Decompress)
                : static stream => new BrotliStream(stream, CompressionMode.Decompress),
            maximumBytes,
            cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]> DecodeWithFactoryAsync(
        byte[] source,
        Func<Stream, Stream> createDecoder,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var input = new MemoryStream(source, writable: false);
        await using var decoder = createDecoder(input);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await decoder.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }
            if (output.Length + read > maximumBytes)
            {
                throw new TlsHttpProtocolException(
                    "The decompressed response body exceeded the configured limit.");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }
}
