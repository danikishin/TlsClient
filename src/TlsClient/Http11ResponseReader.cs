using System.Globalization;
using System.Net;

namespace TlsClient;

internal static class Http11ResponseReader
{
    public static async ValueTask<ParsedHttpResponse> ReadAsync(
        BufferedHttpReader reader,
        string requestMethod,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        int maximumBodyBytes,
        CancellationToken cancellationToken) => await ReadCoreAsync(
            reader,
            requestMethod,
            maximumHeaderBytes,
            maximumHeaderCount,
            maximumBodyBytes,
            null,
            null,
            cancellationToken).ConfigureAwait(false);

    public static async ValueTask<ParsedHttpResponse> ReadStreamingAsync(
        BufferedHttpReader reader,
        string requestMethod,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        int maximumBodyBytes,
        StreamingResponseContext streaming,
        CancellationToken cancellationToken) => await ReadCoreAsync(
            reader,
            requestMethod,
            maximumHeaderBytes,
            maximumHeaderCount,
            maximumBodyBytes,
            streaming,
            null,
            cancellationToken).ConfigureAwait(false);

    public static async ValueTask<ParsedHttpResponse> ReadExpectContinueAsync(
        BufferedHttpReader reader,
        string requestMethod,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        int maximumBodyBytes,
        StreamingResponseContext? streaming,
        ExpectContinueGate gate,
        CancellationToken cancellationToken) => await ReadCoreAsync(
            reader,
            requestMethod,
            maximumHeaderBytes,
            maximumHeaderCount,
            maximumBodyBytes,
            streaming,
            gate,
            cancellationToken).ConfigureAwait(false);

    private static async ValueTask<ParsedHttpResponse> ReadCoreAsync(
        BufferedHttpReader reader,
        string requestMethod,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        int maximumBodyBytes,
        StreamingResponseContext? streaming,
        ExpectContinueGate? expectContinue,
        CancellationToken cancellationToken)
    {
        for (var informationalCount = 0; informationalCount <= 8; informationalCount++)
        {
            var statusLine = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
                .ConfigureAwait(false) ?? throw new EndOfStreamException(
                    "The connection closed before an HTTP status line was received.");
            var (version, statusCode, reasonPhrase) = ParseStatusLine(statusLine.Text);
            var (headers, headerBytes) = await ReadHeadersAsync(
                reader,
                maximumHeaderBytes - statusLine.WireLength,
                maximumHeaderCount,
                cancellationToken).ConfigureAwait(false);

            if (statusCode is >= 100 and < 200 && statusCode != 101)
            {
                if (statusCode == 100)
                {
                    expectContinue?.Continue.TrySetResult();
                }
                continue;
            }
            if (statusCode == 101)
            {
                throw new TlsHttpProtocolException("HTTP protocol upgrades are not supported.");
            }

            expectContinue?.FinalResponse.TrySetResult();

            var noBody = string.Equals(requestMethod, "HEAD", StringComparison.Ordinal) ||
                statusCode is >= 100 and < 200 or 204 or 304;
            var trailers = new TlsHeaders();
            byte[] body;
            var reusable = IsPersistent(version, headers);

            if (streaming is not null)
            {
                streaming.Begin((HttpStatusCode)statusCode, headers);
                body = [];
                if (!noBody)
                {
                    var transferEncodings = GetTokens(headers, "Transfer-Encoding");
                    if (transferEncodings.Count != 0)
                    {
                        if (transferEncodings.Count != 1 ||
                            !string.Equals(
                                transferEncodings[0],
                                "chunked",
                                StringComparison.OrdinalIgnoreCase))
                        {
                            throw new TlsHttpProtocolException(
                                "Only the chunked HTTP/1.1 transfer coding is supported.");
                        }
                        trailers = await CopyChunkedAsync(
                            reader,
                            streaming,
                            maximumHeaderBytes,
                            maximumHeaderCount,
                            maximumBodyBytes,
                            cancellationToken).ConfigureAwait(false);
                    }
                    else if (TryGetContentLength(headers, out var contentLength))
                    {
                        if (contentLength > maximumBodyBytes)
                        {
                            throw new TlsHttpProtocolException(
                                "The declared response body exceeds the configured limit.");
                        }
                        await CopyExactlyAsync(
                            reader,
                            streaming,
                            contentLength,
                            cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await CopyUntilCloseAsync(
                            reader,
                            streaming,
                            maximumBodyBytes,
                            cancellationToken).ConfigureAwait(false);
                        reusable = false;
                    }
                }
                await streaming.CompleteAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                if (noBody)
                {
                    body = [];
                }
                else
                {
                    var transferEncodings = GetTokens(headers, "Transfer-Encoding");
                    if (transferEncodings.Count != 0)
                    {
                        if (transferEncodings.Count != 1 ||
                            !string.Equals(
                                transferEncodings[0],
                                "chunked",
                                StringComparison.OrdinalIgnoreCase))
                        {
                            throw new TlsHttpProtocolException(
                                "Only the chunked HTTP/1.1 transfer coding is supported.");
                        }

                        (body, trailers) = await ReadChunkedAsync(
                            reader,
                            maximumHeaderBytes,
                            maximumHeaderCount,
                            maximumBodyBytes,
                            cancellationToken).ConfigureAwait(false);
                    }
                    else if (TryGetContentLength(headers, out var contentLength))
                    {
                        if (contentLength > maximumBodyBytes)
                        {
                            throw new TlsHttpProtocolException(
                                "The declared response body exceeds the configured limit.");
                        }
                        body = new byte[contentLength];
                        await reader.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        body = await ReadUntilCloseAsync(reader, maximumBodyBytes, cancellationToken)
                            .ConfigureAwait(false);
                        reusable = false;
                    }
                }
            }

            return new ParsedHttpResponse(
                version,
                (HttpStatusCode)statusCode,
                reasonPhrase,
                headers,
                trailers,
                body,
                reusable,
                headerBytes);
        }

        throw new TlsHttpProtocolException("Too many informational HTTP responses were received.");
    }

    internal static (Version Version, int StatusCode, string ReasonPhrase) ParseStatusLine(string line)
    {
        if (!line.StartsWith("HTTP/", StringComparison.Ordinal) || line.Length < 12)
        {
            throw new TlsHttpProtocolException("The HTTP status line is malformed.");
        }

        var firstSpace = line.IndexOf(' ');
        if (firstSpace < 0 ||
            !Version.TryParse(line.AsSpan(5, firstSpace - 5), out var version) ||
            version.Major != 1 || version.Minor is < 0 or > 1)
        {
            throw new TlsHttpProtocolException("The HTTP version is unsupported or malformed.");
        }

        var statusStart = firstSpace + 1;
        if (line.Length < statusStart + 3 ||
            !int.TryParse(
                line.AsSpan(statusStart, 3),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var statusCode) ||
            statusCode is < 100 or > 999 ||
            (line.Length > statusStart + 3 && line[statusStart + 3] != ' '))
        {
            throw new TlsHttpProtocolException("The HTTP status code is malformed.");
        }

        var reason = line.Length > statusStart + 4 ? line[(statusStart + 4)..] : string.Empty;
        if (reason.Any(character => character < '\u0020' && character != '\t' || character == '\u007f'))
        {
            throw new TlsHttpProtocolException("The HTTP reason phrase contains control characters.");
        }
        return (version, statusCode, reason);
    }

    private static async ValueTask<(TlsHeaders Headers, int WireBytes)> ReadHeadersAsync(
        BufferedHttpReader reader,
        int maximumBytes,
        int maximumCount,
        CancellationToken cancellationToken)
    {
        var headers = new TlsHeaders();
        var wireBytes = 0;
        var count = 0;
        while (true)
        {
            var line = await reader.ReadLineAsync(maximumBytes, cancellationToken)
                .ConfigureAwait(false) ?? throw new EndOfStreamException(
                    "The connection closed in the middle of HTTP headers.");
            wireBytes = checked(wireBytes + line.WireLength);
            if (wireBytes > maximumBytes)
            {
                throw new TlsHttpProtocolException("HTTP headers exceeded the configured limit.");
            }
            if (line.Text.Length == 0)
            {
                return (headers, wireBytes);
            }
            if (++count > maximumCount)
            {
                throw new TlsHttpProtocolException("Too many HTTP header fields were received.");
            }
            if (line.Text[0] is ' ' or '\t')
            {
                throw new TlsHttpProtocolException("Obsolete folded HTTP headers are rejected.");
            }

            var separator = line.Text.IndexOf(':');
            if (separator <= 0)
            {
                throw new TlsHttpProtocolException("An HTTP header field is malformed.");
            }
            var name = line.Text[..separator];
            var value = line.Text[(separator + 1)..].Trim(' ', '\t');
            if (value.Any(character => character < '\u0020' && character != '\t' || character == '\u007f'))
            {
                throw new TlsHttpProtocolException(
                    $"The response contains control characters in the '{name}' header.");
            }
            try
            {
                headers.Add(name, value);
            }
            catch (ArgumentException exception)
            {
                throw new TlsHttpProtocolException(
                    $"The response contains an invalid '{name}' header: {exception.Message}");
            }
        }
    }

    private static async ValueTask<(byte[] Body, TlsHeaders Trailers)> ReadChunkedAsync(
        BufferedHttpReader reader,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        int maximumBodyBytes,
        CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        while (true)
        {
            var line = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
                .ConfigureAwait(false) ?? throw new EndOfStreamException(
                    "The connection closed before a chunk size was received.");
            var extension = line.Text.IndexOf(';');
            var sizeText = (extension < 0 ? line.Text : line.Text[..extension]).Trim();
            if (!ulong.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var size) ||
                size > (ulong)(maximumBodyBytes - body.Length))
            {
                throw new TlsHttpProtocolException("A chunk size is invalid or exceeds the body limit.");
            }
            if (size == 0)
            {
                var (trailers, _) = await ReadHeadersAsync(
                    reader,
                    maximumHeaderBytes,
                    maximumHeaderCount,
                    cancellationToken).ConfigureAwait(false);
                return (body.ToArray(), trailers);
            }

            var chunk = new byte[(int)size];
            await reader.ReadExactlyAsync(chunk, cancellationToken).ConfigureAwait(false);
            await body.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
            var ending = await reader.ReadLineAsync(2, cancellationToken).ConfigureAwait(false);
            if (ending is null || ending.Text.Length != 0)
            {
                throw new TlsHttpProtocolException("Chunk data was not followed by CRLF.");
            }
        }
    }

    private static async ValueTask<TlsHeaders> CopyChunkedAsync(
        BufferedHttpReader reader,
        StreamingResponseContext streaming,
        int maximumHeaderBytes,
        int maximumHeaderCount,
        int maximumBodyBytes,
        CancellationToken cancellationToken)
    {
        long total = 0;
        var buffer = new byte[streaming.BufferSize];
        while (true)
        {
            var line = await reader.ReadLineAsync(maximumHeaderBytes, cancellationToken)
                .ConfigureAwait(false) ?? throw new EndOfStreamException(
                    "The connection closed before a chunk size was received.");
            var extension = line.Text.IndexOf(';');
            var sizeText = (extension < 0 ? line.Text : line.Text[..extension]).Trim();
            if (!ulong.TryParse(
                    sizeText,
                    NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture,
                    out var size) ||
                size > (ulong)(maximumBodyBytes - total))
            {
                throw new TlsHttpProtocolException(
                    "A chunk size is invalid or exceeds the body limit.");
            }
            if (size == 0)
            {
                var (trailers, _) = await ReadHeadersAsync(
                    reader,
                    maximumHeaderBytes,
                    maximumHeaderCount,
                    cancellationToken).ConfigureAwait(false);
                return trailers;
            }

            var remaining = checked((long)size);
            while (remaining != 0)
            {
                var length = (int)Math.Min(buffer.Length, remaining);
                await reader.ReadExactlyAsync(
                    buffer.AsMemory(0, length),
                    cancellationToken).ConfigureAwait(false);
                await streaming.WriteAsync(
                    buffer.AsMemory(0, length),
                    cancellationToken).ConfigureAwait(false);
                remaining -= length;
                total += length;
            }
            var ending = await reader.ReadLineAsync(2, cancellationToken).ConfigureAwait(false);
            if (ending is null || ending.Text.Length != 0)
            {
                throw new TlsHttpProtocolException("Chunk data was not followed by CRLF.");
            }
        }
    }

    private static async ValueTask CopyExactlyAsync(
        BufferedHttpReader reader,
        StreamingResponseContext streaming,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[streaming.BufferSize];
        var remaining = length;
        while (remaining != 0)
        {
            var count = Math.Min(buffer.Length, remaining);
            await reader.ReadExactlyAsync(
                buffer.AsMemory(0, count),
                cancellationToken).ConfigureAwait(false);
            await streaming.WriteAsync(
                buffer.AsMemory(0, count),
                cancellationToken).ConfigureAwait(false);
            remaining -= count;
        }
    }

    private static async ValueTask CopyUntilCloseAsync(
        BufferedHttpReader reader,
        StreamingResponseContext streaming,
        int maximumBodyBytes,
        CancellationToken cancellationToken)
    {
        long total = 0;
        var buffer = new byte[streaming.BufferSize];
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }
            total += read;
            if (total > maximumBodyBytes)
            {
                throw new TlsHttpProtocolException(
                    "The response body exceeded the configured limit.");
            }
            await streaming.WriteAsync(
                buffer.AsMemory(0, read),
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async ValueTask<byte[]> ReadUntilCloseAsync(
        BufferedHttpReader reader,
        int maximumBodyBytes,
        CancellationToken cancellationToken)
    {
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return body.ToArray();
            }
            if (body.Length + read > maximumBodyBytes)
            {
                throw new TlsHttpProtocolException("The response body exceeded the configured limit.");
            }
            await body.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool TryGetContentLength(TlsHeaders headers, out int contentLength)
    {
        contentLength = 0;
        if (!headers.TryGetValues("Content-Length", out var values))
        {
            return false;
        }

        long? parsed = null;
        foreach (var item in values.SelectMany(value => value.Split(',')))
        {
            if (!long.TryParse(item.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var current) ||
                current < 0 || current > int.MaxValue || parsed.HasValue && parsed.Value != current)
            {
                throw new TlsHttpProtocolException("Conflicting or invalid Content-Length headers were received.");
            }
            parsed = current;
        }

        if (!parsed.HasValue)
        {
            throw new TlsHttpProtocolException("An empty Content-Length header was received.");
        }
        contentLength = (int)parsed.Value;
        return true;
    }

    private static bool IsPersistent(Version version, TlsHeaders headers)
    {
        var connection = GetTokens(headers, "Connection");
        if (connection.Any(token => string.Equals(token, "close", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }
        return version >= HttpVersion.Version11 || connection.Any(
            token => string.Equals(token, "keep-alive", StringComparison.OrdinalIgnoreCase));
    }

    private static List<string> GetTokens(TlsHeaders headers, string name)
    {
        if (!headers.TryGetValues(name, out var values))
        {
            return [];
        }
        return values.SelectMany(value => value.Split(','))
            .Select(token => token.Trim())
            .Where(token => token.Length != 0)
            .ToList();
    }
}

internal sealed record ParsedHttpResponse(
    Version Version,
    HttpStatusCode StatusCode,
    string ReasonPhrase,
    TlsHeaders Headers,
    TlsHeaders Trailers,
    byte[] Body,
    bool Reusable,
    int HeaderBytes);
