using System.Net;
using System.Text;
using System.Text.Json;

namespace TlsClient;

/// <summary>An HTTP response with TLS metadata.</summary>
public sealed class TlsResponse
{
    private string? _text;

    internal TlsResponse(
        Uri url,
        Version httpVersion,
        HttpStatusCode statusCode,
        string reasonPhrase,
        TlsHeaders headers,
        TlsHeaders trailers,
        byte[] body,
        bool wasDecompressed,
        bool bodyWasStreamed,
        TlsConnectionInfo tls,
        IReadOnlyList<TlsRedirect> history)
    {
        Url = url;
        HttpVersion = httpVersion;
        StatusCode = statusCode;
        ReasonPhrase = reasonPhrase;
        Headers = headers;
        Trailers = trailers;
        Body = body;
        WasDecompressed = wasDecompressed;
        BodyWasStreamed = bodyWasStreamed;
        Tls = tls;
        History = history;
    }

    /// <summary>Gets the final response URL.</summary>
    public Uri Url { get; }

    /// <summary>Gets the HTTP version.</summary>
    public Version HttpVersion { get; }

    /// <summary>Gets the numeric status code.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Gets the wire reason phrase.</summary>
    public string ReasonPhrase { get; }

    /// <summary>Gets response headers.</summary>
    public TlsHeaders Headers { get; }

    /// <summary>Gets chunked response trailers.</summary>
    public TlsHeaders Trailers { get; }

    /// <summary>Gets the buffered, optionally decompressed response bytes.</summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>Gets whether Content-Encoding was automatically decoded.</summary>
    public bool WasDecompressed { get; }

    /// <summary>
    /// Gets whether the response body was written to a caller-provided stream instead of
    /// being retained in <see cref="Body"/>.
    /// </summary>
    public bool BodyWasStreamed { get; }

    /// <summary>Gets secret-free metadata for the physical TLS connection.</summary>
    public TlsConnectionInfo Tls { get; }

    /// <summary>Gets followed redirect hops in chronological order.</summary>
    public IReadOnlyList<TlsRedirect> History { get; }

    /// <summary>Gets the response decoded using its declared charset or UTF-8.</summary>
    public string Text => BodyWasStreamed
        ? throw new InvalidOperationException(
            "The response body was streamed to the supplied destination and is not buffered.")
        : _text ??= ResolveEncoding().GetString(Body.Span);

    /// <summary>Deserializes the buffered response as JSON.</summary>
    public T? Json<T>(JsonSerializerOptions? options = null)
    {
        if (BodyWasStreamed)
        {
            throw new InvalidOperationException(
                "The response body was streamed to the supplied destination and is not buffered.");
        }
        return JsonSerializer.Deserialize<T>(Body.Span, options);
    }

    /// <summary>Throws when the status code is outside 200–299.</summary>
    public TlsResponse EnsureSuccessStatusCode()
    {
        if ((int)StatusCode is < 200 or > 299)
        {
            throw new TlsHttpException(
                $"The server returned HTTP {(int)StatusCode} {ReasonPhrase}.",
                StatusCode,
                Url);
        }

        return this;
    }

    private Encoding ResolveEncoding()
    {
        var contentType = Headers.GetFirstOrDefault("Content-Type");
        if (contentType is null)
        {
            return Encoding.UTF8;
        }

        foreach (var part in contentType.Split(';').Skip(1))
        {
            var separator = part.IndexOf('=');
            if (separator < 0 ||
                !string.Equals(part[..separator].Trim(), "charset", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var name = part[(separator + 1)..].Trim().Trim('"', '\'');
            try
            {
                return Encoding.GetEncoding(name);
            }
            catch (ArgumentException)
            {
                return Encoding.UTF8;
            }
        }

        return Encoding.UTF8;
    }
}

/// <summary>One redirect followed before the final response.</summary>
public sealed record TlsRedirect(Uri From, Uri To, HttpStatusCode StatusCode);

/// <summary>An HTTP error response surfaced by <see cref="TlsResponse.EnsureSuccessStatusCode"/>.</summary>
public sealed class TlsHttpException : HttpRequestException
{
    internal TlsHttpException(string message, HttpStatusCode statusCode, Uri url)
        : base(message, null, statusCode)
    {
        Url = url;
    }

    /// <summary>Gets the URL that returned the error response.</summary>
    public Uri Url { get; }
}

/// <summary>Signals invalid or unsupported HTTP wire data.</summary>
public sealed class TlsHttpProtocolException : IOException
{
    internal TlsHttpProtocolException(string message) : base(message)
    {
    }

    internal TlsHttpProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
