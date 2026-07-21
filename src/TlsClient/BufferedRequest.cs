using System.Net;
using System.Net.Http.Headers;

namespace TlsClient;

internal sealed record BufferedRequest(
    string Method,
    Uri Url,
    HeaderEntry[] Headers,
    byte[] Body,
    bool HasContent,
    TlsHttpVersionPolicy HttpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2,
    HttpContent? StreamingContent = null,
    int StreamingBufferSize = 64 * 1024)
{
    public HeaderEntry[] Trailers { get; init; } = [];

    public TlsRequestReplayPolicy ReplayPolicy { get; init; }

    public bool HasProxyOverride { get; init; }

    public TlsProxy? Proxy { get; init; }

    public bool? EnableRetries { get; init; }

    public bool SuppressSensitiveSessionHeaders { get; init; }

    public bool IsIdempotent => Method is "GET" or "HEAD" or "OPTIONS" or "TRACE" or "PUT" or "DELETE";

    public bool IsStreaming => StreamingContent is not null;

    public bool IsReplayable => StreamingContent is null;

    public bool HasTrailers => Trailers.Length != 0;

    public bool HasPayload => HasContent || HasTrailers;

    public long? ContentLength => !HasContent
        ? null
        : StreamingContent is null
            ? Body.LongLength
            : StreamingContent.Headers.ContentLength;

    public BufferedRequest Redirect(Uri url, string method, bool dropBody, bool originChanged)
    {
        if (!dropBody && StreamingContent is not null)
        {
            throw new HttpRequestException(
                "A redirect requires replaying a streaming request body. Buffer the content " +
                "or disable automatic redirects for this request.");
        }
        var headers = Headers
            .Where(entry => !originChanged ||
                !string.Equals(entry.Name, "Authorization", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(entry.Name, "Cookie", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(entry.Name, "Host", StringComparison.OrdinalIgnoreCase))
            .Where(entry => !dropBody || !IsContentHeader(entry.Name))
            .Select(entry => new HeaderEntry(entry.Name, (string[])entry.Values.Clone()))
            .ToArray();

        return this with
        {
            Method = method,
            Url = url,
            Headers = headers,
            Body = dropBody ? [] : Body,
            HasContent = dropBody ? false : HasContent,
            StreamingContent = dropBody ? null : StreamingContent,
            Trailers = dropBody ? [] : Trailers,
            SuppressSensitiveSessionHeaders = SuppressSensitiveSessionHeaders || originChanged,
        };
    }

    public static async ValueTask<BufferedRequest> CreateAsync(
        HttpRequestMessage request,
        int maximumBodyBytes,
        TlsHttpVersionPolicy sessionVersionPolicy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var requestConfiguration = TlsRequestOptions.Snapshot(request);
        var url = request.RequestUri ??
            throw new ArgumentException("The request must have a RequestUri.", nameof(request));
        if (!url.IsAbsoluteUri)
        {
            throw new ArgumentException("The request URI must be absolute.", nameof(request));
        }
        if (!string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException("TlsClient accepts only https:// request URLs.");
        }
        if (request.Version.Major is < 1 or > 2)
        {
            throw new NotSupportedException(
                "TlsClient currently supports HTTP/1.1 and HTTP/2 request versions.");
        }

        var versionPolicy = request.VersionPolicy ==
            global::System.Net.Http.HttpVersionPolicy.RequestVersionExact
            ? request.Version.Major >= 2
                ? TlsHttpVersionPolicy.Http2Only
                : TlsHttpVersionPolicy.Http11Only
            : sessionVersionPolicy;

        var method = request.Method.Method;
        Http11RequestWriter.ValidateMethod(method);

        var entries = new List<HeaderEntry>();
        AddOrReplace(entries, request.Headers.NonValidated);

        byte[] body = [];
        var hasContent = request.Content is not null;
        if (request.Content is not null)
        {
            AddOrReplace(entries, request.Content.Headers.NonValidated);
            body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (body.Length > maximumBodyBytes)
            {
                throw new HttpRequestException(
                    $"The request body exceeds the {maximumBodyBytes}-byte session limit.");
            }
        }

        return new BufferedRequest(
            method,
            url,
            entries.ToArray(),
            body,
            hasContent,
            versionPolicy)
        {
            Trailers = requestConfiguration.Trailers,
            ReplayPolicy = requestConfiguration.ReplayPolicy,
            HasProxyOverride = requestConfiguration.HasProxyOverride,
            Proxy = requestConfiguration.Proxy,
            EnableRetries = requestConfiguration.EnableRetries,
        };
    }

    public static BufferedRequest CreateStreaming(
        HttpRequestMessage request,
        int maximumBodyBytes,
        int streamingBufferSize,
        TlsHttpVersionPolicy sessionVersionPolicy)
    {
        var requestConfiguration = TlsRequestOptions.Snapshot(request);
        var (method, url, entries, versionPolicy) = ReadMetadata(
            request,
            sessionVersionPolicy);
        var hasContent = request.Content is not null;
        if (request.Content is not null)
        {
            AddOrReplace(entries, request.Content.Headers.NonValidated);
            if (request.Content.Headers.ContentLength is { } declaredLength &&
                declaredLength > maximumBodyBytes)
            {
                throw new HttpRequestException(
                    $"The request body exceeds the {maximumBodyBytes}-byte session limit.");
            }
        }
        return new BufferedRequest(
            method,
            url,
            entries.ToArray(),
            [],
            hasContent,
            versionPolicy,
            request.Content,
            streamingBufferSize)
        {
            Trailers = requestConfiguration.Trailers,
            ReplayPolicy = requestConfiguration.ReplayPolicy,
            HasProxyOverride = requestConfiguration.HasProxyOverride,
            Proxy = requestConfiguration.Proxy,
            EnableRetries = requestConfiguration.EnableRetries,
        };
    }

    public Task<Stream> OpenStreamingContentAsync(CancellationToken cancellationToken) =>
        StreamingContent is null
            ? throw new InvalidOperationException("The request has no streaming content.")
            : StreamingContent.ReadAsStreamAsync(cancellationToken);

    private static (string Method, Uri Url, List<HeaderEntry> Entries,
        TlsHttpVersionPolicy VersionPolicy) ReadMetadata(
        HttpRequestMessage request,
        TlsHttpVersionPolicy sessionVersionPolicy)
    {
        ArgumentNullException.ThrowIfNull(request);
        var url = request.RequestUri ??
            throw new ArgumentException("The request must have a RequestUri.", nameof(request));
        if (!url.IsAbsoluteUri)
        {
            throw new ArgumentException("The request URI must be absolute.", nameof(request));
        }
        if (!string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException("TlsClient accepts only https:// request URLs.");
        }
        if (request.Version.Major is < 1 or > 2)
        {
            throw new NotSupportedException(
                "TlsClient currently supports HTTP/1.1 and HTTP/2 request versions.");
        }

        var versionPolicy = request.VersionPolicy ==
            global::System.Net.Http.HttpVersionPolicy.RequestVersionExact
            ? request.Version.Major >= 2
                ? TlsHttpVersionPolicy.Http2Only
                : TlsHttpVersionPolicy.Http11Only
            : sessionVersionPolicy;
        var method = request.Method.Method;
        Http11RequestWriter.ValidateMethod(method);
        var entries = new List<HeaderEntry>();
        AddOrReplace(entries, request.Headers.NonValidated);
        return (method, url, entries, versionPolicy);
    }

    internal static void AddOrReplace(List<HeaderEntry> destination, HeaderEntry incoming)
    {
        var index = destination.FindIndex(entry =>
            string.Equals(entry.Name, incoming.Name, StringComparison.OrdinalIgnoreCase));
        var copy = new HeaderEntry(incoming.Name, (string[])incoming.Values.Clone());
        if (index < 0)
        {
            destination.Add(copy);
        }
        else
        {
            destination[index] = copy;
        }
    }

    private static void AddOrReplace(
        List<HeaderEntry> destination,
        HttpHeadersNonValidated headers)
    {
        foreach (var header in headers)
        {
            AddOrReplace(
                destination,
                new HeaderEntry(header.Key, header.Value.ToArray()));
        }
    }

    private static bool IsContentHeader(string name) => name.StartsWith(
        "Content-",
        StringComparison.OrdinalIgnoreCase);
}
