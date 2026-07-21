namespace TlsClient;

/// <summary>Controls behavior that belongs to one <see cref="HttpRequestMessage"/>.</summary>
public sealed class TlsRequestOptions
{
    private static readonly HttpRequestOptionsKey<TlsRequestOptions> OptionsKey =
        new("TlsClient.RequestOptions");
    private TlsRequestReplayPolicy _replayPolicy;
    private TlsProxy? _proxy;
    private bool _hasProxyOverride;

    /// <summary>Gets request trailer fields sent after the content body.</summary>
    public TlsHeaders Trailers { get; } = new();

    /// <summary>
    /// Gets or sets how a streamed request body may be made replayable. The default never
    /// buffers a streaming source.
    /// </summary>
    public TlsRequestReplayPolicy ReplayPolicy
    {
        get => _replayPolicy;
        set
        {
            if (!Enum.IsDefined(value))
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            _replayPolicy = value;
        }
    }

    /// <summary>
    /// Gets or sets the proxy for this request. Leaving the property untouched inherits the
    /// session proxy; assigning null explicitly selects a direct connection.
    /// </summary>
    public TlsProxy? Proxy
    {
        get => _proxy;
        set
        {
            _proxy = value;
            _hasProxyOverride = true;
        }
    }

    /// <summary>
    /// Gets or sets whether retries are enabled for this request. Null inherits session policy.
    /// </summary>
    public bool? EnableRetries { get; set; }

    /// <summary>Restores inheritance of the session-wide proxy.</summary>
    public void UseSessionProxy()
    {
        _proxy = null;
        _hasProxyOverride = false;
    }

    /// <summary>Gets or creates the TlsClient options attached to a request.</summary>
    public static TlsRequestOptions For(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Options.TryGetValue(OptionsKey, out var options))
        {
            return options;
        }
        options = new TlsRequestOptions();
        request.Options.Set(OptionsKey, options);
        return options;
    }

    internal static TlsRequestConfiguration Snapshot(HttpRequestMessage request)
    {
        if (!request.Options.TryGetValue(OptionsKey, out var options))
        {
            return new TlsRequestConfiguration(
                [],
                TlsRequestReplayPolicy.Never,
                false,
                null,
                null);
        }
        var trailers = options.Trailers.Snapshot();
        foreach (var trailer in trailers)
        {
            ValidateTrailerName(trailer.Name);
        }
        return new TlsRequestConfiguration(
            trailers,
            options.ReplayPolicy,
            options._hasProxyOverride,
            options._proxy,
            options.EnableRetries);
    }

    internal static void ValidateTrailerName(string name)
    {
        if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("TE", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"The '{name}' field is not permitted in request trailers.",
                nameof(name));
        }
    }
}

/// <summary>Controls whether a streaming upload may be replayed.</summary>
public enum TlsRequestReplayPolicy
{
    /// <summary>Never buffers the source; resend-required redirects and retries fail.</summary>
    Never,

    /// <summary>Buffers the complete request body within the session request-body limit.</summary>
    Buffer,
}

internal sealed record TlsRequestConfiguration(
    HeaderEntry[] Trailers,
    TlsRequestReplayPolicy ReplayPolicy,
    bool HasProxyOverride,
    TlsProxy? Proxy,
    bool? EnableRetries);
