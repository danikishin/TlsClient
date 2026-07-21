using System.Net;
using SharpTls;

namespace TlsClient;

/// <summary>Configures a <see cref="TlsSession"/>. Values are snapshotted at construction.</summary>
public sealed class TlsSessionOptions
{
    /// <summary>Creates options with library defaults.</summary>
    public TlsSessionOptions()
    {
    }

    /// <summary>Creates options initialized from a coherent TLS and HTTP preset.</summary>
    /// <param name="preset">The preset to copy.</param>
    public TlsSessionOptions(TlsPreset preset)
    {
        ArgumentNullException.ThrowIfNull(preset);
        preset.ApplyTo(this);
    }

    /// <summary>Gets or sets the ClientHello profile. The default tracks SharpTls Chrome Auto.</summary>
    public TlsProfile Profile { get; set; } = TlsProfiles.Chrome;

    /// <summary>
    /// Gets or sets optional SharpTls RFC 9848 HTTPS/SVCB discovery. Resolution completes
    /// before the origin ClientHello and is supported only for direct, non-Roller routes.
    /// </summary>
    public TlsEchDnsResolver? EchDnsResolver { get; set; }

    /// <summary>
    /// Gets or sets an optional SharpTls origin-aware profile Roller. Roller mode owns direct
    /// connection establishment and therefore cannot be combined with proxies, custom DNS,
    /// connection telemetry, or an exact per-request HTTP version.
    /// </summary>
    public TlsProfileRoller? ProfileRoller { get; set; }

    /// <summary>Gets or sets the HTTP ALPN/transport policy.</summary>
    public TlsHttpVersionPolicy HttpVersionPolicy { get; set; } =
        TlsHttpVersionPolicy.PreferHttp2;

    /// <summary>Gets HTTP/2 settings and wire-order controls.</summary>
    public TlsHttp2Options Http2 { get; } = new();

    /// <summary>Gets explicit retry policy.</summary>
    public TlsRetryOptions Retry { get; } = new();

    /// <summary>
    /// Gets caller-owned request policies invoked around every physical attempt.
    /// Policies run in insertion order before an attempt and reverse order afterward.
    /// </summary>
    public IList<ITlsRequestPolicy> RequestPolicies { get; } =
        new List<ITlsRequestPolicy>();

    /// <summary>Gets or sets the end-to-end timeout for one request including redirects.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets how long a request with Expect: 100-continue waits before sending its body.
    /// </summary>
    public TimeSpan Expect100ContinueTimeout { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>Gets or sets whether redirects are followed.</summary>
    public bool FollowRedirects { get; set; } = true;

    /// <summary>Gets or sets the maximum number of followed redirects.</summary>
    public int MaximumRedirects { get; set; } = 10;

    /// <summary>Gets or sets the maximum encoded or decoded response body size.</summary>
    public long MaximumResponseBodyBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>Gets or sets the maximum buffered or streamed request body size.</summary>
    public long MaximumRequestBodyBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>Gets or sets the maximum serialized request header size.</summary>
    public int MaximumRequestHeaderBytes { get; set; } = 64 * 1024;

    /// <summary>Gets or sets the maximum aggregate response header size.</summary>
    public int MaximumResponseHeaderBytes { get; set; } = 64 * 1024;

    /// <summary>Gets or sets the maximum number of response header fields.</summary>
    public int MaximumResponseHeaderCount { get; set; } = 200;

    /// <summary>Gets or sets automatic gzip, deflate, and Brotli decompression.</summary>
    public bool AutomaticDecompression { get; set; } = true;

    /// <summary>Gets or sets an HTTP CONNECT proxy.</summary>
    public TlsProxy? Proxy { get; set; }

    /// <summary>Gets or sets how long an idle pooled connection may be reused.</summary>
    public TimeSpan PooledConnectionIdleTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Gets or sets the maximum age of a pooled connection.</summary>
    public TimeSpan PooledConnectionLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Gets or sets the maximum live connections retained for one origin.</summary>
    public int MaximumConnectionsPerOrigin { get; set; } = 6;

    /// <summary>Gets or sets the maximum live connections retained by the session.</summary>
    public int MaximumPooledConnections { get; set; } = 64;

    /// <summary>Gets or sets how long successful DNS answers remain cached.</summary>
    public TimeSpan DnsRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Gets or sets the maximum number of hostnames retained in the DNS cache.</summary>
    public int MaximumDnsCacheEntries { get; set; } = 256;

    /// <summary>Gets or sets the delay before racing the next resolved IP address.</summary>
    public TimeSpan HappyEyeballsDelay { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Gets or sets an optional asynchronous DNS resolver. The default uses the operating
    /// system resolver. Results are validated, copied, and cached for <see cref="DnsRefreshInterval"/>.
    /// </summary>
    public Func<string, CancellationToken, ValueTask<IReadOnlyList<IPAddress>>>? DnsResolver
    {
        get;
        set;
    }

    /// <summary>
    /// Gets or sets a synchronous observer for connection-establishment telemetry.
    /// It may be called concurrently; observer exceptions are ignored and never change
    /// request behavior.
    /// </summary>
    public Action<TlsConnectEvent>? ConnectObserver { get; set; }

    /// <summary>
    /// Gets or sets a synchronous observer for immutable, secret-free TLS handshake events.
    /// It may be called concurrently; observer exceptions are ignored and never change
    /// handshake behavior. A raw observer set through <see cref="ConfigureTls"/> retains
    /// SharpTls's abort-on-exception semantics.
    /// </summary>
    public Action<TlsHandshakeDiagnostic>? HandshakeObserver { get; set; }

    /// <summary>
    /// Gets or sets an optional preferred regular-header order. Names not listed here follow
    /// in insertion order. This does not reorder the request line.
    /// </summary>
    public IReadOnlyList<string>? HeaderOrder { get; set; }

    /// <summary>
    /// Gets headers copied into a new session after the library's safe defaults.
    /// Preset and caller values replace defaults with the same name.
    /// </summary>
    public TlsHeaders DefaultHeaders { get; } = new();

    /// <summary>Gets additional certificate SPKI pins.</summary>
    public TlsCertificatePins CertificatePins { get; } = new();

    /// <summary>Gets caller-owned SharpTls client-certificate selection policy.</summary>
    public TlsClientCertificates ClientCertificates { get; } = new();

    /// <summary>
    /// Gets or sets an advanced SharpTls hook invoked for every new connection after
    /// session defaults are applied. The pinned SharpTls version does not expose
    /// trust-validation bypass.
    /// </summary>
    public Action<CustomTlsClientOptions>? ConfigureTls { get; set; }

    internal TlsSessionConfiguration Snapshot()
    {
        ArgumentNullException.ThrowIfNull(Profile);
        ArgumentNullException.ThrowIfNull(CertificatePins);
        ArgumentNullException.ThrowIfNull(ClientCertificates);
        ArgumentNullException.ThrowIfNull(Http2);
        ArgumentNullException.ThrowIfNull(Retry);
        ArgumentNullException.ThrowIfNull(RequestPolicies);
        if (!Enum.IsDefined(HttpVersionPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(HttpVersionPolicy));
        }
        if (ProfileRoller is not null && Proxy is not null)
        {
            throw new InvalidOperationException("ProfileRoller cannot be combined with Proxy.");
        }
        if (EchDnsResolver is not null && Proxy is not null)
        {
            throw new InvalidOperationException("EchDnsResolver cannot be combined with Proxy.");
        }
        if (EchDnsResolver is not null && ProfileRoller is not null)
        {
            throw new InvalidOperationException(
                "EchDnsResolver cannot be combined with ProfileRoller.");
        }
        if (ProfileRoller is not null && HttpVersionPolicy != TlsHttpVersionPolicy.PreferHttp2)
        {
            throw new InvalidOperationException("ProfileRoller requires PreferHttp2.");
        }
        if (ProfileRoller is not null && DnsResolver is not null)
        {
            throw new InvalidOperationException("ProfileRoller cannot be combined with DnsResolver.");
        }
        if (ProfileRoller is not null && ConnectObserver is not null)
        {
            throw new InvalidOperationException("ProfileRoller cannot be combined with ConnectObserver.");
        }
        if (Timeout <= TimeSpan.Zero && Timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(Timeout));
        }
        if (Expect100ContinueTimeout < TimeSpan.Zero ||
            Expect100ContinueTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(Expect100ContinueTimeout));
        }
        if (MaximumRedirects is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumRedirects));
        }
        if (MaximumResponseBodyBytes is < 1 or > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumResponseBodyBytes));
        }
        if (MaximumRequestBodyBytes is < 1 or > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumRequestBodyBytes));
        }
        if (MaximumRequestHeaderBytes is < 1024 or > 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumRequestHeaderBytes));
        }
        if (MaximumResponseHeaderBytes is < 1024 or > 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumResponseHeaderBytes));
        }
        if (MaximumResponseHeaderCount is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumResponseHeaderCount));
        }
        if (PooledConnectionIdleTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(PooledConnectionIdleTimeout));
        }
        if (PooledConnectionLifetime <= TimeSpan.Zero &&
            PooledConnectionLifetime != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(PooledConnectionLifetime));
        }
        if (MaximumConnectionsPerOrigin is < 1 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumConnectionsPerOrigin));
        }
        if (MaximumPooledConnections is < 1 or > 4096 ||
            MaximumPooledConnections < MaximumConnectionsPerOrigin)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumPooledConnections),
                "The global limit must be at least the per-origin limit and no greater than 4096.");
        }
        if (DnsRefreshInterval <= TimeSpan.Zero &&
            DnsRefreshInterval != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(DnsRefreshInterval));
        }
        if (MaximumDnsCacheEntries is < 1 or > 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumDnsCacheEntries));
        }
        if (HappyEyeballsDelay < TimeSpan.Zero ||
            HappyEyeballsDelay > TimeSpan.FromSeconds(5))
        {
            throw new ArgumentOutOfRangeException(nameof(HappyEyeballsDelay));
        }
        if (RequestPolicies.Count > 32 || RequestPolicies.Any(policy => policy is null))
        {
            throw new ArgumentException(
                "RequestPolicies may contain at most 32 non-null policies.",
                nameof(RequestPolicies));
        }

        var headerOrder = HeaderOrder?.ToArray() ?? [];
        if (headerOrder.Any(string.IsNullOrWhiteSpace) ||
            headerOrder.Distinct(StringComparer.OrdinalIgnoreCase).Count() != headerOrder.Length)
        {
            throw new ArgumentException(
                "HeaderOrder must contain distinct, non-empty names.",
                nameof(HeaderOrder));
        }

        return new TlsSessionConfiguration(
            Profile,
            EchDnsResolver,
            ProfileRoller,
            HttpVersionPolicy,
            Http2.Snapshot(),
            Retry.Snapshot(),
            RequestPolicies.ToArray(),
            Timeout,
            Expect100ContinueTimeout,
            FollowRedirects,
            MaximumRedirects,
            (int)MaximumResponseBodyBytes,
            (int)MaximumRequestBodyBytes,
            MaximumRequestHeaderBytes,
            MaximumResponseHeaderBytes,
            MaximumResponseHeaderCount,
            AutomaticDecompression,
            Proxy,
            PooledConnectionIdleTimeout,
            PooledConnectionLifetime,
            MaximumConnectionsPerOrigin,
            MaximumPooledConnections,
            DnsRefreshInterval,
            MaximumDnsCacheEntries,
            HappyEyeballsDelay,
            DnsResolver,
            ConnectObserver,
            HandshakeObserver,
            headerOrder,
            CertificatePins.Snapshot(),
            ClientCertificates.Snapshot(),
            DefaultHeaders.Snapshot(),
            ConfigureTls);
    }
}

internal sealed record TlsSessionConfiguration(
    TlsProfile Profile,
    TlsEchDnsResolver? EchDnsResolver,
    TlsProfileRoller? ProfileRoller,
    TlsHttpVersionPolicy HttpVersionPolicy,
    TlsHttp2Configuration Http2,
    TlsRetryConfiguration Retry,
    ITlsRequestPolicy[] RequestPolicies,
    TimeSpan Timeout,
    TimeSpan Expect100ContinueTimeout,
    bool FollowRedirects,
    int MaximumRedirects,
    int MaximumResponseBodyBytes,
    int MaximumRequestBodyBytes,
    int MaximumRequestHeaderBytes,
    int MaximumResponseHeaderBytes,
    int MaximumResponseHeaderCount,
    bool AutomaticDecompression,
    TlsProxy? Proxy,
    TimeSpan PooledConnectionIdleTimeout,
    TimeSpan PooledConnectionLifetime,
    int MaximumConnectionsPerOrigin,
    int MaximumPooledConnections,
    TimeSpan DnsRefreshInterval,
    int MaximumDnsCacheEntries,
    TimeSpan HappyEyeballsDelay,
    Func<string, CancellationToken, ValueTask<IReadOnlyList<IPAddress>>>? DnsResolver,
    Action<TlsConnectEvent>? ConnectObserver,
    Action<TlsHandshakeDiagnostic>? HandshakeObserver,
    string[] HeaderOrder,
    TlsCertificatePins CertificatePins,
    TlsClientCertificateConfiguration ClientCertificates,
    HeaderEntry[] DefaultHeaders,
    Action<CustomTlsClientOptions>? ConfigureTls);
