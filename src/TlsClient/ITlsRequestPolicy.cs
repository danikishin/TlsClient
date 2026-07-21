using System.Net;

namespace TlsClient;

/// <summary>
/// Integrates caller-owned rate limiting, circuit breaking, or attempt instrumentation.
/// Implementations may be invoked concurrently.
/// </summary>
public interface ITlsRequestPolicy
{
    /// <summary>
    /// Runs before one physical request attempt. Throwing prevents network work for that attempt.
    /// </summary>
    ValueTask OnAttemptStartingAsync(
        TlsRequestPolicyContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Runs after an attempt in reverse policy order, including when a later start hook fails.
    /// </summary>
    ValueTask OnAttemptCompletedAsync(
        TlsRequestPolicyContext context,
        TlsRequestPolicyOutcome outcome);
}

/// <summary>Immutable attempt metadata plus a policy-owned item bag.</summary>
public sealed class TlsRequestPolicyContext
{
    internal TlsRequestPolicyContext(
        Uri url,
        string method,
        int attempt,
        int redirectHop,
        bool isReplayable,
        bool isIdempotent,
        TlsProxyType? proxyType)
    {
        Url = url;
        Method = method;
        Attempt = attempt;
        RedirectHop = redirectHop;
        IsReplayable = isReplayable;
        IsIdempotent = isIdempotent;
        ProxyType = proxyType;
    }

    /// <summary>Gets the request URL for this hop.</summary>
    public Uri Url { get; }

    /// <summary>Gets the HTTP method token.</summary>
    public string Method { get; }

    /// <summary>Gets the one-based physical attempt number for this redirect hop.</summary>
    public int Attempt { get; }

    /// <summary>Gets the zero-based redirect hop number.</summary>
    public int RedirectHop { get; }

    /// <summary>Gets whether the request body can be sent again.</summary>
    public bool IsReplayable { get; }

    /// <summary>Gets whether the HTTP method is idempotent.</summary>
    public bool IsIdempotent { get; }

    /// <summary>Gets the selected proxy protocol, or null for a direct route.</summary>
    public TlsProxyType? ProxyType { get; }

    /// <summary>
    /// Gets an attempt-local bag for cooperation between start and completion hooks.
    /// Keys should be private objects owned by a policy implementation.
    /// </summary>
    public IDictionary<object, object?> Items { get; } =
        new Dictionary<object, object?>();
}

/// <summary>Describes the observable result of one physical request attempt.</summary>
public sealed record TlsRequestPolicyOutcome(
    HttpStatusCode? StatusCode,
    Exception? Exception,
    TimeSpan Duration,
    bool WillRetry)
{
    /// <summary>Gets whether transport execution produced an HTTP response.</summary>
    public bool HasResponse => StatusCode is not null && Exception is null;
}
