using System.Net;

namespace TlsClient;

/// <summary>Configures explicit, bounded retries for replayable requests.</summary>
public sealed class TlsRetryOptions
{
    private int _maximumAttempts = 2;
    private TimeSpan _delay;
    private TimeSpan _maximumRetryAfter = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the total attempts per request/redirect hop, including the first attempt.
    /// The default is 2.
    /// </summary>
    public int MaximumAttempts
    {
        get => _maximumAttempts;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 10);
            _maximumAttempts = value;
        }
    }

    /// <summary>Gets or sets whether eligible transport failures are retried.</summary>
    public bool RetryConnectionFailures { get; set; } = true;

    /// <summary>
    /// Gets or sets whether non-idempotent methods may be retried. The default is false.
    /// A request body must still be replayable.
    /// </summary>
    public bool RetryNonIdempotentMethods { get; set; }

    /// <summary>
    /// Gets response status codes eligible for retry. The set is empty by default.
    /// </summary>
    public ISet<HttpStatusCode> StatusCodes { get; } = new HashSet<HttpStatusCode>();

    /// <summary>Gets or sets the fixed delay before a retry. The default is zero.</summary>
    public TimeSpan Delay
    {
        get => _delay;
        set
        {
            if (value < TimeSpan.Zero || value > TimeSpan.FromMinutes(1))
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            _delay = value;
        }
    }

    /// <summary>Gets or sets whether a valid Retry-After response header overrides Delay.</summary>
    public bool RespectRetryAfter { get; set; } = true;

    /// <summary>Gets or sets the maximum accepted Retry-After delay.</summary>
    public TimeSpan MaximumRetryAfter
    {
        get => _maximumRetryAfter;
        set
        {
            if (value < TimeSpan.Zero || value > TimeSpan.FromMinutes(10))
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            _maximumRetryAfter = value;
        }
    }

    internal TlsRetryConfiguration Snapshot()
    {
        var statusCodes = StatusCodes.ToHashSet();
        if (statusCodes.Any(status => (int)status is < 100 or > 599))
        {
            throw new ArgumentOutOfRangeException(
                nameof(StatusCodes),
                "Retry status codes must be between 100 and 599.");
        }
        return new TlsRetryConfiguration(
            MaximumAttempts,
            RetryConnectionFailures,
            RetryNonIdempotentMethods,
            statusCodes,
            Delay,
            RespectRetryAfter,
            MaximumRetryAfter);
    }
}

internal sealed record TlsRetryConfiguration(
    int MaximumAttempts,
    bool RetryConnectionFailures,
    bool RetryNonIdempotentMethods,
    HashSet<HttpStatusCode> StatusCodes,
    TimeSpan Delay,
    bool RespectRetryAfter,
    TimeSpan MaximumRetryAfter);
