using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SharpTls;

namespace TlsClient;

/// <summary>
/// A reusable HTTPS session with cookies, TLS tickets, pooled connections, redirects,
/// and a selected SharpTls ClientHello profile.
/// </summary>
public sealed class TlsSession : IAsyncDisposable, IDisposable
{
    private readonly TlsSessionConfiguration _configuration;
    private readonly TlsConnectionPool _pool;
    private readonly object _cookieSync = new();
    private int _disposed;

    /// <summary>Creates a session with Chrome-family defaults.</summary>
    public TlsSession() : this(new TlsSessionOptions())
    {
    }

    /// <summary>Creates a session from a coherent TLS and HTTP preset.</summary>
    public TlsSession(TlsPreset preset) : this(new TlsSessionOptions(preset))
    {
    }

    /// <summary>Creates a session and snapshots its options.</summary>
    public TlsSession(TlsSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _configuration = options.Snapshot();
        _pool = new TlsConnectionPool(_configuration);
        Cookies = new CookieContainer();
        DefaultHeaders = new TlsHeaders();
        DefaultHeaders.Set("User-Agent", "TlsClient/0.1");
        DefaultHeaders.Set("Accept", "*/*");
        if (_configuration.AutomaticDecompression)
        {
            DefaultHeaders.Set("Accept-Encoding", "gzip, deflate, br");
        }
        DefaultHeaders.Set("Connection", "keep-alive");
        foreach (var header in _configuration.DefaultHeaders)
        {
            DefaultHeaders.Set(header.Name, header.Values);
        }
    }

    /// <summary>Gets session-wide, insertion-ordered request headers.</summary>
    public TlsHeaders DefaultHeaders { get; }

    /// <summary>Gets the session cookie container.</summary>
    public CookieContainer Cookies { get; }

    /// <summary>Gets the number of unexpired TLS 1.3 tickets in the in-memory cache.</summary>
    public int CachedTls13SessionCount
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _pool.Tls13SessionCount;
        }
    }

    /// <summary>
    /// Exports unexpired TLS 1.3 tickets as one SharpTls authenticated encrypted blob.
    /// The caller owns and must dispose the protector and protect its keys.
    /// </summary>
    public byte[] ExportTls13SessionState(Tls13SessionStateProtector protector)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _pool.ExportTls13SessionState(protector);
    }

    /// <summary>
    /// Authenticates, validates, and atomically imports a SharpTls encrypted TLS 1.3
    /// ticket set. The caller owns and must dispose the protector.
    /// </summary>
    public void ImportTls13SessionState(
        ReadOnlySpan<byte> protectedState,
        Tls13SessionStateProtector protector)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _pool.ImportTls13SessionState(protectedState, protector);
    }

    /// <summary>Sends an HTTPS request.</summary>
    public async Task<TlsResponse> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var buffered = await BufferedRequest.CreateAsync(
            request,
            _configuration.MaximumRequestBodyBytes,
            _configuration.HttpVersionPolicy,
            cancellationToken).ConfigureAwait(false);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_configuration.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            timeout.CancelAfter(_configuration.Timeout);
        }

        try
        {
            return await SendBufferedAsync(buffered, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (
            !cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"The request exceeded the {_configuration.Timeout} session timeout.",
                exception);
        }
    }

    /// <summary>
    /// Sends an HTTPS request and writes its final response body directly to
    /// <paramref name="responseBody"/>. The destination remains owned by the caller.
    /// </summary>
    public async Task<TlsResponse> SendStreamingAsync(
        HttpRequestMessage request,
        Stream responseBody,
        TlsStreamingOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(responseBody);
        if (!responseBody.CanWrite)
        {
            throw new ArgumentException(
                "The response destination must be writable.",
                nameof(responseBody));
        }
        var streamingConfiguration = (options ?? new TlsStreamingOptions()).Snapshot(
            _configuration.AutomaticDecompression);
        var requestConfiguration = TlsRequestOptions.Snapshot(request);
        var buffered = requestConfiguration.ReplayPolicy == TlsRequestReplayPolicy.Buffer
            ? await BufferedRequest.CreateAsync(
                request,
                _configuration.MaximumRequestBodyBytes,
                _configuration.HttpVersionPolicy,
                cancellationToken).ConfigureAwait(false)
            : BufferedRequest.CreateStreaming(
                request,
                _configuration.MaximumRequestBodyBytes,
                streamingConfiguration.BufferSize,
                _configuration.HttpVersionPolicy);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_configuration.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            timeout.CancelAfter(_configuration.Timeout);
        }

        try
        {
            return await SendStreamingCoreAsync(
                buffered,
                responseBody,
                streamingConfiguration,
                timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (
            !cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"The request exceeded the {_configuration.Timeout} session timeout.",
                exception);
        }
    }

    /// <summary>Downloads a URL directly into a caller-owned stream.</summary>
    public Task<TlsResponse> DownloadAsync(
        string url,
        Stream destination,
        TlsStreamingOptions? options = null,
        CancellationToken cancellationToken = default) => DownloadAsync(
            new Uri(url, UriKind.Absolute),
            destination,
            options,
            cancellationToken);

    /// <summary>Downloads a URL directly into a caller-owned stream.</summary>
    public async Task<TlsResponse> DownloadAsync(
        Uri url,
        Stream destination,
        TlsStreamingOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        return await SendStreamingAsync(
            request,
            destination,
            options,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends a GET request.</summary>
    public Task<TlsResponse> GetAsync(string url, CancellationToken cancellationToken = default) =>
        GetAsync(new Uri(url, UriKind.Absolute), cancellationToken);

    /// <summary>Sends a GET request.</summary>
    public Task<TlsResponse> GetAsync(Uri url, CancellationToken cancellationToken = default) =>
        SendConvenienceAsync(HttpMethod.Get, url, null, cancellationToken);

    /// <summary>Sends a DELETE request.</summary>
    public Task<TlsResponse> DeleteAsync(string url, CancellationToken cancellationToken = default) =>
        SendConvenienceAsync(HttpMethod.Delete, new Uri(url, UriKind.Absolute), null, cancellationToken);

    /// <summary>Sends a POST request.</summary>
    public Task<TlsResponse> PostAsync(
        string url,
        HttpContent content,
        CancellationToken cancellationToken = default) =>
        SendConvenienceAsync(
            HttpMethod.Post,
            new Uri(url, UriKind.Absolute),
            content,
            cancellationToken);

    /// <summary>Serializes a value as JSON and sends a POST request.</summary>
    public Task<TlsResponse> PostJsonAsync<T>(
        string url,
        T value,
        JsonSerializerOptions? options = null,
        CancellationToken cancellationToken = default) =>
        SendConvenienceAsync(
            HttpMethod.Post,
            new Uri(url, UriKind.Absolute),
            JsonContent.Create(value, options: options),
            cancellationToken);

    /// <inheritdoc />
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        await _pool.DisposeAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    private async Task<TlsResponse> SendConvenienceAsync(
        HttpMethod method,
        Uri url,
        HttpContent? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url) { Content = content };
        return await SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TlsResponse> SendBufferedAsync(
        BufferedRequest request,
        CancellationToken cancellationToken)
    {
        var redirects = new List<TlsRedirect>();
        while (true)
        {
            var result = await SendBufferedAttemptAsync(
                request,
                redirects.Count,
                cancellationToken)
                .ConfigureAwait(false);
            StoreCookies(request.Url, result.Http.Headers);

            if (_configuration.FollowRedirects &&
                TryCreateRedirect(request, result.Http, out var redirected))
            {
                if (redirects.Count >= _configuration.MaximumRedirects)
                {
                    throw new HttpRequestException(
                        $"The request exceeded {_configuration.MaximumRedirects} redirects.");
                }
                redirects.Add(new TlsRedirect(request.Url, redirected.Url, result.Http.StatusCode));
                request = redirected;
                continue;
            }

            var (body, wasDecompressed) = _configuration.AutomaticDecompression
                ? await ResponseDecompressor.DecodeAsync(
                    result.Http.Body,
                    result.Http.Headers,
                    _configuration.MaximumResponseBodyBytes,
                    cancellationToken).ConfigureAwait(false)
                : (result.Http.Body, false);
            return new TlsResponse(
                request.Url,
                result.Http.Version,
                result.Http.StatusCode,
                result.Http.ReasonPhrase,
                result.Http.Headers,
                result.Http.Trailers,
                body,
                wasDecompressed,
                false,
                result.Tls,
                redirects.AsReadOnly());
        }
    }

    private async Task<TlsResponse> SendStreamingCoreAsync(
        BufferedRequest request,
        Stream responseBody,
        TlsStreamingConfiguration streamingConfiguration,
        CancellationToken cancellationToken)
    {
        var redirects = new List<TlsRedirect>();
        while (true)
        {
            var attempt = 1;
            while (true)
            {
                using var streaming = new StreamingResponseContext(
                    responseBody,
                    streamingConfiguration,
                    _configuration.MaximumResponseBodyBytes,
                    (statusCode, headers) =>
                        ShouldDiscardRedirectBody(request, statusCode, headers) ||
                        ShouldRetryStatus(request, statusCode, attempt));
                ConnectionResponse result;
                var policy = await StartPoliciesAsync(
                    request,
                    attempt,
                    redirects.Count,
                    cancellationToken).ConfigureAwait(false);
                using var activity = TlsDiagnostics.StartHttpRequest(
                    request,
                    attempt,
                    redirects.Count);
                try
                {
                    result = await _pool.SendStreamingAsync(
                        request,
                        DefaultHeaders.Snapshot(),
                        Cookies,
                        _cookieSync,
                        streaming,
                        cancellationToken).ConfigureAwait(false);
                    TlsDiagnostics.CompleteHttpRequest(
                        activity,
                        result.Http.StatusCode,
                        result.Http.Version,
                        result.Tls);
                }
                catch (Exception exception)
                {
                    TlsDiagnostics.RecordFailure(activity, exception);
                    var willRetry = streaming.BytesWritten == 0 &&
                        ShouldRetryException(request, exception, attempt);
                    await CompletePoliciesAsync(
                        policy,
                        null,
                        exception,
                        willRetry).ConfigureAwait(false);
                    if (willRetry)
                    {
                        attempt++;
                        await DelayBeforeRetryAsync(null, cancellationToken).ConfigureAwait(false);
                        continue;
                    }
                    throw;
                }
                StoreCookies(request.Url, result.Http.Headers);

                var retryStatus = ShouldRetryStatus(
                    request,
                    result.Http.StatusCode,
                    attempt);
                await CompletePoliciesAsync(
                    policy,
                    result.Http.StatusCode,
                    null,
                    retryStatus).ConfigureAwait(false);
                if (retryStatus)
                {
                    attempt++;
                    await DelayBeforeRetryAsync(result.Http.Headers, cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                if (_configuration.FollowRedirects &&
                    TryCreateRedirect(request, result.Http, out var redirected))
                {
                    if (redirects.Count >= _configuration.MaximumRedirects)
                    {
                        throw new HttpRequestException(
                            $"The request exceeded {_configuration.MaximumRedirects} redirects.");
                    }
                    redirects.Add(new TlsRedirect(
                        request.Url,
                        redirected.Url,
                        result.Http.StatusCode));
                    request = redirected;
                    break;
                }

                return new TlsResponse(
                    request.Url,
                    result.Http.Version,
                    result.Http.StatusCode,
                    result.Http.ReasonPhrase,
                    result.Http.Headers,
                    result.Http.Trailers,
                    [],
                    streaming.WasDecompressed,
                    true,
                    result.Tls,
                    redirects.AsReadOnly());
            }
        }
    }

    private async ValueTask<ConnectionResponse> SendBufferedAttemptAsync(
        BufferedRequest request,
        int redirectHop,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            var policy = await StartPoliciesAsync(
                request,
                attempt,
                redirectHop,
                cancellationToken).ConfigureAwait(false);
            using var activity = TlsDiagnostics.StartHttpRequest(
                request,
                attempt,
                redirectHop);
            ConnectionResponse result;
            try
            {
                result = await _pool.SendAsync(
                    request,
                    DefaultHeaders.Snapshot(),
                    Cookies,
                    _cookieSync,
                    cancellationToken).ConfigureAwait(false);
                TlsDiagnostics.CompleteHttpRequest(
                    activity,
                    result.Http.StatusCode,
                    result.Http.Version,
                    result.Tls);
            }
            catch (Exception exception)
            {
                TlsDiagnostics.RecordFailure(activity, exception);
                var willRetry = ShouldRetryException(request, exception, attempt);
                await CompletePoliciesAsync(
                    policy,
                    null,
                    exception,
                    willRetry).ConfigureAwait(false);
                if (willRetry)
                {
                    await DelayBeforeRetryAsync(null, cancellationToken).ConfigureAwait(false);
                    continue;
                }
                throw;
            }
            var retryStatus = ShouldRetryStatus(request, result.Http.StatusCode, attempt);
            await CompletePoliciesAsync(
                policy,
                result.Http.StatusCode,
                null,
                retryStatus).ConfigureAwait(false);
            if (!retryStatus)
            {
                return result;
            }
            StoreCookies(request.Url, result.Http.Headers);
            await DelayBeforeRetryAsync(result.Http.Headers, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask<PolicyInvocation?> StartPoliciesAsync(
        BufferedRequest request,
        int attempt,
        int redirectHop,
        CancellationToken cancellationToken)
    {
        if (_configuration.RequestPolicies.Length == 0)
        {
            return null;
        }
        var selectedProxy = request.HasProxyOverride ? request.Proxy : _configuration.Proxy;
        var context = new TlsRequestPolicyContext(
            request.Url,
            request.Method,
            attempt,
            redirectHop,
            request.IsReplayable,
            request.IsIdempotent,
            selectedProxy?.Type);
        var stopwatch = Stopwatch.StartNew();
        var started = 0;
        try
        {
            for (; started < _configuration.RequestPolicies.Length; started++)
            {
                await _configuration.RequestPolicies[started].OnAttemptStartingAsync(
                    context,
                    cancellationToken).ConfigureAwait(false);
            }
            return new PolicyInvocation(context, started, stopwatch);
        }
        catch (Exception exception)
        {
            var invocation = new PolicyInvocation(context, started, stopwatch);
            try
            {
                await CompletePoliciesAsync(
                    invocation,
                    null,
                    exception,
                    willRetry: false).ConfigureAwait(false);
            }
            catch (Exception completionException)
            {
                throw new AggregateException(exception, completionException);
            }
            throw;
        }
    }

    private async ValueTask CompletePoliciesAsync(
        PolicyInvocation? invocation,
        HttpStatusCode? statusCode,
        Exception? exception,
        bool willRetry)
    {
        if (invocation is null)
        {
            return;
        }
        invocation.Stopwatch.Stop();
        var outcome = new TlsRequestPolicyOutcome(
            statusCode,
            exception,
            invocation.Stopwatch.Elapsed,
            willRetry);
        List<Exception>? failures = null;
        for (var index = invocation.StartedPolicies - 1; index >= 0; index--)
        {
            try
            {
                await _configuration.RequestPolicies[index].OnAttemptCompletedAsync(
                    invocation.Context,
                    outcome).ConfigureAwait(false);
            }
            catch (Exception policyException)
            {
                (failures ??= []).Add(policyException);
            }
        }
        if (failures is { Count: 1 })
        {
            throw failures[0];
        }
        if (failures is { Count: > 1 })
        {
            throw new AggregateException(failures);
        }
    }

    private bool ShouldRetryException(
        BufferedRequest request,
        Exception exception,
        int attempt) =>
        CanRetry(request, attempt) &&
        _configuration.Retry.RetryConnectionFailures &&
        exception is IOException or HttpRequestException or ObjectDisposedException &&
        exception is not TlsHttpProtocolException;

    private bool ShouldRetryStatus(
        BufferedRequest request,
        HttpStatusCode statusCode,
        int attempt) =>
        CanRetry(request, attempt) && _configuration.Retry.StatusCodes.Contains(statusCode);

    private bool CanRetry(BufferedRequest request, int attempt) =>
        request.EnableRetries != false &&
        attempt < _configuration.Retry.MaximumAttempts &&
        request.IsReplayable &&
        (request.IsIdempotent || _configuration.Retry.RetryNonIdempotentMethods);

    private async ValueTask DelayBeforeRetryAsync(
        TlsHeaders? headers,
        CancellationToken cancellationToken)
    {
        var delay = _configuration.Retry.Delay;
        if (_configuration.Retry.RespectRetryAfter && headers is not null &&
            TryGetRetryAfter(headers, out var retryAfter))
        {
            delay = retryAfter > _configuration.Retry.MaximumRetryAfter
                ? _configuration.Retry.MaximumRetryAfter
                : retryAfter;
        }
        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool TryGetRetryAfter(TlsHeaders headers, out TimeSpan delay)
    {
        delay = default;
        var value = headers.GetFirstOrDefault("Retry-After");
        if (value is null)
        {
            return false;
        }
        if (int.TryParse(
                value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var seconds) && seconds >= 0)
        {
            delay = TimeSpan.FromSeconds(seconds);
            return true;
        }
        if (DateTimeOffset.TryParseExact(
                value,
                "r",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal,
                out var date))
        {
            delay = date <= DateTimeOffset.UtcNow ? TimeSpan.Zero : date - DateTimeOffset.UtcNow;
            return true;
        }
        return false;
    }

    private sealed record PolicyInvocation(
        TlsRequestPolicyContext Context,
        int StartedPolicies,
        Stopwatch Stopwatch);

    private bool ShouldDiscardRedirectBody(
        BufferedRequest request,
        HttpStatusCode statusCode,
        TlsHeaders headers)
    {
        if (!_configuration.FollowRedirects || statusCode is not (
                HttpStatusCode.MovedPermanently or
                HttpStatusCode.Found or
                HttpStatusCode.SeeOther or
                HttpStatusCode.TemporaryRedirect or
                HttpStatusCode.PermanentRedirect))
        {
            return false;
        }
        var location = headers.GetFirstOrDefault("Location");
        return location is not null && Uri.TryCreate(request.Url, location, out _);
    }

    private void StoreCookies(Uri url, TlsHeaders headers)
    {
        if (!headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }
        lock (_cookieSync)
        {
            foreach (var value in values)
            {
                try
                {
                    Cookies.SetCookies(url, value);
                }
                catch (CookieException)
                {
                    // Match mainstream clients: an invalid Set-Cookie does not discard the response.
                }
            }
        }
    }

    private static bool TryCreateRedirect(
        BufferedRequest request,
        ParsedHttpResponse response,
        out BufferedRequest redirected)
    {
        redirected = request;
        if (response.StatusCode is not (
                HttpStatusCode.MovedPermanently or
                HttpStatusCode.Found or
                HttpStatusCode.SeeOther or
                HttpStatusCode.TemporaryRedirect or
                HttpStatusCode.PermanentRedirect))
        {
            return false;
        }

        var location = response.Headers.GetFirstOrDefault("Location");
        if (location is null || !Uri.TryCreate(request.Url, location, out var target))
        {
            return false;
        }
        if (!string.Equals(target.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new HttpRequestException(
                $"Redirects to '{target.Scheme}' are rejected because TlsClient is HTTPS-only.");
        }

        var switchToGet = response.StatusCode == HttpStatusCode.SeeOther && request.Method != "HEAD" ||
            response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found &&
            request.Method == "POST";
        var method = switchToGet ? "GET" : request.Method;
        var originChanged = !SameOrigin(request.Url, target);
        redirected = request.Redirect(target, method, switchToGet, originChanged);
        return true;
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.IdnHost, right.IdnHost, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port;
}
