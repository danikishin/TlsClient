# Retry policy

Retries are a visible session policy. TlsClient does not retry indefinitely and never
replays a non-replayable body:

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
options.Retry.MaximumAttempts = 3; // includes the first attempt
options.Retry.RetryConnectionFailures = true;
options.Retry.StatusCodes.Add(HttpStatusCode.RequestTimeout);
options.Retry.StatusCodes.Add(HttpStatusCode.TooManyRequests);
options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
options.Retry.Delay = TimeSpan.FromMilliseconds(250);
options.Retry.MaximumRetryAfter = TimeSpan.FromSeconds(30);
```

`MaximumAttempts` is 1–10 and applies independently to each redirect hop. The default is
2, retries eligible connection failures, and has no retryable status codes. This retains
safe stale pooled-connection recovery without silently retrying an application response.

## Eligibility

Every retry requires all of the following:

- another attempt remains;
- per-request retries were not disabled;
- the request is replayable;
- the method is idempotent, unless `RetryNonIdempotentMethods` is enabled;
- the failure is an eligible transport failure, or its status code is in `StatusCodes`.

Buffered `SendAsync` requests are replayable. A `SendStreamingAsync` upload is replayable
only when it has no content stream or
`TlsRequestOptions.For(request).ReplayPolicy = TlsRequestReplayPolicy.Buffer` was set.
The buffer remains bounded by `MaximumRequestBodyBytes`.

Per-request control is nullable so the normal state inherits session policy:

```csharp
TlsRequestOptions.For(request).EnableRetries = false;
```

## Delays and Retry-After

`Delay` is a fixed cancellation-aware delay between attempts. When
`RespectRetryAfter` is true, a valid delta-seconds or IMF-fixdate `Retry-After` header
replaces it. The value is clamped to `MaximumRetryAfter`, preventing a peer from parking
a request for an unbounded duration. The session's end-to-end timeout still covers all
attempts, delays, and redirects.

## Streaming responses

TlsClient discards a configured retry-status response body before the next attempt, so
only the final response reaches the caller's destination. A transport failure may retry
only while the destination byte count is zero. Once any bytes were delivered, the
partial result is surfaced and never followed by hidden bytes from another attempt.

Cookies from retry responses are processed before the next attempt. Retry attempts are
not redirect-history entries; `TlsResponse.History` remains a redirect-only chronology.
