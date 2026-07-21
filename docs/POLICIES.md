# Request policy hooks

`ITlsRequestPolicy` is a small async middleware boundary for caller-owned rate limiters,
circuit breakers, bulkheads, and attempt instrumentation. TlsClient does not impose a
limiting algorithm, global breaker state, or dependency on a policy framework.

```csharp
public sealed class ConcurrencyPolicy : ITlsRequestPolicy
{
    private static readonly object LeaseKey = new();
    private readonly SemaphoreSlim _slots = new(8, 8);

    public async ValueTask OnAttemptStartingAsync(
        TlsRequestPolicyContext context,
        CancellationToken cancellationToken)
    {
        await _slots.WaitAsync(cancellationToken);
        context.Items[LeaseKey] = true;
    }

    public ValueTask OnAttemptCompletedAsync(
        TlsRequestPolicyContext context,
        TlsRequestPolicyOutcome outcome)
    {
        if (context.Items.Remove(LeaseKey))
        {
            _slots.Release();
        }
        return ValueTask.CompletedTask;
    }
}
```

Register policies before constructing the session:

```csharp
options.RequestPolicies.Add(new ConcurrencyPolicy());
options.RequestPolicies.Add(circuitBreaker);
```

The options are snapshotted. Start hooks run in insertion order before DNS, connection
pool rental, or request bytes. Completion hooks run in reverse order after every
physical attempt. If a later start hook throws, already-started policies are completed
with that exception so acquired leases can be released.

`TlsRequestPolicyContext` reports URL, method, one-based attempt, zero-based redirect
hop, replayability, idempotency, and selected proxy protocol. Its item bag belongs to
the policy chain for that attempt and is not reused by retries.

`TlsRequestPolicyOutcome` reports HTTP status or exception, elapsed attempt duration,
and whether TlsClient's explicit retry policy will make another attempt. A response
status is observable even when it is about to be retried. Policies are normal request
code: a start exception prevents network work, while a completion exception is surfaced
after all remaining cleanup hooks have run.

One policy instance may receive concurrent calls from HTTP/2 streams and parallel
HTTP/1.1 connections. Implementations must protect shared breaker/limiter state. Request
cancellation is passed to start hooks; completion hooks receive no cancelled token so
they can release resources deterministically and should finish promptly.
