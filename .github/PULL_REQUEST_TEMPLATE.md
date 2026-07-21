## What changed

Describe the user-visible behavior and why the change is needed.

## Wire and compatibility impact

Describe changes to TLS profiles, ALPN, HTTP framing, headers, pooling, retries, or the
public API. Write `None` when there is no impact.

## Verification

- [ ] Release build succeeds with zero warnings.
- [ ] Tests pass on the affected protocols.
- [ ] A regression test covers each bug fix.
- [ ] Fuzz/performance gates were run when parser or hot-path code changed.
- [ ] Public API baseline, documentation, and changelog are updated when required.
- [ ] No secrets, private traffic, or vulnerability details are included.
