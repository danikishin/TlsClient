# TlsClient roadmap

TlsClient is the ergonomic HTTP client built on top of
[SharpTls](https://github.com/danikishin/SharpTls). SharpTls owns the managed TLS
protocol and byte-exact ClientHello. TlsClient owns HTTP semantics, sessions,
cookies, redirects, proxies, connection reuse, and the public developer experience.

The goal is not to wrap `HttpClient` or native TLS. The goal is a managed C# client
with the convenience of Python-Tls-Client and a smaller, strongly typed API.

## Product principles

- **SharpTls is the only TLS engine.** No `SslStream`, OpenSSL, BoringSSL, P/Invoke,
  subprocess, or platform TLS fallback.
- **Secure by default.** Certificate and hostname validation are enabled by default.
  The explicit dangerous bypass delegates to SharpTls and never creates a second TLS
  implementation inside TlsClient.
- **Easy first request, deep escape hatches.** The common path is a three-line
  `TlsSession`; advanced callers can supply any SharpTls `ClientHelloProfile` and
  configure the underlying `CustomTlsClientOptions`.
- **Wire behavior is explicit.** HTTP version, header order, ALPN changes, proxy
  routing, retries, and redirects must never change silently.
- **Sessions are real.** Cookies, TLS tickets, connections, default headers, and
  policy live at session scope and are safe for concurrent callers.
- **Protocol code is hostile-input code.** Every length, frame, header, redirect,
  and decompression boundary is limited and tested.

## Public API target

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
options.FollowRedirects = true;
options.Proxy = TlsProxy.Http("http://user:pass@127.0.0.1:8080");

await using var session = new TlsSession(options);

session.DefaultHeaders.Set("User-Agent", "my-app/1.0");

TlsResponse response = await session.GetAsync("https://example.com/api");
response.EnsureSuccessStatusCode();
var model = await response.JsonAsync<MyResponse>();

Console.WriteLine(response.Tls.ProtocolVersion);
Console.WriteLine(response.Tls.ClientHelloProfile);
```

Advanced TLS configuration stays direct instead of being copied into a second,
eventually stale option model:

```csharp
var options = new TlsSessionOptions
{
    Profile = TlsProfiles.Firefox,
    ConfigureTls = tls =>
    {
        tls.EncryptedClientHello = ech;
        tls.HandshakeEventObserver = ObserveHandshake;
    },
};
```

## Phase 0 — clean foundation

- [x] Replace the old prototype and solution layout.
- [x] Target .NET 9 and reference the pinned SharpTls preview package.
- [x] Enable nullable analysis, deterministic builds, XML docs, and warnings as errors.
- [x] Add unit tests, a quick-start sample, package metadata, license, and CI.
- [x] Establish API naming, exceptions, ownership, cancellation, and disposal rules.

Exit gate: a clean checkout restores, builds, tests, packs, and runs the sample.

## Phase 1 — production HTTP/1.1 session

- [x] `TlsSession`, `TlsSessionOptions`, `TlsProfiles`, `TlsHeaders`, and
  `TlsResponse` public API.
- [x] SharpTls-only HTTPS connections with TLS 1.2/1.3 session caches.
- [x] Explicit HTTP/1.1 ALPN normalization for browser ClientHello profiles.
- [x] Correct request-target, Host, ordered headers, content headers, and body framing.
- [x] Strict status-line/header parser with informational-response support.
- [x] Content-Length, chunked, no-body, and connection-close response framing.
- [x] Bounded gzip, deflate, and Brotli response decompression.
- [x] CookieContainer integration across requests and redirect hops.
- [x] 301/302/303/307/308 redirects with credential stripping on origin changes.
- [x] HTTP CONNECT proxies with optional Basic authentication.
- [x] Per-origin keep-alive reuse, stale-connection recovery for idempotent requests,
  and deterministic session shutdown.
- [x] TLS connection metadata on every response.

Exit gate: loopback tests cover framing, cookies, redirects, pooling, limits, proxy
CONNECT, cancellation, and malformed input; public HTTPS smoke tests are optional and
never required for an offline test run.

## Phase 2 — fingerprint-correct HTTP/2

- [x] HTTP/2 framing and stream state machine over SharpTls application streams.
- [x] HPACK encoder/decoder with bounded dynamic tables and Huffman decoding.
- [x] Ordered SETTINGS profiles and explicit SETTINGS acknowledgement.
- [x] Browser-like pseudo-header ordering and regular-header ordering.
- [x] Connection and stream flow control.
- [x] PRIORITY / PRIORITY_UPDATE strategies where the selected profile uses them.
- [x] GOAWAY, RST_STREAM, PING, CONTINUATION, trailers, and graceful draining.
- [x] Multiplexed pool with cancellation that resets one stream, not the connection.
- [x] Coherent presets that pair ClientHello, ALPN, HTTP/2 settings, and headers.

Exit gate: nghttp2 interoperability, client-side malformed-peer coverage, and captured
browser-profile fixtures. The three built-in profiles have deterministic loopback wire
captures and the stack has completed a public nghttp2 smoke test. The
`0.2.0-preview` line remains preview until the interoperability matrix runs in CI across
all supported operating systems. Whenever `h2` is negotiated, TlsClient uses its HTTP/2
stack; it never sends HTTP/1.1 bytes on that connection. (`h2spec` targets HTTP/2 servers,
so its protocol cases are represented by client-facing peer fixtures instead of claiming
a direct client run.)

## Phase 3 — scale and transport depth

- [x] Configurable concurrent connections per origin and bounded global pool.
- [x] Idle/lifetime limits, DNS refresh, Happy Eyeballs, and connect telemetry.
- [x] Streaming uploads/downloads with backpressure and caller-controlled buffering.
- [x] `Expect: 100-continue`, trailers, and large-body replay policy.
- [x] SOCKS4/SOCKS5 proxies and proxy selection per request.
- [x] Explicit retry policy using method idempotency and request replayability.
- [x] Rate-limit and circuit-breaker integration points without hidden policy.

## Phase 4 — fingerprint laboratory

- [x] Named, versioned browser personas combining TLS and HTTP behavior.
- [x] Profile manifest and compatibility table generated from SharpTls metadata.
- [x] ClientHello capture/JSON import helpers powered by SharpTls.
- [x] Deterministic fingerprint snapshots for regression tests.
- [x] Coherent randomized profiles and origin-aware profile Roller integration.
- [x] Opt-in header and HTTP/2 behavior capture/import.
- [x] JA3/JA4 inspection as diagnostics; no promise that a JA3 string alone can
  reproduce a browser handshake.

## Phase 5 — modern privacy and protocols

- [x] ECH DNS discovery convenience layer over SharpTls protected DNS support.
- [x] Session persistence with caller-owned SharpTls state protectors.
- [x] Client-certificate selection and certificate pinning helpers.
- [x] Structured handshake diagnostics and OpenTelemetry activities.
- [x] Evaluate HTTP/3 transport readiness. Deferred with a documented entry gate:
  SharpTls's QUIC-TLS adapter is not itself a QUIC implementation, and no compatible,
  complete, independently tested transport is currently pinned.

## Phase 6 — 1.0 release hardening

- [x] Freeze and baseline the public API.
- [x] Cross-platform Linux/macOS/Windows test and package matrix.
- [x] Fuzz every HTTP parser and decompression boundary.
- [x] Allocation and throughput budgets with regression gates.
- [x] Threat model, security policy, supported-version policy, and disclosure process.
- [x] Deterministic NuGet package, symbols, Source Link, SBOM, and provenance.
- [x] Maintainer protocol review and hostile-peer stress audit of HTTP/2 state,
  pooling, proxy, cookie, and redirect logic. The reviewed scope, resolved findings,
  regression tests, and release evidence are recorded in `docs/PROTOCOL-REVIEW.md`.

## Completed dependency-gated follow-up

- [x] Pin SharpTls `0.9.0-preview.5` and expose its server certificate/hostname
  validation bypass as the deliberately named
  `DangerouslySkipServerCertificateValidation` session option. Secure validation stays
  enabled by default, the advanced SharpTls validation policy remains available through
  `ConfigureTls`, and TlsClient certificate pins remain enforced during bypass.

## Explicit non-goals

- Implementing certificate or hostname validation outside SharpTls.
- Pretending a JA3 string is a complete browser fingerprint.
- Claiming HTTP/3 support without a real QUIC transport.
- Hidden retries of non-idempotent or non-replayable requests.
- Unbounded headers, bodies, redirects, decompression, pools, or parser allocations.
- Compatibility with TLS 1.0/1.1 or cipher suites intentionally rejected by SharpTls.

## Version plan

| Version | Scope |
|---|---|
| `0.1.0-preview` | Phases 0–1 |
| `0.2.0-preview` | Fingerprint-correct HTTP/2 |
| `0.3.0-preview` | Pooling, streaming, proxy, and retry depth |
| `0.4.0-preview` | Fingerprint laboratory and browser personas |
| `0.5.0-preview` | ECH/DNS, persistence, diagnostics, HTTP/3 evaluation |
| `0.6.0-preview` | SharpTls-backed validation controls when available; compatibility hardening |
| `1.0.0` | Audited, fuzzed, API-stable release |
