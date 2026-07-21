<div align="center">
  <h1>TlsClient</h1>
  <p><strong>Browser-shaped HTTPS. Pure managed C#. No native TLS escape hatch.</strong></p>
  <p>
    A production-oriented HTTP/1.1 and HTTP/2 client powered by
    <a href="https://github.com/danikishin/SharpTls">SharpTls</a>.
  </p>
  <p>
    <a href="https://github.com/danikishin/TlsClient/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/danikishin/TlsClient/actions/workflows/ci.yml/badge.svg?branch=main"></a>
    <a href="https://github.com/danikishin/TlsClient/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/danikishin/TlsClient/actions/workflows/codeql.yml/badge.svg?branch=main"></a>
    <a href="https://github.com/danikishin/TlsClient/releases"><img alt="Release" src="https://img.shields.io/github/v/release/danikishin/TlsClient?include_prereleases&sort=semver"></a>
    <a href="https://www.nuget.org/packages/TlsClient"><img alt="NuGet" src="https://img.shields.io/nuget/vpre/TlsClient?logo=nuget"></a>
    <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-2ea44f"></a>
    <img alt=".NET 9" src="https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet">
  </p>
  <p>
    <code>HTTP/1.1</code> · <code>HTTP/2</code> · <code>HPACK</code> ·
    <code>SOCKS4/5</code> · <code>ECH</code> · <code>OpenTelemetry</code>
  </p>
</div>

TlsClient is the ergonomic HTTP layer for
[SharpTls](https://github.com/danikishin/SharpTls). It owns requests, responses,
cookies, redirects, proxies, decompression, pooling, streaming, retries, and coherent
browser-family behavior. SharpTls remains the only TLS engine and owns certificate
validation, TLS state, and the byte-exact ClientHello.

There is no `SslStream`, native TLS library, P/Invoke, helper process, or opaque Go
binary in this package.

> [!IMPORTANT]
> `0.5.0-preview.1` implements the complete pre-1.0 roadmap, including HTTP/2,
> hostile-peer bounds, fuzz/performance gates, and reproducible release artifacts.
> Preview status means the public API may still change before `1.0.0`; it does not mean
> protocol validation or certificate security is disabled.

## Why TlsClient?

| Capability | What you get |
|---|---|
| Managed end to end | HTTP/1.1 and HTTP/2 run directly over SharpTls application streams. |
| Coherent fingerprints | TLS ClientHello, ALPN, HTTP/2 SETTINGS, pseudo-headers, and regular headers move as one preset. |
| Real sessions | Concurrent pooling, cookies, redirects, tickets, retries, proxies, and deterministic shutdown. |
| Bounded by design | Header, body, decompression, redirect, parser, DNS, and pool limits are enforced on hostile input. |
| Deep escape hatches | Start with three lines, then opt into SharpTls profiles, ECH, pins, client certificates, or custom policies. |

```text
Your application
      │
      ▼
  TlsSession ── cookies · redirects · retries · proxies · pooling
      │
      ├── managed HTTP/1.1
      └── managed HTTP/2 + HPACK
                  │
                  ▼
               SharpTls ── TLS 1.2/1.3 · ClientHello · trust validation
                  │
                  ▼
                  TCP
```

## Project at a glance

| | |
|---|---|
| Current version | `0.5.0-preview.1` |
| Runtime | .NET 9 |
| TLS engine | `SharpTls 0.9.0-preview.4` (exact NuGet dependency) |
| HTTP | Managed HTTP/1.1 and HTTP/2 |
| Platforms | Linux, macOS, and Windows |
| License | MIT |

Start with the [quick-start sample](samples/TlsClient.QuickStart/Program.cs), browse the
[roadmap](ROADMAP.md), or jump directly to the
[protocol review evidence](docs/PROTOCOL-REVIEW.md). The focused guides cover
[presets](docs/PRESETS.md), [streaming](docs/STREAMING.md),
[connectivity](docs/CONNECTIVITY.md), [retries](docs/RETRIES.md),
[certificates](docs/CERTIFICATES.md), [diagnostics](docs/DIAGNOSTICS.md), and
[reproducible releases](docs/SUPPLY-CHAIN.md).

## Install

```shell
dotnet add package TlsClient --version 0.5.0-preview.1
```

TlsClient currently targets .NET 9 and pins `SharpTls 0.9.0-preview.4`.

## Quick start

```csharp
using TlsClient;

await using var session = new TlsSession(TlsPresets.Chrome133);

var response = await session.GetAsync("https://example.com/");
response.EnsureSuccessStatusCode();

Console.WriteLine(response.Text);
Console.WriteLine(response.Tls.ProtocolVersion);
Console.WriteLine(response.Tls.ClientHelloProfile);
```

The session reuses HTTP connections and SharpTls session tickets, stores cookies, and
applies one end-to-end timeout across redirect hops.

HTTP/2 is preferred by default and HTTP/1.1 is used when the server does not negotiate
`h2`. The selected version and ALPN are observable on every response:

```csharp
Console.WriteLine(response.HttpVersion);             // 2.0
Console.WriteLine(response.Tls.ApplicationProtocol); // h2
```

## Coherent presets

`TlsPresets` configures the TLS ClientHello and HTTP behavior as one unit:

```csharp
await using var chrome = new TlsSession(TlsPresets.Chrome133);
await using var firefox = new TlsSession(TlsPresets.Firefox148);
await using var android = new TlsSession(TlsPresets.Android11);
```

Use `CreateOptions()` when a preset is the starting point rather than the final policy:

```csharp
var options = TlsPresets.Firefox148.CreateOptions();
options.Proxy = TlsProxy.Http("http://127.0.0.1:8080");
options.Timeout = TimeSpan.FromSeconds(15);
options.DefaultHeaders.Set("Accept-Language", "tr-TR,tr;q=0.9,en;q=0.7");

await using var customized = new TlsSession(options);
```

The versioned names are reproducible. `Chrome`, `Firefox`, and `Android` are convenience
aliases to the current built-in versioned preset and may advance in a later release.
Preset options are independent copies, so customizing one session never mutates a global
preset. See [docs/PRESETS.md](docs/PRESETS.md) for sources and captured wire signatures.
The [generated profile manifest](docs/PROFILE-MANIFEST.md) exposes the SharpTls source
name, ordered TLS/ALPN metadata, feature flags, compatibility, and a deterministic
secret-free specification digest for every built-in profile. Regenerate it with:

```bash
dotnet run --project tools/TlsClient.ProfileCatalog
```

## HTTP version and HTTP/2 wire controls

```csharp
var options = new TlsSessionOptions
{
    HttpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2,
    HeaderOrder = ["accept", "user-agent", "accept-encoding", "accept-language"],
};

options.Http2.HeaderTableSize = 65_536;
options.Http2.InitialWindowSize = 6_291_456;
options.Http2.ConnectionWindowIncrement = 15_663_105;
options.Http2.MaxHeaderListSize = 262_144;
options.Http2.SettingsOrder =
[
    TlsHttp2Setting.HeaderTableSize,
    TlsHttp2Setting.EnablePush,
    TlsHttp2Setting.InitialWindowSize,
    TlsHttp2Setting.MaxHeaderListSize,
];
options.Http2.PseudoHeaderOrder = [":method", ":authority", ":scheme", ":path"];

await using var tuned = new TlsSession(options);
```

Use `Http11Only` for an explicit fallback-free HTTP/1.1 session or `Http2Only` when
missing `h2` ALPN must fail. `HttpRequestMessage.VersionPolicy = RequestVersionExact`
can require HTTP/1.1 or HTTP/2 for one request. SETTINGS and pseudo-header arrays are
written in the exact supplied order; invalid values fail during session construction.

## Bounded connection pooling

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
options.MaximumConnectionsPerOrigin = 6;
options.MaximumPooledConnections = 64;
options.PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2);
options.PooledConnectionLifetime = TimeSpan.FromMinutes(10);
options.DnsRefreshInterval = TimeSpan.FromMinutes(5);
options.MaximumDnsCacheEntries = 256;
options.HappyEyeballsDelay = TimeSpan.FromMilliseconds(250);

await using var session = new TlsSession(options);
```

Concurrent HTTP/1.1 requests can use separate connections up to the per-origin limit.
HTTP/2 requests share a multiplexed connection while it has stream capacity. The first
handshake for an origin is coalesced so concurrent callers do not open redundant sockets
before ALPN is known. At the global limit, the least-recently-used idle connection is
evicted; if every eligible connection is busy, the request waits with cancellation.

New connections use cached, bounded-lifetime DNS answers and race IPv6/IPv4 addresses
with Happy Eyeballs. A failed address starts the next candidate immediately instead of
waiting for the normal delay. DNS and every TCP/proxy/TLS phase can be observed without
changing request behavior:

```csharp
options.ConnectObserver = item => Console.WriteLine(
    $"{item.ConnectionId} {item.Kind} {item.Address} {item.Elapsed}");
```

Custom environments can supply `options.DnsResolver`; IP literals bypass DNS and HTTP
CONNECT sessions resolve the proxy endpoint rather than leaking origin DNS locally.
See [docs/CONNECTIVITY.md](docs/CONNECTIVITY.md) for event and cancellation semantics.

## JSON and standard request messages

```csharp
var created = await session.PostJsonAsync(
    "https://api.example.com/items",
    new { name = "managed TLS" });

var model = created.Json<MyResponse>();

using var request = new HttpRequestMessage(HttpMethod.Put, "https://api.example.com/items/1")
{
    Content = JsonContent.Create(new { enabled = true }),
};
request.Headers.TryAddWithoutValidation("X-Trace-Id", traceId);

TlsResponse updated = await session.SendAsync(request, cancellationToken);
```

`SendAsync` buffers request and response bodies within the configured limits. Use the
streaming API when either side should stay out of memory:

```csharp
await using var upload = File.OpenRead("archive.tar");
using var content = new StreamContent(upload);
content.Headers.ContentLength = upload.Length;
using var request = new HttpRequestMessage(
    HttpMethod.Put,
    "https://api.example.com/archive")
{
    Content = content,
};
await using var reply = File.Create("reply.json");

TlsResponse response = await session.SendStreamingAsync(
    request,
    reply,
    new TlsStreamingOptions { BufferSize = 64 * 1024 },
    cancellationToken);
```

Per-request transport semantics stay on the request instead of growing session-global
switches:

```csharp
request.Headers.ExpectContinue = true;

var requestOptions = TlsRequestOptions.For(request);
requestOptions.Trailers.Set("X-Checksum", checksum);
requestOptions.ReplayPolicy = TlsRequestReplayPolicy.Buffer;
```

`Expect100ContinueTimeout` controls the bounded wait for an interim response. Streaming
uploads are non-replayable by default; `Buffer` is an explicit, session-limit-bounded
opt-in for redirects that must resend the body.

`DownloadAsync(url, destination)` is the GET shorthand. The same bounded buffer drives
request reads, HTTP/1.1 copies, and decompression writes. HTTP/2 keeps flow control per
stream and restores window credit only after the destination accepts data, so a slow
download does not force unbounded buffering or block unrelated multiplexed responses.
Caller-provided streams stay caller-owned. A streamed response has
`BodyWasStreamed == true`; its `Body` is empty and `Text`/`Json<T>()` reject accidental
use. See [docs/STREAMING.md](docs/STREAMING.md) for framing, redirects, replay, limits,
and ownership details.

## Profiles and exact SharpTls access

```csharp
var firefox = new TlsSession(new TlsSessionOptions
{
    Profile = TlsProfiles.Firefox,
});

var customProfile = TlsProfile.Create(
    "my-profile",
    ClientHelloProfiles.Custom(builder => builder
        .WithTls13()
        .WithAlpn("http/1.1")));

var advanced = new TlsSession(new TlsSessionOptions
{
    Profile = customProfile,
    ConfigureTls = tls =>
    {
        tls.HandshakeEventObserver = ObserveHandshake;
        tls.EncryptedClientHello = echOptions;
    },
});
```

`Chrome`, `Firefox`, `Edge`, `Safari`, `IOS`, and `Android` track SharpTls's version-bound
Auto aliases. Pinned profiles such as `Chrome133`, `Firefox148`, and `Android11` are
available when a stable TLS wire image matters. A `TlsProfile` selects TLS only; prefer
the matching `TlsPreset` when HTTP/2 settings and headers should move with it.

TlsClient coherently rewrites ALPN for the selected HTTP policy and removes ALPS when
the advertised protocol set cannot use it. Cipher suites, groups, signatures, GREASE
policy, padding, and extension layout otherwise remain the SharpTls profile's values.
The response reports both the selected profile name and negotiated ALPN.

Applications can consume the same generated data without parsing Markdown through
`TlsProfileCatalog.Profiles`, `TlsProfileCatalog.Inspect(profile)`, or
`TlsProfileCatalog.ExportJson()`.

Captured ClientHello bytes and SharpTls's strict, versioned profile JSON can be imported
without copying TLS semantics into a second model:

```csharp
var imported = TlsClientHello.ImportCapture("reviewed", captureBytes);
string json = TlsClientHello.ExportJson(imported.Profile);
TlsProfile restored = TlsClientHello.ImportJson("restored", json);
```

`TlsClientHello.BuildSnapshotForTesting(...)` produces repeatable, HTTP-policy-aware
ClientHello fixtures and a SHA-256 digest. Its deterministic key material is strictly
test-only and must never be transmitted. See
[docs/FINGERPRINT-LAB.md](docs/FINGERPRINT-LAB.md) for import limits, provenance, JSON,
and snapshot examples.

For coherent entropy-backed profiles use `TlsProfiles.CreateRandomized(...)`. For
bounded negotiation-alert retries with an origin-aware successful-profile cache, assign
a `TlsProfileRoller` to the session. Roller mode deliberately supports only direct DNS
origins with `PreferHttp2`; it rejects proxy/custom-DNS/exact-version routes instead of
bypassing them. The full contract is documented in
[docs/FINGERPRINT-LAB.md](docs/FINGERPRINT-LAB.md#origin-aware-roller).

`TlsHttpBehaviorProfile.Capture(...)` explicitly snapshots header-order and HTTP/2 wire
policy without capturing header values or credentials. Its strict bounded JSON can be
imported and applied independently of TLS, proxy, certificate, and retry configuration.

For diagnostics, `TlsFingerprintDiagnostics.InspectHandshake(...)` computes GREASE-aware
JA3 and JA4 values, while `TlsClientHello.Observe(...)` chains a pre-send observer onto
the exact SharpTls wire image. These identifiers describe selected structure; they are
not sufficient to reproduce a browser handshake.

## ECH DNS discovery

Assign a SharpTls `TlsEchDnsResolver` to `TlsSessionOptions.EchDnsResolver` to resolve
RFC 9848 HTTPS/SVCB metadata before the origin ClientHello. TlsClient follows the ordered
alternative targets, ports and IP hints while preserving the original certificate/SNI
identity and SharpTls downgrade policy. Plain DNS, authenticated managed DoT, and
authenticated managed DoH are supported by the SharpTls resolver. See
[docs/ECH-DNS.md](docs/ECH-DNS.md).

## Encrypted TLS session persistence

`ExportTls13SessionState` and `ImportTls13SessionState` move resumption tickets between
independent sessions using a caller-owned SharpTls `Tls13SessionStateProtector`. SharpTls
authenticates and encrypts the complete blob; TlsClient never exposes plaintext tickets
or owns persistence keys. Key rotation and ownership rules are in
[docs/SESSION-PERSISTENCE.md](docs/SESSION-PERSISTENCE.md).

## Client certificates and pins

`TlsSessionOptions.ClientCertificates` selects caller-owned SharpTls credentials by exact
host, wildcard, fallback, or the complete asynchronous SharpTls selector. Server SPKI pins
accept either `sha256/base64` text or an `X509Certificate2`; they are additional checks and
never bypass normal trust/hostname validation. See
[docs/CERTIFICATES.md](docs/CERTIFICATES.md).

## Handshake diagnostics and OpenTelemetry

`TlsSessionOptions.HandshakeObserver` reports immutable, secret-free SharpTls handshake
events with their origin and connection ID. `TlsDiagnostics.ActivitySourceName` exposes
physical HTTP request attempts, new connections, DNS/TCP/proxy stages, negotiated TLS
metadata, and handshake events to `ActivityListener` and OpenTelemetry. Query values,
headers, bodies, certificates, exception messages, and TLS secrets are never recorded.
See [docs/DIAGNOSTICS.md](docs/DIAGNOSTICS.md).

## HTTP/3 status

HTTP/3 is intentionally deferred. SharpTls `0.9.0-preview.4` supplies the TLS 1.3
state machine for a caller-owned QUIC transport, not UDP packets, loss recovery,
congestion control, streams, HTTP/3, or QPACK. `System.Net.Quic` uses native MsQuic and
platform TLS, so it cannot preserve this project's SharpTls-only ClientHello contract.
HTTP/3 requests are rejected rather than silently downgraded. The complete entry gate
and reevaluation criteria are in [docs/HTTP3-EVALUATION.md](docs/HTTP3-EVALUATION.md).

## API compatibility

The complete nullable public surface is checked by Roslyn Public API analyzers against
`PublicAPI.Shipped.txt`. An undeclared addition, removal, enum-value change, or signature
change fails the build. The review and semantic-versioning policy is documented in
[docs/API-COMPATIBILITY.md](docs/API-COMPATIBILITY.md).

## Fuzzing

The dependency-free `TlsClient.Fuzz` runner exercises HTTP/1.1 framing, HTTP/2 frame
headers, HPACK/Huffman, decompression, proxy replies, strict behavior JSON, ClientHello
diagnostics, and header validation. CI runs deterministic mutations; the same targets
accept minimized files from external process fuzzers. See
[docs/FUZZING.md](docs/FUZZING.md).

## Performance gates

Release-mode CI enforces explicit operations/second floors and bytes/operation ceilings
for HTTP/1.1 parsing/serialization, HPACK decoding, and ClientHello diagnostics. Budgets,
measurement semantics, and the policy for changing thresholds are in
[docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Security

The repository publishes a concrete [threat model](THREAT-MODEL.md), private
[vulnerability-reporting and disclosure process](SECURITY.md), and
[supported-version policy](docs/SUPPORTED-VERSIONS.md). Please never put an unpatched
vulnerability, exploit, credential, private key, or traffic secret in a public issue.

## Reproducible releases

Release packages use an exact SharpTls dependency, locked restores, portable Source Link
symbols, canonical NuGet archives, a validated SPDX SBOM, and GitHub build/SBOM
attestations. CI packs on Linux, macOS, and Windows and requires the normalized package
and symbol archives to be byte-identical across all three. The controls and verification
commands are documented in [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md); maintainers use
the tag ceremony in [docs/RELEASING.md](docs/RELEASING.md).

The 1.0 protocol-hardening gate is backed by a first-party, hostile-peer-oriented
maintainer review of HTTP/2 state, pooling, proxies, cookies, and redirects. Its scope,
resolved findings, regression tests, and release evidence live in
[docs/PROTOCOL-REVIEW.md](docs/PROTOCOL-REVIEW.md). Independent third-party review is
welcome, but it is not represented as a completed certification or required release
gate.

## Ordered headers

```csharp
var options = new TlsSessionOptions
{
    HeaderOrder = ["Host", "User-Agent", "Accept", "Accept-Encoding", "Cookie"],
};

await using var session = new TlsSession(options);
session.DefaultHeaders.Set("User-Agent", "my-agent/1.0");
session.DefaultHeaders.Set("Accept", "text/html");
session.DefaultHeaders.Add("Accept", "application/xhtml+xml");
```

`TlsHeaders` is case-insensitive and insertion-ordered. Per-request headers replace
session defaults of the same name. CR/LF injection and invalid HTTP tokens are rejected.

## HTTP CONNECT and SOCKS proxies

```csharp
await using var session = new TlsSession(new TlsSessionOptions
{
    Proxy = TlsProxy.Http("http://user:password@127.0.0.1:8080"),
});

var socks4 = TlsProxy.Socks4("socks4://user-id@127.0.0.1:1080");
var socks5 = TlsProxy.Socks5("socks5://user:password@127.0.0.1:1080");
```

HTTP credentials are sent only on CONNECT and never forwarded to the origin. SOCKS4a
and SOCKS5 pass hostnames to the proxy, avoiding local origin DNS. SOCKS5 supports
no-auth and username/password negotiation.

Override routing without creating another session:

```csharp
var requestOptions = TlsRequestOptions.For(request);
requestOptions.Proxy = socks5; // use this proxy
requestOptions.Proxy = null;   // explicitly bypass the session proxy
requestOptions.UseSessionProxy();
```

Direct, HTTP, SOCKS4, and SOCKS5 routes have separate pool keys. Proxy credentials are
hashed into that internal identity and never included in diagnostics or `ToString()`.

## Explicit retry policy

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
options.Retry.MaximumAttempts = 3;
options.Retry.StatusCodes.Add(HttpStatusCode.TooManyRequests);
options.Retry.StatusCodes.Add(HttpStatusCode.ServiceUnavailable);
options.Retry.Delay = TimeSpan.FromMilliseconds(200);
options.Retry.RespectRetryAfter = true;

await using var session = new TlsSession(options);
```

The default makes at most two attempts for eligible connection failures and does not
retry response status codes. Requests must be replayable and methods must be idempotent;
`RetryNonIdempotentMethods` is an explicit opt-in. Disable the policy for one request
with `TlsRequestOptions.For(request).EnableRetries = false`.

Streaming uploads are replayable only with `TlsRequestReplayPolicy.Buffer`. A streamed
response can retry only before the caller destination receives bytes; retry-status
bodies are drained separately so attempts never mix in the destination. See
[docs/RETRIES.md](docs/RETRIES.md).

## Rate limits and circuit breakers

TlsClient exposes attempt middleware instead of shipping a hidden limiter or breaker:

```csharp
options.RequestPolicies.Add(myRateLimitPolicy);
options.RequestPolicies.Add(myCircuitBreakerPolicy);
```

`ITlsRequestPolicy.OnAttemptStartingAsync` can asynchronously acquire a caller-owned
rate-limit lease or throw when a circuit is open. `OnAttemptCompletedAsync` runs in
reverse order with status/exception, duration, and retry intent so leases and breaker
state can be completed deterministically. Policy instances may be called concurrently.
See [docs/POLICIES.md](docs/POLICIES.md).

## Certificate pinning

```csharp
var options = new TlsSessionOptions();
options.CertificatePins.Add(
    "api.example.com",
    "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

await using var session = new TlsSession(options);
```

Pins are SHA-256 hashes of DER SubjectPublicKeyInfo. They run only after SharpTls has
completed normal chain and hostname validation, so pinning cannot be used to trust an
otherwise invalid certificate. Exact hosts and single-label `*.example.com` wildcards
are supported.

## Response model

`TlsResponse` contains:

- final URL, HTTP version, status, reason phrase, ordered headers, and trailers;
- bounded response bytes plus `Text` and `Json<T>()` helpers;
- redirect history and decompression state;
- TLS version, cipher suite, key-exchange group, ALPN, resumption/HRR/ECH flags, and
  defensive copies of the authenticated certificate chain.

## Current protocol behavior

- HTTPS only; secure certificate and hostname validation cannot be disabled.
- HTTP/2 with managed framing, HPACK/Huffman, ordered SETTINGS, CONTINUATION,
  multiplexing, flow control, cancellation/RST_STREAM, PING, GOAWAY, and trailers.
- HTTP/1.0 and HTTP/1.1 responses, with HTTP/1.1 requests and explicit ALPN fallback.
- Content-Length, chunked, no-body, and connection-close response framing.
- gzip, zlib/raw-deflate, and Brotli decompression with post-decompression limits.
- Bounded streaming uploads and downloads for HTTP/1.1 and HTTP/2, including chunked
  uploads, streaming decompression, caller-owned destinations, and backpressure.
- `Expect: 100-continue`, request/response trailers, and explicit bounded request replay.
- 301, 302, 303, 307, and 308 redirects; origin changes strip Authorization and
  caller-supplied Cookie headers.
- Bounded session-wide pooling with configurable per-origin and global connection
  limits. HTTP/2 requests multiplex and concurrent HTTP/1.1 requests can scale out.
- Connection lifetime, refreshed DNS, IPv6/IPv4 Happy Eyeballs, and structured
  DNS/TCP/proxy/SharpTls connection telemetry.
- HTTP CONNECT, SOCKS4/SOCKS4a, and SOCKS5 routes with per-request selection.
- Explicit bounded retries based on method idempotency, body replayability, selected
  status codes, connection failures, and bounded Retry-After.
- Composable per-attempt policy hooks for caller-owned rate limiting and circuit breaking.

## Build and test

```shell
dotnet tool restore
dotnet restore TlsClient.slnx --locked-mode
dotnet build TlsClient.slnx --configuration Release --no-restore
dotnet test TlsClient.slnx --configuration Release --no-build
dotnet run --project samples/TlsClient.QuickStart -- https://example.com/
```

The same commit is tested on Linux, macOS, and Windows. Parser fuzzing, performance
budgets, package reproducibility, Source Link, SPDX SBOM validation, and provenance
attestations are separate release gates.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md) before contributing. Security reports
must use the private process in [SECURITY.md](SECURITY.md), never a public issue.

The project roadmap is complete for the current preview; the next work is API feedback,
interoperability evidence, and fixes discovered by real users on the way to `1.0.0`.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for the adapted .NET Runtime
HPACK Huffman decoder notice.
