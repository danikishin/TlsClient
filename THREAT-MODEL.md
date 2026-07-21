# TlsClient threat model

## Overview

TlsClient is an embeddable .NET 9 HTTPS client. It uses SharpTls as its only TLS engine
and implements HTTP/1.1, HTTP/2, HPACK, pooling, cookies, redirects, decompression,
proxies, retries, streaming, profile import/inspection, and diagnostics in managed C#.
Applications use it inside their own process and security identity; TlsClient is not a
standalone service, authorization system, browser sandbox, anonymity network, or SSRF
policy engine.

The primary runtime surface is `src/TlsClient`. `samples/` is demonstration code;
`tools/TlsClient.ProfileCatalog`, `tools/TlsClient.Fuzz`, and
`tools/TlsClient.Performance` are developer/release tools and are not loaded by package
consumers. Tests, documentation, and GitHub workflows affect release assurance and
supply-chain integrity but are not production network listeners.

The assets that matter are:

- confidentiality and integrity of HTTPS request/response bodies, cookies,
  authorization headers, proxy credentials, and application metadata;
- server identity, certificate-chain/hostname validation, optional SPKI pins, and
  correct client-certificate selection;
- client private keys and external signer handles, TLS traffic secrets, resumption
  tickets, and caller-owned state-protection keys;
- isolation between origins, proxies, credentials, HTTP/2 streams, sessions, and
  concurrent callers;
- protocol and fingerprint integrity: the selected ClientHello, ALPN, HTTP version,
  header order, settings, retry, redirect, and proxy behavior must not silently change;
- process availability and bounded CPU, memory, socket, task, and pool consumption;
- integrity of the NuGet package, symbols, source provenance, and pinned SharpTls
  dependency.

## Threat Model, Trust Boundaries, and Assumptions

### Trust boundaries and actors

1. **Application caller to TlsClient.** The caller controls URLs, methods, headers,
   content streams, limits, profiles, proxy selection, custom DNS, policies,
   certificates, pins, callbacks, and `ConfigureTls`. These are operator-controlled,
   trusted configuration from TlsClient's perspective, but may contain application bugs
   or data derived from a less-trusted user.
2. **TlsClient to origin network.** DNS answers, TCP behavior, TLS records, HTTP bytes,
   redirects, compressed bodies, trailers, HTTP/2 frames, timings, truncation, and
   connection closes are attacker-controlled. A hostile origin or on-path attacker can
   fragment, reorder at the transport level, delay, duplicate through reconnects, and
   send malformed or adversarially large data.
3. **TlsClient to proxy.** An HTTP CONNECT, SOCKS4/4a, or SOCKS5 proxy sees routing
   metadata and can return arbitrary negotiation bytes, delay traffic, misroute a
   tunnel, observe its own credentials, or terminate connections. The TLS origin
   identity remains end-to-end SharpTls state after the tunnel.
4. **DNS/ECH discovery.** The OS resolver, a custom resolver, or a caller-configured
   SharpTls protected-DNS resolver supplies attacker-influenceable addresses and service
   parameters according to its authentication policy. IP hints are non-authoritative;
   ECH target/port selection must preserve the original SNI, certificate identity, and
   HTTP authority.
5. **TlsClient to SharpTls/runtime/OS.** TlsClient assumes the pinned SharpTls package
   correctly implements TLS, PKIX/hostname validation, secret erasure, tickets, ECH,
   ClientHello encoding, and certificate APIs. It assumes .NET cryptography,
   compression, sockets, `CookieContainer`, and the OS trust store satisfy their
   documented contracts. Vulnerabilities below this boundary may still affect users but
   should be fixed in the owning component.
6. **Caller-owned secrets and persistence.** Client credentials, HSM/KMS signers,
   `Tls13SessionStateProtector`, its key ring, exported encrypted state, telemetry sinks,
   and output streams remain caller-owned. TlsClient must not dispose or serialize them
   unexpectedly. The caller must protect their lifetime, storage, access, and logs.
7. **Build and release supply chain.** Contributors, GitHub Actions, the .NET SDK, NuGet,
   SharpTls, analyzer/test dependencies, release credentials, and generated artifacts
   cross a developer-controlled trust boundary. A compromised dependency or workflow
   can affect every consumer even when runtime parsing is correct.

### Attacker-controlled inputs

- all bytes received from origins and proxies, including partial reads and EOF;
- DNS addresses and, subject to resolver authentication, HTTPS/SVCB/ECH endpoint data;
- status/header text, content lengths, chunk sizes/extensions, compressed data, HTTP/2
  frame headers/payloads, HPACK indexes/Huffman strings/table updates, SETTINGS, flow
  control, push, continuation, reset, and GOAWAY sequences;
- redirect targets, cookie attributes, retryable status codes, and timing behavior;
- imported behavior JSON or captured ClientHello bytes when an application exposes
  those helpers to untrusted data;
- encrypted persisted-session blobs read from untrusted storage.

Application/operator-controlled inputs include request URLs and bodies, default and
per-request headers, proxy credentials, custom resolver answers, trust roots, pins,
client certificates, callbacks, limits, retry opt-ins, and arbitrary SharpTls changes
made through `ConfigureTls`. Repository/developer-controlled inputs include source,
project files, dependencies, CI actions, package metadata, and release secrets. The
explicit dangerous server-validation bypass is also application/operator-controlled.

### Security invariants

- Only `https://` is accepted. No native/platform TLS fallback, plaintext origin mode,
  HTTP/3 claim, or silent ALPN/HTTP-version downgrade is allowed.
- Certificate-chain and hostname validation are enabled by default. Only the explicit
  dangerous caller option or the advanced SharpTls hook can bypass them; pins remain
  enforced but do not recreate skipped PKIX checks. The original origin identity
  survives proxy and ECH alternative routing.
- A connection is pooled only into the matching origin, HTTP policy, proxy endpoint,
  proxy credential identity, and relevant configuration partition. HTTP/2 stream state
  and cancellation remain isolated.
- Cross-origin redirects remove `Authorization`, explicit `Cookie`, and `Host`; session
  cookies follow `CookieContainer` scope. Redirects and retries are bounded.
- Non-idempotent or non-replayable bodies are never retried unless the caller explicitly
  authorizes the applicable policy; streaming bodies are not replayed implicitly.
- Header/body/frame/decompression/parser/pool/DNS-cache/concurrency limits are enforced
  before large allocation or unbounded work. Malformed peer data fails closed.
- Proxy credentials are sent only to the selected proxy negotiation, omitted from
  string representations/telemetry, and included in pool partitioning by a one-way
  identity hash.
- TLS tickets are plaintext only inside SharpTls memory. Exported TLS 1.3 session state
  is authenticated and encrypted by a caller-owned protector; imports are atomic.
- Diagnostics never include header/body/cookie/certificate bytes, query values, traffic
  secrets, session tickets, or exception messages. Explicit raw SharpTls hooks retain
  their separately documented power and risk.
- Disposal and cancellation close or retire affected resources deterministically and
  do not convert truncation into successful EOF.

### Assumptions and exclusions

TlsClient cannot protect against a fully compromised application process, runtime,
kernel, machine administrator, trusted root CA, caller-provided proxy, client private
key, persistence key, or CI release credential. A caller that deliberately enables a
SharpTls dangerous key log, leaks credentials in its own callback, installs malicious
trust roots, or forwards secrets to an attacker has crossed the library's trust boundary.

Sending a caller-selected URL is the library's purpose. Network access policy, private
address denial, tenant authorization, and SSRF prevention belong to the embedding
application; TlsClient must still prevent cross-origin credential leakage and route/pool
confusion. Fingerprint profiles improve wire control but do not promise anonymity,
anti-bot bypass, browser equivalence, censorship resistance, or protection from traffic
analysis.

## Attack Surface, Mitigations, and Attacker Stories

### HTTP/1.1 parsing, framing, and smuggling

A hostile server or proxy can send ambiguous status lines, duplicate or conflicting
lengths, transfer codings, folded headers, control characters, chunk extensions,
trailers, informational-response floods, or truncation. A framing error could poison a
reused connection and expose one caller's response to another request. The reader
requires CRLF, strict versions/status, bounded header bytes/count, unambiguous supported
framing, exact body length/chunk terminators, bounded informational responses, and marks
close-delimited or failed connections non-reusable. Parser tests and the
`http1-response` fuzz target cover this boundary.

### HTTP/2, HPACK, multiplexing, and flow control

An attacker can use malformed frames, continuation interleaving, invalid stream IDs,
oversized frames/header lists, dynamic-table abuse, Huffman bombs, flow-control
under/overflow, push, reset races, or GOAWAY timing to corrupt streams or exhaust the
process. The implementation bounds frame/header/body/table sizes, validates state and
stream ownership, isolates per-stream cancellation, tracks connection/stream windows,
rejects push data, drains GOAWAY, and fails all affected streams on connection errors.
Deterministic malformed-peer fixtures, HPACK tests, and frame/HPACK fuzz targets are
security controls. This remains a highest-priority independent-review surface.

### Decompression and streaming

Small gzip/deflate/Brotli bodies can expand into memory or CPU exhaustion; stacked
encodings and corrupt streams can trigger fallback edge cases. Decoding is output
bounded, cancellation-aware, and applied in reverse encoding order. Streaming preserves
backpressure and a caller-selected buffer limit. Invalid compressed data fails instead
of returning unauthenticated partial output. The decompression fuzz target covers each
supported decoder and the deflate fallback.

### Redirects, cookies, retries, and application secrets

A hostile origin can redirect to another authority to steal bearer credentials, set
broad cookies, induce loops, or make an unsafe request replay. TlsClient caps redirects,
strips credential-bearing request headers on origin changes, delegates cookie scope to
`CookieContainer`, and applies explicit replayability/idempotency gates. Applications
remain responsible for deciding which initial URLs, cookies, and non-idempotent retry
overrides are authorized.

### DNS, ECH, proxies, and pool partitioning

DNS rebinding, malicious IP hints, proxy negotiation confusion, credential cross-talk,
or reusing a tunnel for another route could cross trust boundaries. DNS results are
validated, copied, capped, cached with bounded LRU lifetime, and raced with cancellation.
Proxy routes resolve the proxy locally and carry the origin through the selected
protocol. Pool keys separate proxy type/address/credential identity. ECH DNS follows
SharpTls's authenticated/fallback endpoint set while retaining original SNI and
certificate/HTTP identity. IP hints are attempted before authoritative resolution but
do not redefine trust identity.

### Certificates, client authentication, and resumption

The most damaging failures would accept an invalid server identity, send a client
certificate to the wrong origin, weaken normal validation unintentionally, or import
tampered tickets. SharpTls performs chain/hostname validation by default; only explicit
dangerous caller configuration bypasses it, while the pin hook still runs. Exact and
one-label wildcard selection precede a caller-owned default;
configuration conflicts fail rather than guessing precedence. Credentials remain
caller-owned. Session export requires authenticated encryption and atomic import, with
key rotation controlled by the caller. TLS 1.2 state is not persisted because SharpTls
does not expose a safe client persistence contract.

### Resource exhaustion and concurrency

Attackers can hold connections/streams open, delay DNS/proxy/TLS/headers/bodies, create
many origins, force reconnects, or race cancellation/disposal. End-to-end timeouts,
caller cancellation, bounded per-origin/global pools, idle/lifetime expiry, DNS cache
limits, header/body/frame limits, and deterministic disposal constrain this. Application
rate limiting and circuit breaking are explicit policy integration points because one
universal hidden policy would be unsafe.

### Diagnostics and privacy

Telemetry sinks are an exfiltration boundary. Structured callbacks expose address,
stage, lengths, enum values, elapsed time, negotiated metadata, and exception objects to
the caller. OpenTelemetry redacts query values and omits header/body/cookie/certificate
bytes and exception messages. The raw `Exception` object on the direct callback is
trusted-caller data and must not be forwarded blindly. Observer failures are ignored;
an explicitly configured raw SharpTls handshake observer may abort by design.

### Profile/import and developer tooling

Imported JSON/capture bytes can trigger parser or allocation bugs. Documents have size,
depth, duplicate-property, count, enum, and range limits; ClientHello diagnostic input is
bounded and parsed by SharpTls/TlsClient strict readers. The profile catalog, fuzz, and
performance tools consume local developer inputs and do not run in consumer processes.
If CI is allowed to process untrusted corpora, artifacts must not contain secrets.

### Supply chain and release

A malicious SharpTls/package/action update or stolen NuGet credential can compromise all
users. Dependencies and SDK feature band are pinned with lock files; CI builds/tests on
Linux, macOS, and Windows; API compatibility, format, fuzz, performance, package
contents, Source Link, SBOM, and provenance are release gates. Release workflows must
use least-privilege permissions, protected environments, short-lived GitHub identity
where supported, and never execute pull-request code with publishing secrets.

## Severity Calibration (Critical, High, Medium, Low)

### Critical

- remotely exploitable arbitrary code execution or memory corruption in normal client
  use, including a dependency boundary reachable from attacker-controlled network data;
- package/release compromise that distributes attacker-controlled binaries or steals
  signing/publishing credentials;
- extraction of client private keys, TLS traffic secrets, or persistence-protector keys
  without an explicit dangerous caller action;
- universal certificate/hostname-validation bypass affecting default connections.

### High

- cross-origin/proxy/pool confusion that sends authorization, cookies, client
  certificates, or decrypted bodies to the wrong peer;
- HTTP framing or HTTP/2 stream-state confusion that crosses requests or accepts
  attacker-controlled response data as another stream;
- remotely triggered, practical unbounded memory/CPU/socket exhaustion under default
  limits;
- tampered persisted session state accepted as authentic, or a pin helper weakening
  normal trust validation;
- silent fallback away from SharpTls or the selected HTTPS identity/version contract.

### Medium

- bounded but disproportionate remote CPU/memory consumption requiring repeated input;
- denial of service limited to one session/origin/connection rather than the process;
- sensitive URL query/header/certificate data emitted by default diagnostics without
  exposing keys or bodies;
- unsafe retry/redirect behavior requiring a non-default caller opt-in but violating its
  documented guard;
- profile/import confusion that changes wire behavior without crossing server identity.

### Low

- inaccurate non-secret diagnostic metadata, low-impact exception inconsistency, or a
  minor resource leak recovered by session disposal;
- fingerprint mismatch without confidentiality, integrity, authentication, or material
  availability impact;
- developer-tool failure that cannot affect produced packages or consumer runtime;
- attacks requiring a caller to deliberately provide malicious code through trusted
  callbacks, compromise its own process, or expose secrets outside TlsClient's contract.

Severity may move upward when an issue is default, cross-origin, remotely triggerable,
repeatable, and affects many concurrent sessions; it may move downward when exploitation
requires explicit dangerous configuration, process compromise, or violates the stated
embedding assumptions.
