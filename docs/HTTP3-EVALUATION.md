# HTTP/3 transport-readiness evaluation

Decision date: 2026-07-21
Decision for: TlsClient `0.6.0-preview` with SharpTls `0.9.0-preview.5`
Outcome: **deferred; HTTP/3 is not implemented or advertised**

## Why the current components are insufficient

SharpTls provides a recordless QUIC-TLS state machine. Its package documentation and
API contract explicitly leave UDP packets, packet numbers, header/payload protection,
CRYPTO frames, Retry, loss recovery, congestion control, connection IDs, migration,
streams, and `HANDSHAKE_DONE` to a caller-owned QUIC transport. HTTP/3 and QPACK are
also outside SharpTls. TLS handshake completion therefore does not mean a QUIC
connection is usable.

`.NET 9` has a stable `System.Net.Quic` API, but it is backed by native MsQuic and takes
`SslClientAuthenticationOptions`. It does not expose a boundary for replacing its TLS
engine with `SharpTls.Quic.CustomTlsQuicClient`. Using it would violate this project's
SharpTls-only transport and byte-exact ClientHello guarantees. It would also introduce
MsQuic/OpenSSL/SChannel platform dependencies and a materially different fingerprint
surface.

No independent, complete QUIC transport compatible with the SharpTls recordless API is
pinned by this repository. Building only enough packets to pass a happy-path demo would
not meet the security, interoperability, congestion, loss, and hostile-input standards
used by the HTTP/1.1 and HTTP/2 implementations.

## Required entry gate

HTTP/3 work may start only when a candidate transport satisfies all of these conditions:

1. It accepts caller-owned SharpTls handshake bytes and traffic secrets without invoking
   platform TLS or replacing the selected ClientHello.
2. QUIC v1 packet parsing/protection, packet-number recovery, ACK/loss/PTO, congestion
   control, Retry, connection IDs, flow control, stream state, key discard/update,
   connection close, and transport-parameter validation are implemented with strict
   bounds. QUIC v2 is separately declared and tested if exposed.
3. It has independent unit/fuzz testing and interoperability evidence against at least
   two established QUIC implementations under reordering, duplication, loss, and
   malformed input—not only localhost success cases.
4. The HTTP/3 layer implements control streams, SETTINGS, request streams, QPACK,
   GOAWAY, cancellation, priorities when selected, response limits, and graceful
   draining without routing through `HttpClient`.
5. Pooling, DNS/ECH, proxy policy, retries, redirects, cookies, streaming, telemetry,
   resumption, and 0-RTT replay policy have explicit HTTP/3 semantics.
6. Linux, macOS, and Windows CI can run deterministic protocol tests, with public
   interoperability smoke tests isolated from the offline suite.
7. A focused independent security review covers packet parsing, loss recovery, stream
   state, QPACK, amplification, resource exhaustion, and 0-RTT replay behavior.

## Current API behavior

TlsClient accepts HTTP/1.1 and HTTP/2 request versions. An HTTP/3 request is rejected
with `NotSupportedException`; it is never silently downgraded and no `h3` ALPN is
advertised. This preserves the project's rule that wire behavior cannot change silently.

Relevant primary documentation:

- the SharpTls NuGet package's bundled `docs/QUIC-TLS.md` for the exact pinned adapter
  contract;
- Microsoft's [.NET QUIC overview](https://learn.microsoft.com/dotnet/fundamentals/networking/quic/quic-overview)
  for the native MsQuic implementation and platform dependencies;
- [`QuicClientConnectionOptions.ClientAuthenticationOptions`](https://learn.microsoft.com/dotnet/api/system.net.quic.quicclientconnectionoptions.clientauthenticationoptions?view=net-9.0)
  for the platform TLS configuration boundary.

The gate should be revisited when the pinned SharpTls version changes or a credible
compatible managed QUIC transport becomes available. Deferral is a protocol-integrity
decision, not a permanent rejection of HTTP/3.
