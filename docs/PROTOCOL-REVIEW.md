# Protocol review and release evidence

Status: **maintainer review complete for `0.5.0-preview.1`**.

This is a first-party, source-assisted, hostile-peer-oriented review of the protocol
and request lifecycle code that forms the final 1.0 hardening gate. It is not an
independent audit or certification. Independent third-party review remains welcome,
and suspected vulnerabilities must follow `SECURITY.md`, but neither is represented as
a completed external sign-off or required release gate.

## Review method

The maintainer traced state ownership, bounds, cancellation, timeout, failure, and
cleanup paths in the production implementation. Confirmed defects were fixed with a
targeted regression test. The review was then backed by the complete test suite,
repeated protocol stress runs, deterministic parser fuzzing, performance budgets, and
the reproducible-package checks described below.

The evidence is commit-bound when run by CI. A release maintainer must repeat the
commands in this document on the exact release commit and retain the workflow URL and
artifact digests with the release record.

## HTTP/2 state and HPACK

Reviewed properties:

- frame lengths, stream identifiers, reserved bits, continuation sequencing, and
  frame/stream legality fail in the correct connection or stream scope;
- SETTINGS validation, acknowledgement, initial-window deltas, integer overflow, and
  concurrent-stream capacity remain bounded and wake blocked senders;
- stream lifecycle covers local/remote half-close, early final responses, RST_STREAM,
  GOAWAY, trailers, response completion, and graceful drain;
- HPACK integer/string/Huffman decoding, table eviction, table-size updates, header-list
  accounting, and compressed header-block accumulation are bounded; and
- flow-control credit, cancellation, and error propagation cannot corrupt another
  stream or leave an upload indefinitely blocked.

Primary entry points: `Http2Connection`, `Http2StreamState`, `Http2FrameParser`,
`HpackDecoder`, `Http2LoopbackTests`, captured wire fixtures, and the `http2-frame` and
`hpack` fuzz targets.

## Pooling and DNS/connect races

Reviewed properties:

- pool keys include the origin, proxy, TLS/profile state, HTTP policy, and
  client-certificate identity that affect trust or wire behavior;
- origin/global limits, idle and lifetime expiry, eviction, connection reuse, and
  concurrent disposal do not leak permits, sockets, or cross-origin state;
- first-connect coalescing and Happy Eyeballs cancellation publish only a fully
  initialized winning connection; and
- GOAWAY, DNS refresh, retry, request completion, and shutdown paths preserve request
  ownership and wake capacity waiters.

Primary entry points: `TlsConnectionPool`, `ConnectionKey`, `DnsEndpointResolver`,
`HappyEyeballsConnector`, `ConnectionPoolLoopbackTests`, `NetworkConnectorTests`, and
the connection telemetry tests.

## Proxy protocols

Reviewed properties:

- HTTP CONNECT bounds and validates the response and never forwards proxy credentials
  to the destination;
- SOCKS4/4a and SOCKS5 validate versions, methods, address types, lengths, status,
  authentication, and caller-selected DNS behavior;
- proxy identity participates in pool keys, and redirect/retry cannot bypass the
  selected proxy or silently alter local versus remote DNS behavior; and
- cancellation and failure dispose the incomplete tunnel without falling back across
  the proxy trust boundary.

Primary entry points: `ProxyTunnel`, `TlsProxy`, `ProxyTunnelTests`, proxy selection
tests, and the `proxy-http`, `proxy-socks4`, and `proxy-socks5` fuzz targets.

## Cookies and redirects

Reviewed properties:

- domain, path, secure, expiry, and origin rules use `CookieContainer` without
  cross-origin or cleartext disclosure;
- redirect targets, schemes, and counts are validated and bounded;
- `Authorization`, `Proxy-Authorization`, manual `Cookie`, `Host`, and content headers
  are stripped or rebuilt at the correct origin and method transitions;
- 301/302/303 rewriting and 307/308 replay obey the documented body replay policy; and
- redirect loops, cancellation, decompression, retry, and response disposal preserve
  connection ownership.

Primary entry points: `TlsSession`, `BufferedRequest`, `Http11RequestWriter`, cookie and
redirect loopback tests, streaming replay tests, and the attacker stories in
`THREAT-MODEL.md`.

## Findings resolved during review

- Origin-changing redirects now suppress session-default `Authorization`, manual
  `Cookie`, and `Host` values in addition to per-request values while still allowing
  the destination's `CookieContainer` cookies.
- Compressed HEADERS/PUSH_PROMISE plus CONTINUATION blocks are bounded before an HPACK
  decode allocation can grow beyond the response-header limit.
- A final HTTP/2 response cancels a blocked streaming upload, emits
  `RST_STREAM(CANCEL)` for the unfinished request side, and returns the valid response.
- Flow-control senders and stream-slot waiters are awakened on response completion,
  RST_STREAM, GOAWAY, read failure, and SETTINGS capacity changes.
- Idle-stream RST_STREAM/WINDOW_UPDATE, invalid push association/order, and more than
  1024 outstanding rejected push streams fail the connection.
- SOCKS5 replies containing a zero-length domain address are rejected.

Targeted regression tests include
`Redirect_StripsOriginBoundSessionHeadersWhenOriginChanges`,
`Socks5_RejectsEmptyBoundDomain`,
`EarlyFinalResponse_CancelsFlowControlledUploadWithoutHanging`, and
`OversizedCompressedHeaderBlock_FailsBeforeContinuationBufferGrows`.

## Required release evidence

Run from a clean checkout of the candidate commit:

```bash
dotnet tool restore
dotnet restore TlsClient.slnx --locked-mode
dotnet format whitespace --folder . --verify-no-changes
dotnet build TlsClient.slnx --configuration Release --no-restore
dotnet test TlsClient.slnx --configuration Release --no-build
dotnet run --project tools/TlsClient.Fuzz --configuration Release \
  --no-build -- --smoke 25000
dotnet run --project tools/TlsClient.Performance --configuration Release \
  --no-build -- --verify
```

The completed maintainer run for this preview includes:

- a warning-free Release build and all 108 tests passing;
- 10 consecutive runs of the 13 critical protocol/pool/proxy/session tests, for 130
  successful stress invocations;
- 25,010 deterministic fuzz cases across all parser/decompression boundaries;
- all four allocation and throughput budgets passing; and
- two independently packed and normalized `.nupkg`/`.snupkg` pairs comparing
  byte-for-byte, followed by Source Link metadata and SPDX 2.2 SBOM validation.

Linux, macOS, and Windows CI must repeat the cross-platform build/test/package matrix
for the release commit. GitHub release jobs bind provenance and SBOM attestations to the
published artifact bytes; local evidence does not substitute for those hosted checks.

## Residual review posture

No source review proves the absence of defects. The bounded parsers, limits, threat
model, disclosure process, deterministic regressions, fuzz campaign, and release
checks are complementary controls. New findings require a regression test and an
update to this document when they change the reviewed guarantees. Optional external
review may add evidence, but it does not change the meaning of this first-party record.
