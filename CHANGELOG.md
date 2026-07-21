# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) and keeps preview releases explicitly
versioned.

## [Unreleased]

No unreleased changes yet.

## [0.5.0-preview.1] - 2026-07-21

The first complete TlsClient preview, rebuilt from the original prototype around the
managed [SharpTls](https://github.com/danikishin/SharpTls) stack.

### Highlights

- Managed HTTP/1.1 and HTTP/2 with HPACK/Huffman, flow control, multiplexing,
  CONTINUATION, PING, RST_STREAM, GOAWAY, trailers, and graceful draining.
- Coherent Chrome 133, Firefox 148, and OkHttp/Android 11 TLS + HTTP behavior presets.
- Session cookies, redirects, bounded decompression, connection pooling, DNS refresh,
  Happy Eyeballs, streaming, retries, and policy integration points.
- HTTP CONNECT, SOCKS4/SOCKS4a, and SOCKS5 proxies with per-request routing.
- ClientHello capture/import, deterministic fingerprint fixtures, JA3/JA4 diagnostics,
  profile rolling, ECH DNS discovery, protected session persistence, client
  certificates, pins, and OpenTelemetry activities.
- Public API baseline, 108 deterministic tests, parser/decompression fuzz targets,
  allocation and throughput budgets, and hostile-peer protocol review evidence.
- Deterministic NuGet and symbol packages with Source Link, SPDX 2.2 SBOM, and GitHub
  artifact attestations.

### Known boundaries

- Targets .NET 9 and pins `SharpTls 0.9.0-preview.4`.
- HTTP/3 remains deferred until a compatible complete QUIC transport exists.
- Certificate and hostname validation cannot be disabled through this release.
- Preview APIs may change before `1.0.0`.

[Unreleased]: https://github.com/danikishin/TlsClient/compare/v0.5.0-preview.1...HEAD
[0.5.0-preview.1]: https://github.com/danikishin/TlsClient/releases/tag/v0.5.0-preview.1
