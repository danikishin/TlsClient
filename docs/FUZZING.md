# Parser and decompression fuzzing

`tools/TlsClient.Fuzz` is the bounded, dependency-free fuzz entry point for hostile
HTTP-facing inputs. It can replay one file for an external mutational fuzzer or run its
own deterministic CI smoke campaign.

## Targets

| Target | Boundary |
|---|---|
| `http1-response` | status line, headers, informational responses, content length, chunk framing, trailers, and close-delimited bodies |
| `http2-frame` | the production 9-byte frame-header parser and maximum-frame-size gate |
| `hpack` | HPACK integers, strings, Huffman input, indexes, dynamic-table updates, and header-list limits |
| `decompression` | gzip, zlib/raw deflate fallback, Brotli, truncation, invalid coding, and decoded-size limit |
| `proxy-http` | HTTP CONNECT status/header parsing and bounds |
| `proxy-socks4` | SOCKS4 reply parsing and truncation |
| `proxy-socks5` | method, authentication, CONNECT reply, address type/length, and truncation |
| `behavior-json` | strict HTTP-behavior JSON, duplicate fields, depth, size, enums, and numeric ranges |
| `clienthello` | diagnostic ClientHello framing and extension parsing delegated to SharpTls |
| `headers` | request/response header name and value validation, including CR/LF injection |

The HTTP/2 header target is the same `Http2FrameParser.ParseHeader` called by the live
connection. Stateful frame sequencing, stream transitions, SETTINGS, flow control,
CONTINUATION, GOAWAY, and malformed-peer behavior remain covered by deterministic
loopback/fixture tests; a future state-machine fuzzer must not replace those assertions.

## Deterministic smoke campaign

```bash
dotnet run --project tools/TlsClient.Fuzz -c Release -- --smoke 25000
```

The runner starts from a valid seed for every target and performs reproducible length
and byte mutations. CI runs 25,000 cases on each change and a larger scheduled campaign.
Known parser rejection exceptions are treated as normal. Indexing, null-reference,
access-violation, resource-exhaustion, and other unexpected failures terminate with a
non-zero exit code and preserve the failing CI context.

## External fuzzer/reproducer mode

Every target accepts one file of at most 64 KiB:

```bash
dotnet run --project tools/TlsClient.Fuzz -c Release -- \
  hpack ./corpus/crash-input.bin
```

An external process fuzzer can repeatedly invoke this form and treat a non-zero exit as
a finding. Before filing an issue, minimize the input, reproduce in Release, record the
target, operating system, architecture, .NET SDK/runtime, TlsClient commit, SharpTls
version, and whether the failure is deterministic. Fuzz findings that may be exploitable
follow `SECURITY.md`, not a public issue.

All targets cap input and parser output. The harness must never disable production
limits merely to increase coverage; add small injectable limits when a new parser needs
direct fuzz access.
