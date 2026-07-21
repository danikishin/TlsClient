# Diagnostics and OpenTelemetry

TlsClient exposes two complementary diagnostics surfaces without adding an
OpenTelemetry package dependency:

- immutable callback records for connection and TLS handshake events;
- `System.Diagnostics.ActivitySource` spans and events that OpenTelemetry can collect.

Both surfaces are opt-in. With no observer or `ActivityListener`, the tracing helpers do
not create an `Activity`.

## Structured handshake events

`HandshakeObserver` enriches SharpTls's secret-free handshake events with the original
origin and a connection identifier:

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
options.HandshakeObserver = item => Console.WriteLine(
    $"{item.ConnectionId} #{item.SequenceNumber} {item.Kind} " +
    $"{item.Direction} {item.ProtocolVersion} {item.EncodedLength}");
```

The callback receives classification, direction, protocol version, encoded length, and
ClientHello flight. It never receives handshake bytes, randoms, key shares, transcript
hashes, traffic secrets, session tickets, or certificate contents. Callbacks are
serialized within one SharpTls connection but may run concurrently across pooled
connections. TlsClient catches callback exceptions so instrumentation cannot break a
request.

An advanced `HandshakeEventObserver` assigned through `ConfigureTls` is preserved and
runs first. That raw SharpTls observer retains SharpTls's documented behavior: throwing
aborts the handshake. This lets protocol test tools deliberately enforce invariants
without weakening the safe default callback.

## ActivitySource

Register the stable source name with an OpenTelemetry tracer provider:

```csharp
services.AddOpenTelemetry()
    .WithTracing(tracing => tracing.AddSource(TlsDiagnostics.ActivitySourceName));
```

TlsClient emits:

- one client `Activity` per physical HTTP request attempt, named with its normalized
  method (`GET`, `POST`, and so on);
- a child `tlsclient.connect` activity only when a new physical connection is needed;
- DNS, TCP, proxy, TLS-stage, and redacted SharpTls handshake events on the connection
  activity.

HTTP activities use current OpenTelemetry semantic keys such as
`http.request.method`, `server.address`, `server.port`, `url.full`,
`http.response.status_code`, `network.protocol.name`, `network.protocol.version`, and
`error.type`. Connection activities add the development TLS convention keys
`tls.protocol.name`, `tls.protocol.version`, `tls.cipher`, `tls.curve`, and
`tls.resumed`, plus `tlsclient.*` details for profile, ALPN, ECH, retries, redirects, and
handshake stages.

The emitted `url.full` preserves scheme, authority, and path but replaces the entire
query with `REDACTED` and removes user information and fragments. TlsClient never emits
header values, cookies, bodies, certificate bytes, exception messages, keys, or TLS
secrets. Status/error tags contain only numeric HTTP status or exception type.

Activity duration covers the physical request through response processing. A redirect
or retry creates another HTTP activity; `tlsclient.retry.attempt` and
`tlsclient.redirect.hop` identify its position. A reused connection produces no new
connection activity.

The attribute names follow the official
[OpenTelemetry HTTP span conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/)
and [TLS attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/tls/).
TLS attributes are currently marked development by OpenTelemetry, so consumers should
expect that external convention—not TlsClient's public .NET API—to evolve.

## Connection callback

`ConnectObserver` remains useful without a tracing backend:

```csharp
options.ConnectObserver = item => Console.WriteLine(
    $"{item.ConnectionId} {item.Kind} {item.Address} {item.Elapsed}");
```

See [CONNECTIVITY.md](CONNECTIVITY.md) for DNS cache, Happy Eyeballs, proxy route, and
cancellation semantics.
