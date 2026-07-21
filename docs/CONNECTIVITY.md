# Connectivity and connection telemetry

TlsClient owns TCP connection establishment while SharpTls owns the TLS handshake. The
session keeps these layers explicit and bounded:

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
options.MaximumConnectionsPerOrigin = 6;
options.MaximumPooledConnections = 64;
options.PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2);
options.PooledConnectionLifetime = TimeSpan.FromMinutes(10);
options.DnsRefreshInterval = TimeSpan.FromMinutes(5);
options.MaximumDnsCacheEntries = 256;
options.HappyEyeballsDelay = TimeSpan.FromMilliseconds(250);
```

An idle timeout removes a connection only while it has no leased requests. A lifetime
expiry prevents new leases immediately; active HTTP/2 streams may finish before the old
connection is closed. The replacement connection performs a fresh DNS lookup when the
cached answer has also expired.

## DNS and Happy Eyeballs

Hostname answers are copied, filtered to IPv4/IPv6, de-duplicated, capped at 64 addresses,
and cached at session scope. The hostname cache is LRU-bounded by
`MaximumDnsCacheEntries`. Failed lookups are not cached. IP-literal URLs bypass DNS. When
an HTTP CONNECT proxy is configured, TlsClient resolves and connects to the proxy; the
origin hostname is carried inside CONNECT and is not resolved locally.

Resolved IPv6 and IPv4 addresses are interleaved without changing order inside either
family. The first address starts immediately. Another address starts after
`HappyEyeballsDelay`, or immediately when an earlier attempt fails. Once a connection
wins, losing sockets are cancelled and disposed.

A custom resolver can integrate service discovery or a caller-owned DNS client:

```csharp
options.DnsResolver = async (host, cancellationToken) =>
    await serviceDiscovery.ResolveAsync(host, cancellationToken);
```

The resolver must return at least one IPv4 or IPv6 address. Request cancellation flows
through DNS, racing TCP attempts, proxy CONNECT, and the SharpTls handshake.

## Telemetry

`ConnectObserver` receives synchronous immutable `TlsConnectEvent` values. It may be
called concurrently by racing connections, so the callback must be thread-safe. Observer
exceptions are ignored so diagnostics cannot break a request.

```csharp
options.ConnectObserver = item =>
{
    Console.WriteLine(
        $"{item.ConnectionId} {item.Kind} {item.Host}:{item.Port} " +
        $"{item.Address} {item.Elapsed}");
};
```

Events sharing a `ConnectionId` belong to one connection attempt. Available stages are:

- DNS cache hit, resolution start/completion/failure;
- TCP attempt start/failure and the selected address;
- proxy tunnel start/completion/failure;
- SharpTls handshake start/completion/failure, including negotiated ALPN on completion.

`Exception` is populated only for failure events. Telemetry reports no proxy credentials,
cookies, request headers, TLS secrets, session tickets, or response data.

The same stages are added as events to the `tlsclient.connect` activity when an
`ActivityListener` subscribes to `TlsDiagnostics.ActivitySourceName`. Structured
secret-free handshake events and OpenTelemetry tag/redaction rules are documented in
[DIAGNOSTICS.md](DIAGNOSTICS.md).

## Proxy routes

The session default may be HTTP CONNECT, SOCKS4/SOCKS4a, or SOCKS5:

```csharp
options.Proxy = TlsProxy.Socks5("socks5://user:password@127.0.0.1:1080");
```

TlsClient resolves only the proxy endpoint locally. HTTP CONNECT carries the origin in
the CONNECT authority; SOCKS4a and SOCKS5 carry its IDN ASCII hostname in their tunnel
request. IPv4 and IPv6 literals use the protocol's binary address form. SOCKS4 rejects
IPv6 literals because the protocol cannot represent them.

`TlsRequestOptions.For(request).Proxy` overrides the route for one request. Assign a
proxy instance to select it, assign null to force a direct route even when the session
has a proxy, or call `UseSessionProxy()` to restore inheritance. Each origin, HTTP
version policy, proxy protocol/endpoint, and credential identity gets a separate pool
key; a tunnel is never reused through a different route.
