# TLS 1.3 session persistence

Each `TlsSession` owns bounded in-memory SharpTls TLS 1.3 and TLS 1.2 caches. TLS 1.3
tickets can be moved between independent sessions through SharpTls's authenticated,
encrypted state format. TlsClient never exposes plaintext tickets or PSKs and never owns
the application's persistence keys.

```csharp
byte[] julyKey = Load32ByteKeyFromSecretStore();
byte[] persisted;

using (var july = new Tls13SessionStateProtector("2026-07", julyKey))
await using (var session = new TlsSession(TlsPresets.Chrome133))
{
    await session.GetAsync("https://example.com/");
    persisted = session.ExportTls13SessionState(july);
}

await File.WriteAllBytesAsync("tls-sessions.bin", persisted);
```

Import into a later process or session, optionally retaining an old decrypt-only key
during rotation:

```csharp
byte[] augustKey = Load32ByteKeyFromSecretStore();
using var august = new Tls13SessionStateProtector("2026-08", augustKey);
august.AddDecryptionKey("2026-07", julyKey);

await using var restored = new TlsSession(TlsPresets.Chrome133);
restored.ImportTls13SessionState(
    await File.ReadAllBytesAsync("tls-sessions.bin"),
    august);

TlsResponse response = await restored.GetAsync("https://example.com/");
Console.WriteLine(response.Tls.SessionWasResumed);
```

The caller owns and disposes every `Tls13SessionStateProtector`, stores its random
32-byte AES-256-GCM keys in an appropriate secret store, rotates them, and protects or
deletes persisted blobs. Do not embed keys in source code, configuration committed to
version control, or the state blob itself. Do not reuse a protection key for another
protocol.

SharpTls authenticates the complete blob before parsing and atomically imports only
fully valid state. Unknown keys, tampering, truncation, unsupported versions, oversized
state, invalid origins, and invalid fields fail without a partial import. Expired tickets
are discarded and origin, port, ALPN, transcript hash, ECH source, authentication age,
capacity, and single-use bindings remain enforced.

`CachedTls13SessionCount` is a non-secret operational count. An export does not consume
tickets; an actual resumption offer does. The session and its cache may remain active
while an encrypted snapshot is exported because SharpTls's cache is thread-safe.

TLS 1.2 resumption remains in-memory only because the current SharpTls TLS 1.2 cache has
no client persistence API. TlsClient does not invent an unprotected or incompatible
format for it.
