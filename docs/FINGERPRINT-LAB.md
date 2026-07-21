# ClientHello laboratory

TlsClient delegates capture parsing, strict JSON interchange, fresh executable profile
construction, and deterministic test encoding to SharpTls. Imported data never carries
captured random values, private keys, binders, traffic secrets, or session tickets into
a new connection.

## Import a capture

`ImportCapture` accepts either a bare TLS Handshake message or TLSPlaintext records.
SharpTls applies its structural validation, executable-algorithm checks, normalization,
and bounded input policy:

```csharp
byte[] bytes = await File.ReadAllBytesAsync("clienthello.bin");

TlsImportedClientHello imported = TlsClientHello.ImportCapture(
    "my-reviewed-capture",
    bytes,
    ClientHelloCaptureFormat.Auto,
    new ClientHelloImportOptions
    {
        MaximumInputSize = 256 * 1024,
        PreserveSessionId = false,
    });

await using var session = new TlsSession(new TlsSessionOptions
{
    Profile = imported.Profile,
});

Console.WriteLine(imported.Capture.CapturedServerName);
Console.WriteLine(imported.Capture.WasRecordFramed);
```

The caller explicitly decides whether a capture is trusted and suitable for its
application protocol. Unknown or unsafe negotiation semantics are rejected by SharpTls
rather than silently weakened.

## Strict JSON interchange

```csharp
string json = TlsClientHello.ExportJson(TlsProfiles.Chrome133);
TlsProfile restored = TlsClientHello.ImportJson("reviewed-profile", json);
```

This is SharpTls's versioned and bounded ClientHello specification format, not a
TlsClient-owned approximation. Use `ClientHelloSpecJsonOptions` to select indentation
and input limits. JSON contains reusable offer policy only, never connection secrets.

## Deterministic regression snapshots

```csharp
byte[] testSeed = SHA256.HashData("my-fixture-v1"u8);
TlsClientHelloSnapshot snapshot = TlsClientHello.BuildSnapshotForTesting(
    TlsProfiles.Chrome133,
    "fixture.example",
    testSeed,
    TlsHttpVersionPolicy.PreferHttp2);

Assert.Equal("expected sha256", snapshot.Sha256);
await File.WriteAllTextAsync("snapshot.json", snapshot.ExportJson());
```

The snapshot includes TlsClient's ALPN rewrite for the selected HTTP policy. Equal
profile, server name, seed, HTTP policy, and SharpTls version produce equal bytes.
Changing any of those inputs may intentionally change the digest.

`BuildSnapshotForTesting` uses fixed deterministic ECDHE material. Its encoded bytes
are test fixtures and **must never be sent over a network**. Production handshakes
always use SharpTls's secure runtime entropy and fresh private keys.

## Coherent randomization

```csharp
TlsProfile randomized = TlsProfiles.CreateRandomized(
    "my-randomized-policy",
    new ClientHelloRandomizationOptions
    {
        GreaseProbabilityPercent = 75,
        GreaseEchProbabilityPercent = 25,
        MaximumPaddingLength = 64,
    });

await using var session = new TlsSession(new TlsSessionOptions
{
    Profile = randomized,
    HttpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2,
});
```

SharpTls generates only executable, internally coherent suite/group/signature/key-share
combinations. TlsClient then derives ALPN from the selected HTTP policy so it never
advertises an application protocol that its active connection implementation will not
honor. `CreateRandomizedForTesting` makes the randomized policy repeatable for tests;
normal connections from that profile still use secure handshake entropy.

## Origin-aware Roller

```csharp
var roller = new TlsProfileRoller(
    "browser-roller",
    new ClientHelloRollerOptions
    {
        MaximumAttempts = 3,
        CacheCapacity = 256,
    });

await using var session = new TlsSession(new TlsSessionOptions
{
    ProfileRoller = roller,
    ConfigureTls = tls =>
    {
        // Certificate policy, ECH, inspection, and other SharpTls options remain available.
    },
});
```

SharpTls tries bounded coherent candidates only for explicit peer negotiation alerts and
remembers the successful profile in its capacity-bounded, origin-aware LRU. It never
turns certificate, hostname, malformed-message, socket, cancellation, or generic I/O
failures into profile retries.

Roller candidates preserve their exact ALPN and SNI layout. Roller mode therefore
requires `PreferHttp2`, a DNS-name origin, and a direct connection. It rejects session
or per-request proxies, exact per-request HTTP versions, custom DNS, and connection
telemetry instead of silently bypassing those policies. Connection pooling, HTTP/1.1,
HTTP/2, certificate pins, and `ConfigureTls` remain active after SharpTls establishes the
connection. Use a regular `TlsProfile` when custom routing is required.

## HTTP behavior capture and import

TLS is only one part of a wire persona. Header order, pseudo-header order, ordered
HTTP/2 SETTINGS, flow-control increments, and priority frames can be captured explicitly
from session options and moved through a strict JSON document:

```csharp
var source = TlsPresets.Chrome133.CreateOptions();
TlsHttpBehaviorProfile behavior = TlsHttpBehaviorProfile.Capture(
    "chrome-133-http",
    source);

string json = behavior.ExportJson();
TlsHttpBehaviorProfile restored = TlsHttpBehaviorProfile.ImportJson(json);

var target = new TlsSessionOptions { Profile = TlsProfiles.Chrome133 };
restored.ApplyTo(target);
```

Capture is opt-in and records only HTTP version policy, preferred regular-header names,
and HTTP/2 wire controls. It deliberately excludes header values, authorization, cookies,
bodies, proxy data, certificates, and TLS configuration. `ApplyTo` changes only those
captured HTTP fields and leaves all other target policy intact.

Import is case-sensitive, bounded to 256 KiB by default (4 MiB hard maximum), rejects
unknown and duplicate properties, and runs the result through the same HTTP/2 bounds and
cross-field validation used when a session starts. This describes configured behavior;
request-dependent headers still depend on the method, URL, content, cookies, and caller
headers for that individual request.

## JA3 and JA4 diagnostics

Inspect a bare ClientHello Handshake message without opening a connection:

```csharp
TlsClientHelloFingerprint fingerprint =
    TlsFingerprintDiagnostics.InspectHandshake(handshakeBytes);

Console.WriteLine(fingerprint.Ja3String);
Console.WriteLine(fingerprint.Ja3Hash);
Console.WriteLine(fingerprint.Ja4);
Console.WriteLine(fingerprint.Ja4Raw);
```

Or observe the exact SharpTls wire image immediately before it is sent:

```csharp
var options = TlsPresets.Chrome133.CreateOptions();
TlsClientHello.Observe(options, observation =>
{
    Console.WriteLine(observation.Flight);
    Console.WriteLine(observation.WireForm);
    Console.WriteLine(observation.Fingerprint.Ja4);
});
```

`Observe` chains existing `ConfigureTls` and `ClientHelloInspector` callbacks instead of
replacing them. The observer is synchronous; like SharpTls's inspector, an exception
aborts that connection before the ClientHello is written.

JA3 follows Salesforce's published legacy-version, ordered cipher, ordered extension,
supported-group, and EC-point-format representation and removes RFC 8701 GREASE values.
JA4 follows FoxIO's TCP ClientHello algorithm: the highest supported version, SNI/ALPN
indicators and non-GREASE counts form the prefix; sorted non-GREASE ciphers and sorted
extensions plus ordered signature algorithms form the truncated SHA-256 sections.

- [Salesforce JA3 reference](https://github.com/salesforce/ja3)
- [FoxIO JA4 reference implementation](https://github.com/FoxIO-LLC/ja4)

These values are diagnostics, not a profile language. JA3 omits extension bodies,
signatures, key shares, ALPN contents, record fragmentation, HTTP behavior, and many
other observable properties. JA4 is richer and resistant to shuffled cipher/extension
order, but it still does not reproduce a complete browser, TLS state, transport stack,
or application session. Use a reviewed `TlsProfile`/`TlsPreset` or capture import when
reproduction is the actual goal.
