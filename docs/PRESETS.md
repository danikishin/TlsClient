# Built-in presets

A `TlsPreset` is a coherent starting point, not just a TLS alias. It selects the pinned
SharpTls ClientHello profile and configures ALPN policy, ordered HTTP/2 SETTINGS, the
connection WINDOW_UPDATE increment, pseudo-header order, HEADERS priority data, regular
header order, and conservative default headers.

```csharp
await using var session = new TlsSession(TlsPresets.Chrome133);

var options = TlsPresets.Firefox148.CreateOptions();
options.DefaultHeaders.Set("Accept-Language", "tr-TR,tr;q=0.9");
await using var customized = new TlsSession(options);
```

`CreateOptions()` always returns an independent mutable object. The short aliases
`Chrome`, `Firefox`, and `Android` point to the current built-in versioned presets;
choose the versioned property when reproducibility matters.

## Profile matrix

| TlsClient preset | SharpTls TLS profile | Ordered HTTP/2 SETTINGS | WINDOW_UPDATE increment | HEADERS priority | Pseudo-header order |
|---|---|---|---:|---|---|
| `Chrome133` | `UTlsChrome133` | `1:65536; 2:0; 4:6291456; 6:262144` | `15663105` | none | `m,a,s,p` |
| `Firefox148` | `UTlsFirefox148` | `1:65536; 2:0; 4:131072; 5:16384` | `12517377` | dep `0`, non-exclusive, weight `41` | `m,p,a,s` |
| `Android11` | `UTlsAndroid11OkHttp` | `4:16777216` | `16711681` | dep `0`, non-exclusive, weight `1` | `m,p,a,s` |

The setting identifiers are the HTTP/2 registry values. The pseudo-header abbreviation
uses `m` = method, `a` = authority, `s` = scheme, and `p` = path. WINDOW_UPDATE values
are increments, not final receive-window sizes.

The HTTP/2 values were transcribed from bogdanfinn/tls-client commit
[`b790a311273f26051935641120de169e497e5943`](https://github.com/bogdanfinn/tls-client/commit/b790a311273f26051935641120de169e497e5943):

- [Chrome 133 profile](https://github.com/bogdanfinn/tls-client/blob/b790a311273f26051935641120de169e497e5943/profiles/internal_browser_profiles.go#L820-L935)
- [Firefox 148 profile](https://github.com/bogdanfinn/tls-client/blob/b790a311273f26051935641120de169e497e5943/profiles/contributed_browser_profiles.go#L10-L151)
- [OkHttp Android 11 profile](https://github.com/bogdanfinn/tls-client/blob/b790a311273f26051935641120de169e497e5943/profiles/contributed_custom_profiles.go#L1250-L1274)

TlsClient's loopback capture tests establish a real SharpTls connection and assert the
serialized settings order and values, connection window increment, HEADERS priority
bytes, decoded pseudo-header order, and preset User-Agent. Android's omitted
`SETTINGS_ENABLE_PUSH` is intentional: HTTP/2 defaults push to enabled, so TlsClient
keeps the HPACK state synchronized and immediately rejects promised streams with
`RST_STREAM(CANCEL)`.

Regular request headers are application context, not part of the upstream HTTP/2
profile. The built-ins provide a useful order and User-Agent, but they do not invent a
complete browser navigation request (`sec-ch-*`, Fetch Metadata, and similar values
depend on runtime context). Callers can set or remove those headers explicitly.
