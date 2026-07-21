# ECH DNS discovery

TlsClient can use SharpTls's RFC 9848 HTTPS/SVCB resolver before opening an origin TLS
connection. SharpTls owns DNS framing, SVCB selection, ECHConfigList parsing, downgrade
policy, protected resolver authentication, TTLs, bounds, and caching. TlsClient owns the
HTTP connection route and consumes the ordered endpoints without reinterpreting them.

```csharp
var echResolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
{
    SupportedAlpnProtocols = ["h2", "http/1.1"],
    // Plain DNS uses explicit NameServers or active interface configuration.
    // DoT/DoH require explicit bootstrap IPs and authenticate the resolver name.
});

var options = TlsPresets.Chrome133.CreateOptions();
options.EchDnsResolver = echResolver;

await using var session = new TlsSession(options);
TlsResponse response = await session.GetAsync("https://example.com/");

Console.WriteLine(response.Tls.EncryptedClientHelloAccepted);
```

Resolution completes before any origin ClientHello is encoded or sent. For each ordered
SharpTls endpoint, TlsClient:

1. tries securely shuffled IPv6/IPv4 SVCB hints when present;
2. falls back to resolving the endpoint TargetName because hints are non-authoritative;
3. connects to the endpoint's selected port, including non-default SVCB ports;
4. keeps the original origin as SNI, ECH inner name, and certificate identity;
5. applies the endpoint through `TlsEchDnsEndpoint.ConfigureClient`; and
6. honors SharpTls's ECH-required or legitimate mixed/direct fallback endpoint set.

An all-ECH result never gains a direct endpoint in TlsClient. DNS transport errors fail
closed unless the caller explicitly enabled SharpTls's
`AllowDirectFallbackOnDnsError`. NODATA/NXDOMAIN and malformed-RRSet behavior likewise
comes from SharpTls's RFC 9460/9848 policy rather than an HTTP-layer guess.

## Protected resolver example

```csharp
var resolver = new TlsEchDnsResolver(new TlsEchDnsResolverOptions
{
    SupportedAlpnProtocols = ["h2", "http/1.1"],
    DnsOverHttps = new TlsEchDnsOverHttpsOptions
    {
        Endpoint = new Uri("https://cloudflare-dns.com/dns-query"),
        BootstrapEndpoints =
        [
            new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443),
            new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 443),
        ],
    },
});
```

DoT/DoH is implemented and authenticated by SharpTls itself and never falls back to
port 53. Bootstrap IPs avoid a plaintext recursive lookup for the protected resolver.
`RequireAuthenticatedData` trusts a recursive resolver's AD assertion; it is not a local
DNSSEC validator.

ECH discovery currently supports direct session routes. Session or per-request proxies
and profile Roller mode are rejected because those components own a different connection
destination. A custom `DnsResolver` remains valid and is used only for a selected SVCB
TargetName after SharpTls has completed HTTPS discovery.

See SharpTls's packaged `ECH-DNS-BOOTSTRAP.md` and `PROTECTED-DNS.md` for its full
standards, bounds, cache, and trust model.
