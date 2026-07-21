# Server validation, client certificates, and pins

TlsClient keeps certificate operations on SharpTls. Client credentials are
caller-created `TlsClientCertificate` instances; their private keys remain in the .NET
key handle, hardware signer, smart card, or remote signer selected by the caller.

## Server certificate validation

SharpTls validates the server certificate chain, hostname, and revocation policy by
default. SharpTls `0.9.0-preview.5` allows unavailable revocation evidence to soft-fail
only after a second chain build validates every non-revocation requirement. A certificate
reported as revoked is never accepted.

The complete SharpTls policy remains available through the advanced hook:

```csharp
var options = new TlsSessionOptions
{
    ConfigureTls = tls =>
    {
        tls.CertificateValidation.RevocationMode = X509RevocationMode.Online;
        tls.CertificateValidation.AllowUnknownRevocationStatus = true;
    },
};
```

For a controlled local test with a self-signed or deliberately mismatched certificate,
callers can explicitly bypass the built-in chain and hostname checks:

```csharp
var options = new TlsSessionOptions
{
    DangerouslySkipServerCertificateValidation = true,
};
```

The default is `false`. Enabling this option permits active man-in-the-middle attacks
and is not suitable for production. It delegates directly to SharpTls; TLS
`CertificateVerify` and handshake authentication still run. An evidence validator and
TlsClient certificate pins also remain active when configured.

## Client certificate selection

Select a static fallback credential:

```csharp
using var credential = new TlsClientCertificate(clientLeafWithPrivateKey, issuerChain);

var options = new TlsSessionOptions();
options.ClientCertificates.Default = credential;

await using var session = new TlsSession(options);
```

Or map exact and wildcard hosts:

```csharp
options.ClientCertificates.Set("api.example.com", apiCredential);
options.ClientCertificates.Set("*.internal.example.com", internalCredential);
options.ClientCertificates.Default = fallbackCredential;
```

Exact matching runs before a single-label wildcard, then `Default`. Hostnames are
case-insensitive and normalized without a trailing dot. Wildcards must have the form
`*.example.com`; they do not match the apex.

For server-request details, HSM/KMS routing, TLS version, signature schemes, certificate
types, or post-handshake authentication, assign SharpTls's asynchronous selector directly:

```csharp
options.ClientCertificates.Selector = async (context, cancellationToken) =>
{
    return await credentialStore.SelectAsync(
        context.ServerName,
        context.ProtocolVersion,
        context.SignatureSchemes,
        context.IsPostHandshake,
        cancellationToken);
};
```

A custom `Selector` is a complete policy and cannot be combined with mappings or
`Default`. The collection is snapshotted when `TlsSession` is constructed. Credentials,
external signers, delegated credentials, certificates, and keys remain caller-owned;
keep them alive until every using session is disposed, then dispose them yourself.

The advanced `ConfigureTls` hook may still set SharpTls client authentication when the
helper is unused. Configuring both surfaces is rejected instead of guessing precedence.

## Certificate pins

Pins are additional SHA-256 SubjectPublicKeyInfo requirements. With secure defaults,
normal certificate-chain and hostname validation succeeds first and a pin can only make
acceptance stricter.

```csharp
options.CertificatePins.Add("api.example.com", "sha256/base64-value");
options.CertificatePins.Add("*.internal.example.com", certificate);

string display = TlsCertificatePins.CreateSha256Pin(certificate);
```

Multiple pins for a host provide rotation overlap. Any certificate in the already-valid
peer chain may match. Wildcards cover exactly one label below the suffix but not the
apex. Pin comparisons are fixed-time and temporary digests are zeroized.

Pinning is not a replacement for PKIX, hostname validation, revocation policy, or secure
certificate deployment. If `DangerouslySkipServerCertificateValidation` is enabled,
pins continue to reject non-matching peers, but they do not restore the skipped PKIX and
hostname checks.
