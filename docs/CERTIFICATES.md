# Client certificates and server pins

TlsClient keeps certificate operations on SharpTls. Client credentials are
caller-created `TlsClientCertificate` instances; their private keys remain in the .NET
key handle, hardware signer, smart card, or remote signer selected by the caller.

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

Pins are additional SHA-256 SubjectPublicKeyInfo requirements. Normal certificate-chain
and hostname validation always succeeds first; a pin can only make acceptance stricter.

```csharp
options.CertificatePins.Add("api.example.com", "sha256/base64-value");
options.CertificatePins.Add("*.internal.example.com", certificate);

string display = TlsCertificatePins.CreateSha256Pin(certificate);
```

Multiple pins for a host provide rotation overlap. Any certificate in the already-valid
peer chain may match. Wildcards cover exactly one label below the suffix but not the
apex. Pin comparisons are fixed-time and temporary digests are zeroized.

Pinning is not a replacement for PKIX, hostname validation, revocation policy, or secure
certificate deployment. This release has no SharpTls callback that can accept an
otherwise invalid certificate; a future TlsClient option is dependency-gated on that
capability being added to SharpTls.
