using SharpTls.Protocol;

namespace TlsClient;

/// <summary>Immutable, secret-free TLS metadata attached to an HTTP response.</summary>
public sealed record TlsConnectionInfo
{
    private readonly byte[][] _peerCertificateChain;

    internal TlsConnectionInfo(
        string clientHelloProfile,
        TlsProtocolVersion protocolVersion,
        TlsCipherSuite cipherSuite,
        NamedGroup group,
        string? applicationProtocol,
        bool sessionWasResumed,
        bool usedHelloRetryRequest,
        bool encryptedClientHelloAccepted,
        IReadOnlyList<byte[]> peerCertificateChain)
    {
        ClientHelloProfile = clientHelloProfile;
        ProtocolVersion = protocolVersion;
        CipherSuite = cipherSuite;
        Group = group;
        ApplicationProtocol = applicationProtocol;
        SessionWasResumed = sessionWasResumed;
        UsedHelloRetryRequest = usedHelloRetryRequest;
        EncryptedClientHelloAccepted = encryptedClientHelloAccepted;
        _peerCertificateChain = peerCertificateChain
            .Select(certificate => (byte[])certificate.Clone())
            .ToArray();
    }

    /// <summary>Gets the selected TlsClient profile name.</summary>
    public string ClientHelloProfile { get; }

    /// <summary>Gets the negotiated TLS version.</summary>
    public TlsProtocolVersion ProtocolVersion { get; }

    /// <summary>Gets the negotiated cipher suite.</summary>
    public TlsCipherSuite CipherSuite { get; }

    /// <summary>Gets the negotiated key-exchange group.</summary>
    public NamedGroup Group { get; }

    /// <summary>Gets the negotiated ALPN value.</summary>
    public string? ApplicationProtocol { get; }

    /// <summary>Gets whether this physical connection resumed a TLS session.</summary>
    public bool SessionWasResumed { get; }

    /// <summary>Gets whether this physical connection used HelloRetryRequest.</summary>
    public bool UsedHelloRetryRequest { get; }

    /// <summary>Gets whether configured ECH was accepted.</summary>
    public bool EncryptedClientHelloAccepted { get; }

    /// <summary>Gets defensive DER copies of the authenticated certificate chain.</summary>
    public IReadOnlyList<byte[]> PeerCertificateChain => Array.AsReadOnly(
        _peerCertificateChain.Select(certificate => (byte[])certificate.Clone()).ToArray());
}
