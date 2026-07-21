using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Certificates;

namespace TlsClient;

/// <summary>
/// Additional SHA-256 SubjectPublicKeyInfo pins. Normal chain and hostname validation
/// still run first; pins can only make validation stricter.
/// </summary>
public sealed class TlsCertificatePins
{
    private readonly object _sync = new();
    private readonly Dictionary<string, List<byte[]>> _pins =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds a <c>sha256/base64</c> or raw-base64 SPKI pin for a host.</summary>
    public void Add(string host, string pin)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(pin);
        var normalizedHost = NormalizeHost(host);
        var encoded = pin.StartsWith("sha256/", StringComparison.OrdinalIgnoreCase)
            ? pin[7..]
            : pin;

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The pin must be base64 encoded.", nameof(pin), exception);
        }
        if (bytes.Length != SHA256.HashSizeInBytes)
        {
            throw new ArgumentException("A SHA-256 pin must contain exactly 32 bytes.", nameof(pin));
        }

        lock (_sync)
        {
            if (!_pins.TryGetValue(normalizedHost, out var hostPins))
            {
                hostPins = [];
                _pins.Add(normalizedHost, hostPins);
            }
            hostPins.Add(bytes);
        }
    }

    /// <summary>Computes and adds a SHA-256 SPKI pin from a certificate.</summary>
    public void Add(string host, X509Certificate2 certificate) =>
        Add(host, CreateSha256Pin(certificate));

    /// <summary>Creates a standard <c>sha256/base64</c> SPKI pin from a certificate.</summary>
    public static string CreateSha256Pin(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        using var publicKey = GetPublicKey(certificate);
        var digest = SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo());
        try
        {
            return $"sha256/{Convert.ToBase64String(digest)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <summary>Removes all pins.</summary>
    public void Clear()
    {
        lock (_sync)
        {
            foreach (var pin in _pins.Values.SelectMany(static values => values))
            {
                CryptographicOperations.ZeroMemory(pin);
            }
            _pins.Clear();
        }
    }

    internal bool HasPins
    {
        get
        {
            lock (_sync)
            {
                return _pins.Count != 0;
            }
        }
    }

    internal TlsCertificatePins Snapshot()
    {
        var snapshot = new TlsCertificatePins();
        lock (_sync)
        {
            foreach (var (host, pins) in _pins)
            {
                snapshot._pins.Add(
                    host,
                    pins.Select(pin => (byte[])pin.Clone()).ToList());
            }
        }
        return snapshot;
    }

    internal void Validate(TlsServerCertificateEvidence evidence)
    {
        var expected = GetPins(evidence.ServerName);
        if (expected.Count == 0)
        {
            return;
        }

        try
        {
            foreach (var certificateBytes in evidence.CertificateChain)
            {
                using var certificate = X509CertificateLoader.LoadCertificate(certificateBytes);
                using var publicKey = GetPublicKey(certificate);
                var actual = SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo());
                try
                {
                    if (expected.Any(pin => CryptographicOperations.FixedTimeEquals(pin, actual)))
                    {
                        return;
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(actual);
                }
            }
        }
        finally
        {
            foreach (var pin in expected)
            {
                CryptographicOperations.ZeroMemory(pin);
            }
        }

        throw new AuthenticationException(
            $"The certificate chain for '{evidence.ServerName}' did not match a configured SPKI pin.");
    }

    private static AsymmetricAlgorithm GetPublicKey(X509Certificate2 certificate) =>
        (AsymmetricAlgorithm?)certificate.GetRSAPublicKey() ??
        (AsymmetricAlgorithm?)certificate.GetECDsaPublicKey() ??
        (AsymmetricAlgorithm?)certificate.GetDSAPublicKey() ??
        throw new AuthenticationException(
            $"Certificate public-key algorithm '{certificate.PublicKey.Oid.Value}' cannot be pinned.");

    private List<byte[]> GetPins(string host)
    {
        var normalizedHost = NormalizeHost(host);
        lock (_sync)
        {
            var result = new List<byte[]>();
            if (_pins.TryGetValue(normalizedHost, out var exact))
            {
                result.AddRange(exact);
            }

            var firstDot = normalizedHost.IndexOf('.');
            if (firstDot > 0 &&
                _pins.TryGetValue($"*{normalizedHost[firstDot..]}", out var wildcard))
            {
                result.AddRange(wildcard);
            }

            return result.Select(pin => (byte[])pin.Clone()).ToList();
        }
    }

    private static string NormalizeHost(string host)
    {
        var normalized = host.Trim();
        if (normalized.Length >= 2 && normalized[0] == '[' && normalized[^1] == ']')
        {
            normalized = normalized[1..^1];
        }
        if (IPAddress.TryParse(normalized, out var address))
        {
            return address.ToString().ToLowerInvariant();
        }

        normalized = normalized.TrimEnd('.').ToLowerInvariant();
        if (normalized.Length == 0 || normalized.Contains('/') || normalized.Contains(':'))
        {
            throw new ArgumentException("A pin host must be a DNS name or IP address.", nameof(host));
        }
        if (normalized.StartsWith('*') && !normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            throw new ArgumentException("Wildcard pins must start with '*.'.", nameof(host));
        }
        return normalized;
    }
}
