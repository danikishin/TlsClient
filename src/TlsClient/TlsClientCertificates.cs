using System.Net;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient;

/// <summary>
/// Selects caller-owned SharpTls client credentials by exact host, wildcard, default,
/// or a fully custom asynchronous selector.
/// </summary>
public sealed class TlsClientCertificates
{
    private readonly object _sync = new();
    private readonly Dictionary<string, TlsClientCertificate> _certificates =
        new(StringComparer.OrdinalIgnoreCase);
    private TlsClientCertificate? _defaultCertificate;
    private TlsClientCertificateSelector? _selector;

    /// <summary>Gets or sets the fallback credential when no host mapping matches.</summary>
    public TlsClientCertificate? Default
    {
        get
        {
            lock (_sync)
            {
                return _defaultCertificate;
            }
        }
        set
        {
            lock (_sync)
            {
                _defaultCertificate = value;
            }
        }
    }

    /// <summary>
    /// Gets or sets a complete custom SharpTls selector. It cannot be combined with host
    /// mappings or <see cref="Default"/>.
    /// </summary>
    public TlsClientCertificateSelector? Selector
    {
        get
        {
            lock (_sync)
            {
                return _selector;
            }
        }
        set
        {
            lock (_sync)
            {
                _selector = value;
            }
        }
    }

    /// <summary>Gets the number of exact or wildcard host mappings.</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _certificates.Count;
            }
        }
    }

    /// <summary>Adds or replaces a credential for an exact host or <c>*.example.com</c>.</summary>
    public void Set(string host, TlsClientCertificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var normalized = NormalizeHost(host);
        lock (_sync)
        {
            _certificates[normalized] = certificate;
        }
    }

    /// <summary>Removes an exact or wildcard host mapping.</summary>
    public bool Remove(string host)
    {
        var normalized = NormalizeHost(host);
        lock (_sync)
        {
            return _certificates.Remove(normalized);
        }
    }

    /// <summary>Removes every mapping and selector without disposing caller-owned credentials.</summary>
    public void Clear()
    {
        lock (_sync)
        {
            _certificates.Clear();
            _defaultCertificate = null;
            _selector = null;
        }
    }

    internal TlsClientCertificateConfiguration Snapshot()
    {
        lock (_sync)
        {
            if (_selector is not null &&
                (_defaultCertificate is not null || _certificates.Count != 0))
            {
                throw new InvalidOperationException(
                    "ClientCertificates.Selector cannot be combined with host mappings or Default.");
            }
            if (_certificates.Count > 128)
            {
                throw new InvalidOperationException(
                    "ClientCertificates supports at most 128 host mappings.");
            }
            return new TlsClientCertificateConfiguration(
                new Dictionary<string, TlsClientCertificate>(
                    _certificates,
                    StringComparer.OrdinalIgnoreCase),
                _defaultCertificate,
                _selector);
        }
    }

    private static string NormalizeHost(string host)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized.Length >= 2 && normalized[0] == '[' && normalized[^1] == ']')
        {
            normalized = normalized[1..^1];
        }
        if (IPAddress.TryParse(normalized, out var address))
        {
            return address.ToString().ToLowerInvariant();
        }
        if (normalized.Length == 0 || normalized.Contains('/') || normalized.Contains(':'))
        {
            throw new ArgumentException(
                "A client-certificate host must be a DNS name or IP address.",
                nameof(host));
        }
        if (normalized.StartsWith('*') && !normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            throw new ArgumentException("A wildcard must start with '*.'.", nameof(host));
        }
        if (normalized.StartsWith("*.", StringComparison.Ordinal) &&
            normalized.AsSpan(2).IndexOf('.') < 0)
        {
            throw new ArgumentException(
                "A wildcard must contain a registrable-looking suffix.",
                nameof(host));
        }
        return normalized;
    }
}

internal sealed class TlsClientCertificateConfiguration
{
    private readonly IReadOnlyDictionary<string, TlsClientCertificate> _certificates;
    private readonly TlsClientCertificate? _defaultCertificate;
    private readonly TlsClientCertificateSelector? _selector;

    public TlsClientCertificateConfiguration(
        IReadOnlyDictionary<string, TlsClientCertificate> certificates,
        TlsClientCertificate? defaultCertificate,
        TlsClientCertificateSelector? selector)
    {
        _certificates = certificates;
        _defaultCertificate = defaultCertificate;
        _selector = selector;
    }

    public void Apply(CustomTlsClientOptions options)
    {
        if (_selector is null && _defaultCertificate is null && _certificates.Count == 0)
        {
            return;
        }
        if (options.ClientCertificate is not null || options.ClientCertificateSelector is not null)
        {
            throw new InvalidOperationException(
                "ConfigureTls and ClientCertificates both configured client authentication.");
        }

        if (_selector is not null)
        {
            options.ClientCertificateSelector = _selector;
            return;
        }
        if (_certificates.Count == 0)
        {
            options.ClientCertificate = _defaultCertificate;
            return;
        }

        options.ClientCertificateSelector = (context, _) =>
            ValueTask.FromResult(Resolve(context.ServerName));
    }

    private TlsClientCertificate? Resolve(string host)
    {
        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (_certificates.TryGetValue(normalized, out var exact))
        {
            return exact;
        }
        var firstDot = normalized.IndexOf('.');
        if (firstDot > 0 &&
            _certificates.TryGetValue($"*{normalized[firstDot..]}", out var wildcard))
        {
            return wildcard;
        }
        return _defaultCertificate;
    }
}
