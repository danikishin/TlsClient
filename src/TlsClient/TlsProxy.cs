using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace TlsClient;

/// <summary>Describes an HTTP CONNECT, SOCKS4/SOCKS4a, or SOCKS5 proxy.</summary>
public sealed class TlsProxy
{
    private readonly NetworkCredential? _credentials;

    private TlsProxy(
        TlsProxyType type,
        Uri address,
        NetworkCredential? credentials)
    {
        Type = type;
        Address = address;
        _credentials = credentials is null
            ? null
            : new NetworkCredential(credentials.UserName, credentials.Password, credentials.Domain);
        PoolKey = CreatePoolKey(type, address, _credentials);
    }

    /// <summary>Gets the proxy protocol.</summary>
    public TlsProxyType Type { get; }

    /// <summary>Gets the proxy endpoint without user-info.</summary>
    public Uri Address { get; }

    /// <summary>Gets credentials without exposing them through <see cref="ToString"/>.</summary>
    public NetworkCredential? Credentials => _credentials is null
        ? null
        : new NetworkCredential(_credentials.UserName, _credentials.Password, _credentials.Domain);

    /// <summary>Creates an HTTP CONNECT proxy from a URL, including optional user-info.</summary>
    public static TlsProxy Http(string address) => CreateFromUri(
        TlsProxyType.Http,
        address,
        Uri.UriSchemeHttp);

    /// <summary>Creates an HTTP CONNECT proxy from a URL, including optional user-info.</summary>
    public static TlsProxy Http(Uri address) => CreateFromUri(
        TlsProxyType.Http,
        address,
        Uri.UriSchemeHttp);

    /// <summary>Creates an HTTP CONNECT proxy with Basic credentials.</summary>
    public static TlsProxy Http(string address, string username, string password) => Create(
        TlsProxyType.Http,
        new Uri(address, UriKind.Absolute),
        Uri.UriSchemeHttp,
        new NetworkCredential(username, password));

    /// <summary>Creates a SOCKS4/SOCKS4a proxy from a URL, including an optional user ID.</summary>
    public static TlsProxy Socks4(string address) => CreateFromUri(
        TlsProxyType.Socks4,
        address,
        "socks4");

    /// <summary>Creates a SOCKS4/SOCKS4a proxy with a user ID.</summary>
    public static TlsProxy Socks4(string address, string userId)
    {
        ArgumentNullException.ThrowIfNull(userId);
        return Create(
            TlsProxyType.Socks4,
            new Uri(address, UriKind.Absolute),
            "socks4",
            new NetworkCredential(userId, string.Empty));
    }

    /// <summary>Creates a SOCKS5 proxy from a URL, including optional user-info.</summary>
    public static TlsProxy Socks5(string address) => CreateFromUri(
        TlsProxyType.Socks5,
        address,
        "socks5");

    /// <summary>Creates a SOCKS5 proxy with username/password authentication.</summary>
    public static TlsProxy Socks5(string address, string username, string password)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);
        return Create(
            TlsProxyType.Socks5,
            new Uri(address, UriKind.Absolute),
            "socks5",
            new NetworkCredential(username, password));
    }

    /// <inheritdoc />
    public override string ToString() => $"{Type} proxy {Address.Host}:{EffectivePort}";

    internal int EffectivePort => Address.IsDefaultPort || Address.Port < 0
        ? Type == TlsProxyType.Http ? 80 : 1080
        : Address.Port;

    internal string PoolKey { get; }

    internal NetworkCredential? GetCredentials() => Credentials;

    internal string? GetBasicAuthorizationValue()
    {
        if (Type != TlsProxyType.Http || _credentials is null)
        {
            return null;
        }
        var bytes = Encoding.UTF8.GetBytes($"{_credentials.UserName}:{_credentials.Password}");
        return $"Basic {Convert.ToBase64String(bytes)}";
    }

    private static TlsProxy CreateFromUri(
        TlsProxyType type,
        string address,
        string expectedScheme)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(address);
        return CreateFromUri(type, new Uri(address, UriKind.Absolute), expectedScheme);
    }

    private static TlsProxy CreateFromUri(
        TlsProxyType type,
        Uri address,
        string expectedScheme)
    {
        ArgumentNullException.ThrowIfNull(address);
        NetworkCredential? credentials = null;
        if (!string.IsNullOrEmpty(address.UserInfo))
        {
            var separator = address.UserInfo.IndexOf(':');
            var username = separator < 0 ? address.UserInfo : address.UserInfo[..separator];
            var password = separator < 0 ? string.Empty : address.UserInfo[(separator + 1)..];
            credentials = new NetworkCredential(
                Uri.UnescapeDataString(username),
                Uri.UnescapeDataString(password));
        }
        return Create(type, address, expectedScheme, credentials);
    }

    private static TlsProxy Create(
        TlsProxyType type,
        Uri address,
        string expectedScheme,
        NetworkCredential? credentials)
    {
        if (!address.IsAbsoluteUri ||
            !address.Scheme.Equals(expectedScheme, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"The proxy URL must be an absolute {expectedScheme}:// URL.",
                nameof(address));
        }
        if (string.IsNullOrWhiteSpace(address.Host))
        {
            throw new ArgumentException("The proxy URL must contain a host.", nameof(address));
        }
        if (type == TlsProxyType.Socks4 &&
            !string.IsNullOrEmpty(credentials?.Password))
        {
            throw new ArgumentException(
                "SOCKS4 supports a user ID but not password authentication.",
                nameof(address));
        }
        ValidateNoNull(credentials?.UserName, "proxy username");
        ValidateNoNull(credentials?.Password, "proxy password");
        var builder = new UriBuilder(address)
        {
            UserName = string.Empty,
            Password = string.Empty,
        };
        return new TlsProxy(type, builder.Uri, credentials);
    }

    private static string CreatePoolKey(
        TlsProxyType type,
        Uri address,
        NetworkCredential? credentials)
    {
        var port = address.IsDefaultPort || address.Port < 0
            ? type == TlsProxyType.Http ? 80 : 1080
            : address.Port;
        var credentialBytes = Encoding.UTF8.GetBytes(
            $"{credentials?.UserName}\0{credentials?.Password}");
        var credentialHash = Convert.ToHexString(SHA256.HashData(credentialBytes));
        return $"{type}|{address.IdnHost.ToLowerInvariant()}|{port}|{credentialHash}";
    }

    private static void ValidateNoNull(string? value, string description)
    {
        if (value?.Contains('\0', StringComparison.Ordinal) == true)
        {
            throw new ArgumentException($"The {description} cannot contain NUL.");
        }
    }
}

/// <summary>Identifies a supported proxy protocol.</summary>
public enum TlsProxyType
{
    /// <summary>HTTP CONNECT.</summary>
    Http,

    /// <summary>SOCKS4 with SOCKS4a hostname extension.</summary>
    Socks4,

    /// <summary>SOCKS5 with optional username/password authentication.</summary>
    Socks5,
}
