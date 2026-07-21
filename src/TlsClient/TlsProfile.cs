using SharpTls;
using System.Net;

namespace TlsClient;

/// <summary>A named SharpTls ClientHello profile used by an HTTP session.</summary>
public sealed class TlsProfile
{
    private readonly Lazy<ClientHelloProfile> _http11Profile;
    private readonly Lazy<ClientHelloProfile> _http11IpProfile;
    private readonly Lazy<ClientHelloProfile> _http2Profile;
    private readonly Lazy<ClientHelloProfile> _http2IpProfile;
    private readonly Lazy<ClientHelloProfile> _http2OnlyProfile;
    private readonly Lazy<ClientHelloProfile> _http2OnlyIpProfile;

    private TlsProfile(
        string name,
        ClientHelloProfile clientHello,
        string sharpTlsProfileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(clientHello);
        Name = name;
        ClientHello = clientHello;
        SharpTlsProfileName = sharpTlsProfileName;
        _http11Profile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http11IpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2Profile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "h2", "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2IpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "h2", "http/1.1"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2OnlyProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: true, "h2"),
            LazyThreadSafetyMode.ExecutionAndPublication);
        _http2OnlyIpProfile = new Lazy<ClientHelloProfile>(
            () => ClientHelloProfileRewriter.WithAlpn(ClientHello, includeSni: false, "h2"),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>Gets the stable display name.</summary>
    public string Name { get; }

    /// <summary>Gets the original, unmodified SharpTls profile.</summary>
    public ClientHelloProfile ClientHello { get; }

    /// <summary>Gets the SharpTls built-in property name, or "custom".</summary>
    public string SharpTlsProfileName { get; }

    /// <summary>Wraps any SharpTls profile with a diagnostic name.</summary>
    public static TlsProfile Create(string name, ClientHelloProfile clientHello) =>
        new(name, clientHello, "custom");

    internal static TlsProfile CreateBuiltIn(
        string name,
        string sharpTlsProfileName,
        ClientHelloProfile clientHello) => new(name, clientHello, sharpTlsProfileName);

    /// <inheritdoc />
    public override string ToString() => Name;

    internal ClientHelloProfile Http11ClientHello => _http11Profile.Value;

    internal ClientHelloProfile GetHttp11ClientHello(string host) =>
        IPAddress.TryParse(host, out _) ? _http11IpProfile.Value : _http11Profile.Value;

    internal ClientHelloProfile GetClientHello(string host, TlsHttpVersionPolicy policy)
    {
        var ipAddress = IPAddress.TryParse(host, out _);
        return policy switch
        {
            TlsHttpVersionPolicy.Http11Only =>
                ipAddress ? _http11IpProfile.Value : _http11Profile.Value,
            TlsHttpVersionPolicy.Http2Only =>
                ipAddress ? _http2OnlyIpProfile.Value : _http2OnlyProfile.Value,
            _ => ipAddress ? _http2IpProfile.Value : _http2Profile.Value,
        };
    }
}

/// <summary>Curated browser-family profiles backed directly by SharpTls.</summary>
public static class TlsProfiles
{
    /// <summary>Creates a coherent randomized profile using secure runtime entropy.</summary>
    public static TlsProfile CreateRandomized(
        string name = "randomized",
        ClientHelloRandomizationOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return TlsProfile.Create(
            name,
            ClientHelloProfileRandomizer.CreateSecure(
                options ?? new ClientHelloRandomizationOptions()));
    }

    /// <summary>
    /// Creates repeatable randomized profile policy for tests. Normal connections made from
    /// it still use secure handshake entropy.
    /// </summary>
    public static TlsProfile CreateRandomizedForTesting(
        string name,
        byte[] seed,
        ClientHelloRandomizationOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(seed);
        return TlsProfile.Create(
            name,
            ClientHelloProfileRandomizer.CreateDeterministicForTesting(
                seed,
                options ?? new ClientHelloRandomizationOptions()));
    }

    /// <summary>Gets the current SharpTls Chrome-family profile.</summary>
    public static TlsProfile Chrome { get; } =
        TlsProfile.CreateBuiltIn(
            "chrome-auto",
            nameof(ClientHelloProfiles.UTlsChromeAuto),
            ClientHelloProfiles.UTlsChromeAuto);

    /// <summary>Gets the current SharpTls Firefox-family profile.</summary>
    public static TlsProfile Firefox { get; } =
        TlsProfile.CreateBuiltIn(
            "firefox-auto",
            nameof(ClientHelloProfiles.UTlsFirefoxAuto),
            ClientHelloProfiles.UTlsFirefoxAuto);

    /// <summary>Gets the current SharpTls Edge-family profile.</summary>
    public static TlsProfile Edge { get; } =
        TlsProfile.CreateBuiltIn(
            "edge-auto",
            nameof(ClientHelloProfiles.UTlsEdgeAuto),
            ClientHelloProfiles.UTlsEdgeAuto);

    /// <summary>Gets the current SharpTls Safari-family profile.</summary>
    public static TlsProfile Safari { get; } =
        TlsProfile.CreateBuiltIn(
            "safari-auto",
            nameof(ClientHelloProfiles.UTlsSafariAuto),
            ClientHelloProfiles.UTlsSafariAuto);

    /// <summary>Gets the current SharpTls iOS-family profile.</summary>
    public static TlsProfile IOS { get; } =
        TlsProfile.CreateBuiltIn(
            "ios-auto",
            nameof(ClientHelloProfiles.UTlsIOSAuto),
            ClientHelloProfiles.UTlsIOSAuto);

    /// <summary>Gets the current SharpTls Android/OkHttp-family profile.</summary>
    public static TlsProfile Android { get; } =
        TlsProfile.CreateBuiltIn(
            "android-auto",
            nameof(ClientHelloProfiles.UTlsAndroidAuto),
            ClientHelloProfiles.UTlsAndroidAuto);

    /// <summary>Gets SharpTls's conservative modern TLS 1.3 profile.</summary>
    public static TlsProfile Modern { get; } =
        TlsProfile.CreateBuiltIn(
            "modern-tls13",
            nameof(ClientHelloProfiles.ModernTls13),
            ClientHelloProfiles.ModernTls13);

    /// <summary>Gets the pinned upstream Chrome 133 profile.</summary>
    public static TlsProfile Chrome133 { get; } =
        TlsProfile.CreateBuiltIn(
            "chrome-133",
            nameof(ClientHelloProfiles.UTlsChrome133),
            ClientHelloProfiles.UTlsChrome133);

    /// <summary>Gets the pinned upstream Firefox 148 profile.</summary>
    public static TlsProfile Firefox148 { get; } =
        TlsProfile.CreateBuiltIn(
            "firefox-148",
            nameof(ClientHelloProfiles.UTlsFirefox148),
            ClientHelloProfiles.UTlsFirefox148);

    /// <summary>Gets the pinned upstream OkHttp Android 11 profile.</summary>
    public static TlsProfile Android11 { get; } =
        TlsProfile.CreateBuiltIn(
            "okhttp4-android-11",
            nameof(ClientHelloProfiles.UTlsAndroid11OkHttp),
            ClientHelloProfiles.UTlsAndroid11OkHttp);

    /// <summary>Gets every built-in TlsClient profile in stable name order.</summary>
    public static IReadOnlyList<TlsProfile> All { get; } = Array.AsReadOnly(
        new TlsProfile[]
        {
            Android,
            Android11,
            Chrome,
            Chrome133,
            Edge,
            Firefox,
            Firefox148,
            IOS,
            Modern,
            Safari,
        });
}
