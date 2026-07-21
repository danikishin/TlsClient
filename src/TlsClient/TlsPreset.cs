namespace TlsClient;

/// <summary>
/// A coherent preset pairing a SharpTls ClientHello with HTTP/2 settings, flow control,
/// priorities, pseudo-header order, regular-header order, and conservative default headers.
/// </summary>
public sealed class TlsPreset
{
    private readonly Action<TlsHttp2Options> _configureHttp2;
    private readonly string[] _headerOrder;
    private readonly HeaderEntry[] _defaultHeaders;

    internal TlsPreset(
        string name,
        TlsProfile profile,
        Action<TlsHttp2Options> configureHttp2,
        string[] headerOrder,
        HeaderEntry[] defaultHeaders)
    {
        Name = name;
        Profile = profile;
        _configureHttp2 = configureHttp2;
        _headerOrder = headerOrder;
        _defaultHeaders = defaultHeaders;
    }

    /// <summary>Gets the stable, versioned preset name.</summary>
    public string Name { get; }

    /// <summary>Gets the SharpTls ClientHello profile paired with this preset.</summary>
    public TlsProfile Profile { get; }

    /// <summary>Creates an independent, caller-mutable options object.</summary>
    public TlsSessionOptions CreateOptions() => new(this);

    /// <inheritdoc />
    public override string ToString() => Name;

    internal void ApplyTo(TlsSessionOptions options)
    {
        options.Profile = Profile;
        options.HttpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2;
        options.HeaderOrder = (string[])_headerOrder.Clone();
        _configureHttp2(options.Http2);
        foreach (var header in _defaultHeaders)
        {
            options.DefaultHeaders.Set(header.Name, (string[])header.Values.Clone());
        }
    }
}

/// <summary>Versioned TLS and HTTP/2 presets backed by SharpTls profiles.</summary>
public static class TlsPresets
{
    private static readonly string[] ChromeHeaderOrder =
    [
        "Host",
        "Connection",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "Upgrade-Insecure-Requests",
        "User-Agent",
        "Accept",
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-User",
        "Sec-Fetch-Dest",
        "Accept-Encoding",
        "Accept-Language",
        "Cookie",
        "Priority",
    ];

    private static readonly string[] FirefoxHeaderOrder =
    [
        "Host",
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Connection",
        "Cookie",
    ];

    private static readonly string[] AndroidHeaderOrder =
    [
        "Host",
        "User-Agent",
        "Accept-Encoding",
        "Connection",
        "Cookie",
    ];

    /// <summary>Gets the SharpTls Chrome 133 and matching HTTP/2 preset.</summary>
    public static TlsPreset Chrome133 { get; } = new(
        "chrome-133",
        TlsProfiles.Chrome133,
        ConfigureChrome,
        ChromeHeaderOrder,
        [
            new HeaderEntry(
                "User-Agent",
                [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                    "AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/133.0.0.0 Safari/537.36",
                ]),
            new HeaderEntry("Accept-Language", ["en-US,en;q=0.9"]),
        ]);

    /// <summary>Gets the current SharpTls Chrome-family preset.</summary>
    public static TlsPreset Chrome => Chrome133;

    /// <summary>Gets the SharpTls Firefox 148 and matching HTTP/2 preset.</summary>
    public static TlsPreset Firefox148 { get; } = new(
        "firefox-148",
        TlsProfiles.Firefox148,
        ConfigureFirefox,
        FirefoxHeaderOrder,
        [
            new HeaderEntry(
                "User-Agent",
                ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"]),
            new HeaderEntry("Accept-Language", ["en-US,en;q=0.5"]),
        ]);

    /// <summary>Gets the current SharpTls Firefox-family preset.</summary>
    public static TlsPreset Firefox => Firefox148;

    /// <summary>Gets the SharpTls OkHttp Android 11 and matching HTTP/2 preset.</summary>
    public static TlsPreset Android11 { get; } = new(
        "okhttp4-android-11",
        TlsProfiles.Android11,
        ConfigureAndroid,
        AndroidHeaderOrder,
        [new HeaderEntry("User-Agent", ["okhttp/4.10.0"])]);

    /// <summary>Gets the current SharpTls Android/OkHttp-family preset.</summary>
    public static TlsPreset Android => Android11;

    private static void ConfigureChrome(TlsHttp2Options http2)
    {
        http2.HeaderTableSize = 65_536;
        http2.InitialWindowSize = 6_291_456;
        http2.MaxHeaderListSize = 262_144;
        http2.ConnectionWindowIncrement = 15_663_105;
        http2.SettingsOrder =
        [
            TlsHttp2Setting.HeaderTableSize,
            TlsHttp2Setting.EnablePush,
            TlsHttp2Setting.InitialWindowSize,
            TlsHttp2Setting.MaxHeaderListSize,
        ];
        http2.PseudoHeaderOrder = [":method", ":authority", ":scheme", ":path"];
        http2.HeaderPriority = null;
        http2.InitialPriorityFrames = [];
        http2.PriorityUpdate = null;
    }

    private static void ConfigureFirefox(TlsHttp2Options http2)
    {
        http2.HeaderTableSize = 65_536;
        http2.InitialWindowSize = 131_072;
        http2.MaxFrameSize = 16_384;
        http2.ConnectionWindowIncrement = 12_517_377;
        http2.SettingsOrder =
        [
            TlsHttp2Setting.HeaderTableSize,
            TlsHttp2Setting.EnablePush,
            TlsHttp2Setting.InitialWindowSize,
            TlsHttp2Setting.MaxFrameSize,
        ];
        http2.PseudoHeaderOrder = [":method", ":path", ":authority", ":scheme"];
        http2.HeaderPriority = new TlsHttp2Priority { Weight = 41 };
        http2.InitialPriorityFrames = [];
        http2.PriorityUpdate = null;
    }

    private static void ConfigureAndroid(TlsHttp2Options http2)
    {
        http2.InitialWindowSize = 16_777_216;
        http2.ConnectionWindowIncrement = 16_711_681;
        http2.SettingsOrder = [TlsHttp2Setting.InitialWindowSize];
        http2.PseudoHeaderOrder = [":method", ":path", ":authority", ":scheme"];
        http2.HeaderPriority = new TlsHttp2Priority { Weight = 1 };
        http2.InitialPriorityFrames = [];
        http2.PriorityUpdate = null;
    }
}
