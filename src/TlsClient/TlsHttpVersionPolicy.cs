namespace TlsClient;

/// <summary>Controls which HTTP protocol is advertised and accepted over SharpTls.</summary>
public enum TlsHttpVersionPolicy
{
    /// <summary>Advertise HTTP/2 and HTTP/1.1, preferring HTTP/2.</summary>
    PreferHttp2,

    /// <summary>Advertise and accept only HTTP/1.1.</summary>
    Http11Only,

    /// <summary>Advertise and accept only HTTP/2.</summary>
    Http2Only,
}

/// <summary>HTTP/2 settings sent by TlsClient, in caller-controlled wire order.</summary>
public enum TlsHttp2Setting : ushort
{
    /// <summary>HPACK decoder dynamic-table capacity.</summary>
    HeaderTableSize = 0x1,

    /// <summary>
    /// Disables server push with value zero. If omitted, promised streams are decoded
    /// to preserve HPACK state and immediately cancelled.
    /// </summary>
    EnablePush = 0x2,

    /// <summary>Maximum peer-initiated concurrent streams.</summary>
    MaxConcurrentStreams = 0x3,

    /// <summary>Initial per-stream receive window.</summary>
    InitialWindowSize = 0x4,

    /// <summary>Largest accepted frame payload.</summary>
    MaxFrameSize = 0x5,

    /// <summary>Advisory maximum decoded header-list size.</summary>
    MaxHeaderListSize = 0x6,

    /// <summary>Whether RFC 8441 extended CONNECT is enabled.</summary>
    EnableConnectProtocol = 0x8,

    /// <summary>Whether RFC 7540 priority signaling is disabled.</summary>
    NoRfc7540Priorities = 0x9,
}

/// <summary>Configures HTTP/2 wire settings and ordering.</summary>
public sealed class TlsHttp2Options
{
    /// <summary>Gets or sets the local HPACK dynamic-table capacity.</summary>
    public uint HeaderTableSize { get; set; } = 65_536;

    /// <summary>Gets or sets the advertised peer-initiated stream limit.</summary>
    public uint MaxConcurrentStreams { get; set; } = 1000;

    /// <summary>Gets or sets the initial per-stream receive window.</summary>
    public uint InitialWindowSize { get; set; } = 6_291_456;

    /// <summary>Gets or sets the maximum accepted frame payload.</summary>
    public uint MaxFrameSize { get; set; } = 16 * 1024;

    /// <summary>Gets or sets the advisory maximum decoded header-list size.</summary>
    public uint MaxHeaderListSize { get; set; } = 262_144;

    /// <summary>
    /// Gets or sets the connection-level WINDOW_UPDATE increment sent after the preface.
    /// Zero keeps HTTP/2's initial 65,535-byte connection window.
    /// </summary>
    public uint ConnectionWindowIncrement { get; set; } = 15_663_105;

    /// <summary>Gets or sets the SETTINGS_ENABLE_CONNECT_PROTOCOL value.</summary>
    public bool EnableConnectProtocol { get; set; }

    /// <summary>Gets or sets the SETTINGS_NO_RFC7540_PRIORITIES value.</summary>
    public bool DisableRfc7540Priorities { get; set; }

    /// <summary>Gets or sets SETTINGS entries in exact wire order.</summary>
    public IReadOnlyList<TlsHttp2Setting> SettingsOrder { get; set; } =
    [
        TlsHttp2Setting.HeaderTableSize,
        TlsHttp2Setting.EnablePush,
        TlsHttp2Setting.InitialWindowSize,
        TlsHttp2Setting.MaxHeaderListSize,
    ];

    /// <summary>Gets or sets pseudo-headers in exact request wire order.</summary>
    public IReadOnlyList<string> PseudoHeaderOrder { get; set; } =
        [":method", ":authority", ":scheme", ":path"];

    /// <summary>Gets or sets optional RFC 7540 priority data embedded in HEADERS.</summary>
    public TlsHttp2Priority? HeaderPriority { get; set; }

    /// <summary>Gets or sets optional PRIORITY frames emitted after the client preface.</summary>
    public IReadOnlyList<TlsHttp2PriorityFrame> InitialPriorityFrames { get; set; } = [];

    /// <summary>
    /// Gets or sets an optional RFC 9218 Priority Field Value sent in a PRIORITY_UPDATE
    /// frame for every new request stream, for example <c>u=3, i</c>.
    /// </summary>
    public string? PriorityUpdate { get; set; }

    internal TlsHttp2Configuration Snapshot()
    {
        if (HeaderTableSize > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(HeaderTableSize));
        }
        if (InitialWindowSize > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(InitialWindowSize));
        }
        if (MaxFrameSize is < 16 * 1024 or > 16_777_215)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxFrameSize));
        }
        if (MaxHeaderListSize is < 1024 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxHeaderListSize));
        }
        if (ConnectionWindowIncrement > int.MaxValue - 65_535U)
        {
            throw new ArgumentOutOfRangeException(nameof(ConnectionWindowIncrement));
        }

        var settingsOrder = SettingsOrder?.ToArray() ??
            throw new ArgumentNullException(nameof(SettingsOrder));
        if (settingsOrder.Length == 0 ||
            settingsOrder.Distinct().Count() != settingsOrder.Length ||
            settingsOrder.Any(setting => !Enum.IsDefined(setting)))
        {
            throw new ArgumentException(
                "SettingsOrder must contain distinct, defined settings.",
                nameof(SettingsOrder));
        }
        var pseudoHeaderOrder = PseudoHeaderOrder?.ToArray() ??
            throw new ArgumentNullException(nameof(PseudoHeaderOrder));
        string[] required = [":method", ":authority", ":scheme", ":path"];
        if (pseudoHeaderOrder.Length != required.Length ||
            !pseudoHeaderOrder.ToHashSet(StringComparer.Ordinal).SetEquals(required))
        {
            throw new ArgumentException(
                "PseudoHeaderOrder must contain :method, :authority, :scheme, and :path exactly once.",
                nameof(PseudoHeaderOrder));
        }

        var headerPriority = HeaderPriority?.Snapshot();
        var initialPriorityFrames = InitialPriorityFrames?.ToArray() ??
            throw new ArgumentNullException(nameof(InitialPriorityFrames));
        if (initialPriorityFrames.Any(frame => frame is null) ||
            initialPriorityFrames.Select(frame => frame.StreamId).Distinct().Count() !=
                initialPriorityFrames.Length)
        {
            throw new ArgumentException(
                "InitialPriorityFrames must contain distinct, non-null stream entries.",
                nameof(InitialPriorityFrames));
        }
        var priorityFrames = initialPriorityFrames.Select(frame => frame.Snapshot()).ToArray();
        if (PriorityUpdate is { } priorityUpdate &&
            (priorityUpdate.Length is < 1 or > 256 || priorityUpdate.Any(character =>
                character is < '\u0020' or > '\u007e')))
        {
            throw new ArgumentException(
                "PriorityUpdate must contain 1–256 visible ASCII characters.",
                nameof(PriorityUpdate));
        }

        return new TlsHttp2Configuration(
            HeaderTableSize,
            MaxConcurrentStreams,
            InitialWindowSize,
            MaxFrameSize,
            MaxHeaderListSize,
            ConnectionWindowIncrement,
            EnableConnectProtocol,
            DisableRfc7540Priorities,
            settingsOrder,
            pseudoHeaderOrder,
            headerPriority,
            priorityFrames,
            PriorityUpdate);
    }
}

/// <summary>RFC 7540 stream dependency and weight.</summary>
public sealed class TlsHttp2Priority
{
    /// <summary>Gets or sets the dependency stream identifier, or zero for the root.</summary>
    public int StreamDependency { get; set; }

    /// <summary>Gets or sets whether this dependency is exclusive.</summary>
    public bool Exclusive { get; set; }

    /// <summary>Gets or sets the relative weight from 1 through 256.</summary>
    public int Weight { get; set; } = 16;

    internal TlsHttp2PriorityConfiguration Snapshot()
    {
        if (StreamDependency is < 0 || Weight is < 1 or > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(StreamDependency),
                "StreamDependency must be non-negative and Weight must be between 1 and 256.");
        }
        return new TlsHttp2PriorityConfiguration(StreamDependency, Exclusive, Weight);
    }
}

/// <summary>An RFC 7540 PRIORITY frame emitted when an HTTP/2 connection starts.</summary>
public sealed class TlsHttp2PriorityFrame
{
    /// <summary>Creates a priority frame for an idle or open client stream.</summary>
    /// <param name="streamId">A positive odd client stream identifier.</param>
    public TlsHttp2PriorityFrame(int streamId)
    {
        StreamId = streamId;
    }

    /// <summary>Gets the prioritized stream identifier.</summary>
    public int StreamId { get; }

    /// <summary>Gets priority parameters for the stream.</summary>
    public TlsHttp2Priority Priority { get; } = new();

    internal TlsHttp2PriorityFrameConfiguration Snapshot()
    {
        if (StreamId <= 0 || (StreamId & 1) == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(StreamId),
                "Initial priority stream identifiers must be positive and odd.");
        }
        var priority = Priority.Snapshot();
        if (priority.StreamDependency == StreamId)
        {
            throw new ArgumentException("A stream cannot depend on itself.", nameof(Priority));
        }
        return new TlsHttp2PriorityFrameConfiguration(StreamId, priority);
    }
}

internal sealed record TlsHttp2Configuration(
    uint HeaderTableSize,
    uint MaxConcurrentStreams,
    uint InitialWindowSize,
    uint MaxFrameSize,
    uint MaxHeaderListSize,
    uint ConnectionWindowIncrement,
    bool EnableConnectProtocol,
    bool DisableRfc7540Priorities,
    TlsHttp2Setting[] SettingsOrder,
    string[] PseudoHeaderOrder,
    TlsHttp2PriorityConfiguration? HeaderPriority,
    TlsHttp2PriorityFrameConfiguration[] InitialPriorityFrames,
    string? PriorityUpdate);

internal sealed record TlsHttp2PriorityConfiguration(
    int StreamDependency,
    bool Exclusive,
    int Weight);

internal sealed record TlsHttp2PriorityFrameConfiguration(
    int StreamId,
    TlsHttp2PriorityConfiguration Priority);
