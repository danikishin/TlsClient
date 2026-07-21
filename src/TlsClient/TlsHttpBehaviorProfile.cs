using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TlsClient;

/// <summary>
/// Immutable, importable HTTP header-order and HTTP/2 wire behavior captured from options.
/// Header values, cookies, credentials, and request bodies are never captured.
/// </summary>
public sealed class TlsHttpBehaviorProfile
{
    private const int DefaultMaximumDocumentSize = 256 * 1024;
    private const int MaximumAllowedDocumentSize = 4 * 1024 * 1024;
    private const string DocumentFormat = "tlsclient-http-behavior";
    private const int DocumentVersion = 1;

    private static readonly JsonSerializerOptions IndentedJsonOptions = CreateJsonOptions(true);
    private static readonly JsonSerializerOptions CompactJsonOptions = CreateJsonOptions(false);

    private TlsHttpBehaviorProfile(
        string name,
        TlsHttpVersionPolicy httpVersionPolicy,
        string[] headerOrder,
        TlsHttp2Behavior http2)
    {
        Name = name;
        HttpVersionPolicy = httpVersionPolicy;
        HeaderOrder = Array.AsReadOnly(headerOrder);
        Http2 = http2;
    }

    /// <summary>Gets the caller-assigned behavior profile name.</summary>
    public string Name { get; }

    /// <summary>Gets the captured HTTP version and ALPN policy.</summary>
    public TlsHttpVersionPolicy HttpVersionPolicy { get; }

    /// <summary>Gets preferred regular-header names in exact order.</summary>
    public IReadOnlyList<string> HeaderOrder { get; }

    /// <summary>Gets the captured HTTP/2 wire behavior.</summary>
    public TlsHttp2Behavior Http2 { get; }

    /// <summary>
    /// Explicitly captures fingerprint-relevant HTTP behavior from mutable session options.
    /// </summary>
    public static TlsHttpBehaviorProfile Capture(string name, TlsSessionOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(options);
        if (!Enum.IsDefined(options.HttpVersionPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }

        var headerOrder = options.HeaderOrder?.ToArray() ?? [];
        ValidateHeaderOrder(headerOrder);
        var http2 = options.Http2.Snapshot();
        return new TlsHttpBehaviorProfile(
            name,
            options.HttpVersionPolicy,
            headerOrder,
            TlsHttp2Behavior.FromConfiguration(http2));
    }

    /// <summary>Exports the behavior in TlsClient's strict, versioned JSON format.</summary>
    public string ExportJson(bool writeIndented = true) =>
        JsonSerializer.Serialize(
            ToDocument(),
            writeIndented ? IndentedJsonOptions : CompactJsonOptions);

    /// <summary>Imports a strict, bounded TlsClient HTTP behavior document.</summary>
    /// <param name="json">The versioned JSON document.</param>
    /// <param name="maximumDocumentSize">Maximum UTF-8 size, up to 4 MiB.</param>
    public static TlsHttpBehaviorProfile ImportJson(
        string json,
        int maximumDocumentSize = DefaultMaximumDocumentSize)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (maximumDocumentSize is < 1 or > MaximumAllowedDocumentSize)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDocumentSize));
        }
        if (Encoding.UTF8.GetByteCount(json) > maximumDocumentSize)
        {
            throw new JsonException(
                $"The HTTP behavior document exceeds {maximumDocumentSize} UTF-8 bytes.");
        }

        using (var parsed = JsonDocument.Parse(
            json,
            new JsonDocumentOptions { MaxDepth = 32 }))
        {
            ValidateNoDuplicateProperties(parsed.RootElement);
        }

        var document = JsonSerializer.Deserialize<HttpBehaviorDocument>(
            json,
            CompactJsonOptions) ?? throw new JsonException("The document cannot be null.");
        if (!string.Equals(document.Format, DocumentFormat, StringComparison.Ordinal) ||
            document.Version != DocumentVersion)
        {
            throw new JsonException("Unsupported HTTP behavior format or version.");
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(document.Name);
        if (!Enum.IsDefined(document.HttpVersionPolicy))
        {
            throw new JsonException("The HTTP version policy is not defined.");
        }
        if (document.HeaderOrder is null || document.Http2 is null)
        {
            throw new JsonException("The behavior document is missing required fields.");
        }

        ValidateHeaderOrder(document.HeaderOrder);
        var profile = new TlsHttpBehaviorProfile(
            document.Name,
            document.HttpVersionPolicy,
            (string[])document.HeaderOrder.Clone(),
            TlsHttp2Behavior.FromDocument(document.Http2));

        // Apply through the normal public option model so every production bound and
        // cross-field constraint is enforced by the same validation path.
        var validationOptions = new TlsSessionOptions();
        profile.ApplyTo(validationOptions);
        _ = validationOptions.Snapshot();
        return profile;
    }

    /// <summary>
    /// Applies the captured HTTP behavior to options without changing TLS, headers values,
    /// proxy, retry, cookie, or certificate policy.
    /// </summary>
    public void ApplyTo(TlsSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.HttpVersionPolicy = HttpVersionPolicy;
        options.HeaderOrder = HeaderOrder.ToArray();
        Http2.ApplyTo(options.Http2);
    }

    private HttpBehaviorDocument ToDocument() => new(
        DocumentFormat,
        DocumentVersion,
        Name,
        HttpVersionPolicy,
        HeaderOrder.ToArray(),
        Http2.ToDocument());

    private static JsonSerializerOptions CreateJsonOptions(bool writeIndented) => new()
    {
        WriteIndented = writeIndented,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 32,
    };

    private static void ValidateHeaderOrder(string[] headerOrder)
    {
        if (headerOrder.Length > 256 ||
            headerOrder.Any(string.IsNullOrWhiteSpace) ||
            headerOrder.Distinct(StringComparer.OrdinalIgnoreCase).Count() != headerOrder.Length)
        {
            throw new JsonException(
                "Header order must contain at most 256 distinct, non-empty names.");
        }
    }

    private static void ValidateNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new JsonException($"Duplicate JSON property '{property.Name}'.");
                }
                ValidateNoDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item);
            }
        }
    }

    internal sealed record HttpBehaviorDocument(
        string Format,
        int Version,
        string Name,
        TlsHttpVersionPolicy HttpVersionPolicy,
        string[] HeaderOrder,
        Http2Document Http2);

    internal sealed record Http2Document(
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
        PriorityDocument? HeaderPriority,
        PriorityFrameDocument[] InitialPriorityFrames,
        string? PriorityUpdate);

    internal sealed record PriorityDocument(int StreamDependency, bool Exclusive, int Weight);

    internal sealed record PriorityFrameDocument(int StreamId, PriorityDocument Priority);

    /// <summary>Immutable HTTP/2 settings, ordering, flow-control, and priority behavior.</summary>
    public sealed class TlsHttp2Behavior
    {
        private TlsHttp2Behavior(
            uint headerTableSize,
            uint maxConcurrentStreams,
            uint initialWindowSize,
            uint maxFrameSize,
            uint maxHeaderListSize,
            uint connectionWindowIncrement,
            bool enableConnectProtocol,
            bool disableRfc7540Priorities,
            TlsHttp2Setting[] settingsOrder,
            string[] pseudoHeaderOrder,
            TlsHttp2PriorityBehavior? headerPriority,
            TlsHttp2PriorityFrameBehavior[] initialPriorityFrames,
            string? priorityUpdate)
        {
            HeaderTableSize = headerTableSize;
            MaxConcurrentStreams = maxConcurrentStreams;
            InitialWindowSize = initialWindowSize;
            MaxFrameSize = maxFrameSize;
            MaxHeaderListSize = maxHeaderListSize;
            ConnectionWindowIncrement = connectionWindowIncrement;
            EnableConnectProtocol = enableConnectProtocol;
            DisableRfc7540Priorities = disableRfc7540Priorities;
            SettingsOrder = Array.AsReadOnly(settingsOrder);
            PseudoHeaderOrder = Array.AsReadOnly(pseudoHeaderOrder);
            HeaderPriority = headerPriority;
            InitialPriorityFrames = Array.AsReadOnly(initialPriorityFrames);
            PriorityUpdate = priorityUpdate;
        }

        /// <summary>Gets the HPACK dynamic-table capacity.</summary>
        public uint HeaderTableSize { get; }

        /// <summary>Gets the advertised peer-initiated stream limit.</summary>
        public uint MaxConcurrentStreams { get; }

        /// <summary>Gets the initial per-stream receive window.</summary>
        public uint InitialWindowSize { get; }

        /// <summary>Gets the maximum accepted frame payload.</summary>
        public uint MaxFrameSize { get; }

        /// <summary>Gets the advisory maximum decoded header-list size.</summary>
        public uint MaxHeaderListSize { get; }

        /// <summary>Gets the initial connection WINDOW_UPDATE increment.</summary>
        public uint ConnectionWindowIncrement { get; }

        /// <summary>Gets whether extended CONNECT is advertised.</summary>
        public bool EnableConnectProtocol { get; }

        /// <summary>Gets whether RFC 7540 priorities are disabled.</summary>
        public bool DisableRfc7540Priorities { get; }

        /// <summary>Gets SETTINGS identifiers in exact wire order.</summary>
        public IReadOnlyList<TlsHttp2Setting> SettingsOrder { get; }

        /// <summary>Gets pseudo-header names in exact wire order.</summary>
        public IReadOnlyList<string> PseudoHeaderOrder { get; }

        /// <summary>Gets optional priority data embedded in HEADERS.</summary>
        public TlsHttp2PriorityBehavior? HeaderPriority { get; }

        /// <summary>Gets PRIORITY frames emitted after the preface.</summary>
        public IReadOnlyList<TlsHttp2PriorityFrameBehavior> InitialPriorityFrames { get; }

        /// <summary>Gets the optional RFC 9218 Priority Field Value.</summary>
        public string? PriorityUpdate { get; }

        internal static TlsHttp2Behavior FromConfiguration(TlsHttp2Configuration value) => new(
            value.HeaderTableSize,
            value.MaxConcurrentStreams,
            value.InitialWindowSize,
            value.MaxFrameSize,
            value.MaxHeaderListSize,
            value.ConnectionWindowIncrement,
            value.EnableConnectProtocol,
            value.DisableRfc7540Priorities,
            (TlsHttp2Setting[])value.SettingsOrder.Clone(),
            (string[])value.PseudoHeaderOrder.Clone(),
            TlsHttp2PriorityBehavior.FromConfiguration(value.HeaderPriority),
            value.InitialPriorityFrames
                .Select(TlsHttp2PriorityFrameBehavior.FromConfiguration)
                .ToArray(),
            value.PriorityUpdate);

        internal static TlsHttp2Behavior FromDocument(Http2Document value)
        {
            if (value.SettingsOrder is null ||
                value.PseudoHeaderOrder is null ||
                value.InitialPriorityFrames is null)
            {
                throw new JsonException("The HTTP/2 document is missing required fields.");
            }
            return new TlsHttp2Behavior(
                value.HeaderTableSize,
                value.MaxConcurrentStreams,
                value.InitialWindowSize,
                value.MaxFrameSize,
                value.MaxHeaderListSize,
                value.ConnectionWindowIncrement,
                value.EnableConnectProtocol,
                value.DisableRfc7540Priorities,
                (TlsHttp2Setting[])value.SettingsOrder.Clone(),
                (string[])value.PseudoHeaderOrder.Clone(),
                TlsHttp2PriorityBehavior.FromDocument(value.HeaderPriority),
                value.InitialPriorityFrames
                    .Select(TlsHttp2PriorityFrameBehavior.FromDocument)
                    .ToArray(),
                value.PriorityUpdate);
        }

        internal void ApplyTo(TlsHttp2Options options)
        {
            options.HeaderTableSize = HeaderTableSize;
            options.MaxConcurrentStreams = MaxConcurrentStreams;
            options.InitialWindowSize = InitialWindowSize;
            options.MaxFrameSize = MaxFrameSize;
            options.MaxHeaderListSize = MaxHeaderListSize;
            options.ConnectionWindowIncrement = ConnectionWindowIncrement;
            options.EnableConnectProtocol = EnableConnectProtocol;
            options.DisableRfc7540Priorities = DisableRfc7540Priorities;
            options.SettingsOrder = SettingsOrder.ToArray();
            options.PseudoHeaderOrder = PseudoHeaderOrder.ToArray();
            options.HeaderPriority = HeaderPriority?.ToOptions();
            options.InitialPriorityFrames = InitialPriorityFrames
                .Select(static frame => frame.ToOptions())
                .ToArray();
            options.PriorityUpdate = PriorityUpdate;
        }

        internal Http2Document ToDocument() => new(
            HeaderTableSize,
            MaxConcurrentStreams,
            InitialWindowSize,
            MaxFrameSize,
            MaxHeaderListSize,
            ConnectionWindowIncrement,
            EnableConnectProtocol,
            DisableRfc7540Priorities,
            SettingsOrder.ToArray(),
            PseudoHeaderOrder.ToArray(),
            HeaderPriority?.ToDocument(),
            InitialPriorityFrames.Select(static value => value.ToDocument()).ToArray(),
            PriorityUpdate);
    }

    /// <summary>Immutable HTTP/2 dependency, exclusivity, and weight.</summary>
    public sealed class TlsHttp2PriorityBehavior
    {
        private TlsHttp2PriorityBehavior(int streamDependency, bool exclusive, int weight)
        {
            StreamDependency = streamDependency;
            Exclusive = exclusive;
            Weight = weight;
        }

        /// <summary>Gets the dependency stream identifier.</summary>
        public int StreamDependency { get; }

        /// <summary>Gets whether the dependency is exclusive.</summary>
        public bool Exclusive { get; }

        /// <summary>Gets the relative weight.</summary>
        public int Weight { get; }

        internal static TlsHttp2PriorityBehavior? FromConfiguration(
            TlsHttp2PriorityConfiguration? value) => value is null
                ? null
                : new(value.StreamDependency, value.Exclusive, value.Weight);

        internal static TlsHttp2PriorityBehavior? FromDocument(PriorityDocument? value) =>
            value is null ? null : new(value.StreamDependency, value.Exclusive, value.Weight);

        internal TlsHttp2Priority ToOptions() => new()
        {
            StreamDependency = StreamDependency,
            Exclusive = Exclusive,
            Weight = Weight,
        };

        internal PriorityDocument ToDocument() => new(StreamDependency, Exclusive, Weight);
    }

    /// <summary>Immutable initial PRIORITY frame behavior.</summary>
    public sealed class TlsHttp2PriorityFrameBehavior
    {
        private TlsHttp2PriorityFrameBehavior(
            int streamId,
            TlsHttp2PriorityBehavior priority)
        {
            StreamId = streamId;
            Priority = priority;
        }

        /// <summary>Gets the prioritized client stream identifier.</summary>
        public int StreamId { get; }

        /// <summary>Gets the frame's priority parameters.</summary>
        public TlsHttp2PriorityBehavior Priority { get; }

        internal static TlsHttp2PriorityFrameBehavior FromConfiguration(
            TlsHttp2PriorityFrameConfiguration value) => new(
                value.StreamId,
                TlsHttp2PriorityBehavior.FromConfiguration(value.Priority)!);

        internal static TlsHttp2PriorityFrameBehavior FromDocument(
            PriorityFrameDocument value)
        {
            if (value.Priority is null)
            {
                throw new JsonException("A priority frame is missing its priority object.");
            }
            return new(
                value.StreamId,
                TlsHttp2PriorityBehavior.FromDocument(value.Priority)!);
        }

        internal TlsHttp2PriorityFrame ToOptions()
        {
            var value = new TlsHttp2PriorityFrame(StreamId);
            value.Priority.StreamDependency = Priority.StreamDependency;
            value.Priority.Exclusive = Priority.Exclusive;
            value.Priority.Weight = Priority.Weight;
            return value;
        }

        internal PriorityFrameDocument ToDocument() => new(StreamId, Priority.ToDocument());
    }
}
