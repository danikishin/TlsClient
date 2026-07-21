using SharpTls;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TlsClient;

/// <summary>Imports, exports, and snapshots SharpTls ClientHello profiles.</summary>
public static class TlsClientHello
{
    /// <summary>
    /// Adds an opt-in pre-send fingerprint observer without replacing existing TLS hooks.
    /// Observer exceptions abort the connection before the ClientHello is written.
    /// </summary>
    public static void Observe(
        TlsSessionOptions options,
        Action<TlsClientHelloObservation> observer)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(observer);

        var existingConfigure = options.ConfigureTls;
        options.ConfigureTls = tlsOptions =>
        {
            existingConfigure?.Invoke(tlsOptions);
            var existingInspector = tlsOptions.ClientHelloInspector;
            tlsOptions.ClientHelloInspector = inspection =>
            {
                existingInspector?.Invoke(inspection);
                observer(new TlsClientHelloObservation(inspection));
            };
        };
    }

    /// <summary>Imports a captured bare handshake or TLS-record image into an executable profile.</summary>
    /// <param name="name">Diagnostic name assigned to the imported profile.</param>
    /// <param name="source">Captured ClientHello bytes.</param>
    /// <param name="format">Expected capture framing.</param>
    /// <param name="options">Optional SharpTls normalization and input-limit policy.</param>
    /// <returns>The imported profile together with SharpTls capture metadata.</returns>
    public static TlsImportedClientHello ImportCapture(
        string name,
        ReadOnlySpan<byte> source,
        ClientHelloCaptureFormat format = ClientHelloCaptureFormat.Auto,
        ClientHelloImportOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var result = ClientHelloCapture.Import(
            source,
            format,
            options ?? new ClientHelloImportOptions());
        return new TlsImportedClientHello(
            TlsProfile.Create(name, ClientHelloProfiles.FromSpec(result.Spec)),
            result);
    }

    /// <summary>Exports a profile through SharpTls's strict, versioned, secret-free JSON format.</summary>
    public static string ExportJson(
        TlsProfile profile,
        ClientHelloSpecJsonOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return ClientHelloSpecJson.Serialize(
            profile.ClientHello.Spec,
            options ?? new ClientHelloSpecJsonOptions());
    }

    /// <summary>Imports SharpTls's strict, versioned, secret-free JSON format.</summary>
    public static TlsProfile ImportJson(
        string name,
        string json,
        ClientHelloSpecJsonOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(json);
        var spec = ClientHelloSpecJson.Deserialize(
            json,
            options ?? new ClientHelloSpecJsonOptions());
        return TlsProfile.Create(name, ClientHelloProfiles.FromSpec(spec));
    }

    /// <summary>
    /// Builds a repeatable ClientHello using SharpTls's test-only deterministic key material.
    /// The returned bytes must never be transmitted.
    /// </summary>
    public static TlsClientHelloSnapshot BuildSnapshotForTesting(
        TlsProfile profile,
        string serverName,
        byte[] seed,
        TlsHttpVersionPolicy httpVersionPolicy = TlsHttpVersionPolicy.PreferHttp2)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentNullException.ThrowIfNull(seed);
        if (!Enum.IsDefined(httpVersionPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(httpVersionPolicy));
        }

        var bytes = profile
            .GetClientHello(serverName, httpVersionPolicy)
            .BuildDeterministicForTesting(serverName, seed);
        return new TlsClientHelloSnapshot(
            profile.Name,
            serverName,
            httpVersionPolicy,
            bytes);
    }
}

/// <summary>Combines an imported TlsClient profile with SharpTls capture provenance.</summary>
public sealed class TlsImportedClientHello
{
    internal TlsImportedClientHello(
        TlsProfile profile,
        ClientHelloCaptureResult capture)
    {
        Profile = profile;
        Capture = capture;
    }

    /// <summary>Gets the normalized executable profile.</summary>
    public TlsProfile Profile { get; }

    /// <summary>
    /// Gets SharpTls's immutable normalized result, including captured SNI and record boundaries.
    /// </summary>
    public ClientHelloCaptureResult Capture { get; }
}

/// <summary>A deterministic, test-only ClientHello regression snapshot.</summary>
public sealed class TlsClientHelloSnapshot
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = CreateJsonOptions(true);
    private static readonly JsonSerializerOptions CompactJsonOptions = CreateJsonOptions(false);
    private readonly byte[] _encodedHandshake;

    internal TlsClientHelloSnapshot(
        string profileName,
        string serverName,
        TlsHttpVersionPolicy httpVersionPolicy,
        byte[] encodedHandshake)
    {
        ProfileName = profileName;
        ServerName = serverName;
        HttpVersionPolicy = httpVersionPolicy;
        _encodedHandshake = encodedHandshake.ToArray();
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(_encodedHandshake));
    }

    /// <summary>Gets the source TlsClient profile name.</summary>
    public string ProfileName { get; }

    /// <summary>Gets the reference server name encoded into the snapshot.</summary>
    public string ServerName { get; }

    /// <summary>Gets the HTTP policy used to derive ALPN for the snapshot.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter<TlsHttpVersionPolicy>))]
    public TlsHttpVersionPolicy HttpVersionPolicy { get; }

    /// <summary>Gets the encoded handshake length.</summary>
    public int Length => _encodedHandshake.Length;

    /// <summary>Gets the lowercase SHA-256 digest of the encoded handshake.</summary>
    public string Sha256 { get; }

    /// <summary>Returns a caller-owned copy of the encoded handshake.</summary>
    public byte[] GetEncodedHandshake() => _encodedHandshake.ToArray();

    /// <summary>Exports the regression snapshot, including the test-only bytes, as JSON.</summary>
    public string ExportJson(bool writeIndented = true) =>
        JsonSerializer.Serialize(
            new SnapshotDocument(
                ProfileName,
                ServerName,
                HttpVersionPolicy,
                Length,
                Sha256,
                Convert.ToBase64String(_encodedHandshake)),
            writeIndented ? IndentedJsonOptions : CompactJsonOptions);

    private static JsonSerializerOptions CreateJsonOptions(bool writeIndented) => new()
    {
        WriteIndented = writeIndented,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter<TlsHttpVersionPolicy>() },
    };

    private sealed record SnapshotDocument(
        string ProfileName,
        string ServerName,
        TlsHttpVersionPolicy HttpVersionPolicy,
        int Length,
        string Sha256,
        string EncodedHandshakeBase64);
}
