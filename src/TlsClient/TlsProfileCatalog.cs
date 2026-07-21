using SharpTls;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TlsClient;

/// <summary>Describes which HTTP protocols a ClientHello can negotiate.</summary>
[Flags]
public enum TlsProfileHttpCompatibility
{
    /// <summary>The profile does not advertise an HTTP ALPN identifier.</summary>
    None = 0,

    /// <summary>The profile advertises HTTP/1.1.</summary>
    Http11 = 1,

    /// <summary>The profile advertises HTTP/2.</summary>
    Http2 = 2,
}

/// <summary>
/// Contains deterministic metadata derived from a SharpTls ClientHello specification.
/// </summary>
public sealed class TlsProfileManifest
{
    internal TlsProfileManifest(TlsProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var spec = profile.ClientHello.Spec;
        Name = profile.Name;
        SharpTlsProfileName = profile.SharpTlsProfileName;
        SharpTlsVersion = GetSharpTlsVersion();
        TlsVersions = Names(spec.SupportedVersions);
        AlpnProtocols = spec.AlpnProtocols.ToArray();
        CipherSuites = Names(spec.CipherSuites);
        SupportedGroups = Names(spec.SupportedGroups);
        KeyShareGroups = Names(spec.KeyShareGroups);
        SignatureAlgorithms = Names(spec.SignatureAlgorithms);
        ExtensionCount = spec.Extensions.Count;
        UsesGrease = spec.Grease;
        UsesGreaseEch = spec.GreaseEncryptedClientHello;
        ShufflesExtensions = spec.ShuffleExtensions;
        SupportsSessionResumption = spec.SupportsSessionResumption;
        SupportsEarlyData = spec.SupportsEarlyData;
        HttpCompatibility = GetHttpCompatibility(AlpnProtocols);
        SpecificationSha256 = Convert.ToHexStringLower(
            SHA256.HashData(ClientHelloSpecJson.SerializeUtf8(spec)));
    }

    /// <summary>Gets the stable TlsClient profile name.</summary>
    public string Name { get; }

    /// <summary>Gets the SharpTls built-in property name, or <c>custom</c>.</summary>
    public string SharpTlsProfileName { get; }

    /// <summary>Gets the SharpTls informational version used to derive the manifest.</summary>
    public string SharpTlsVersion { get; }

    /// <summary>Gets supported TLS versions in exact offer order.</summary>
    public IReadOnlyList<string> TlsVersions { get; }

    /// <summary>Gets ALPN identifiers in exact offer order.</summary>
    public IReadOnlyList<string> AlpnProtocols { get; }

    /// <summary>Gets cipher suites in exact offer order.</summary>
    public IReadOnlyList<string> CipherSuites { get; }

    /// <summary>Gets supported groups in exact preference order.</summary>
    public IReadOnlyList<string> SupportedGroups { get; }

    /// <summary>Gets initial key-share groups in exact order.</summary>
    public IReadOnlyList<string> KeyShareGroups { get; }

    /// <summary>Gets signature algorithms in exact preference order.</summary>
    public IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>Gets the number of extension slots in the original specification.</summary>
    public int ExtensionCount { get; }

    /// <summary>Gets whether semantic GREASE generation is enabled.</summary>
    public bool UsesGrease { get; }

    /// <summary>Gets whether semantic GREASE ECH generation is enabled.</summary>
    public bool UsesGreaseEch { get; }

    /// <summary>Gets whether extensions are shuffled for each connection.</summary>
    public bool ShufflesExtensions { get; }

    /// <summary>Gets whether the profile supports TLS 1.3 session resumption.</summary>
    public bool SupportsSessionResumption { get; }

    /// <summary>Gets whether the profile can conditionally offer TLS 1.3 early data.</summary>
    public bool SupportsEarlyData { get; }

    /// <summary>Gets HTTP compatibility inferred from the original ALPN offer.</summary>
    [JsonConverter(typeof(JsonStringEnumConverter<TlsProfileHttpCompatibility>))]
    public TlsProfileHttpCompatibility HttpCompatibility { get; }

    /// <summary>
    /// Gets the lowercase SHA-256 digest of SharpTls's versioned, secret-free spec JSON.
    /// </summary>
    public string SpecificationSha256 { get; }

    private static string[] Names<T>(IEnumerable<T> values) =>
        values.Select(static value => value?.ToString() ?? string.Empty).ToArray();

    private static TlsProfileHttpCompatibility GetHttpCompatibility(
        IReadOnlyList<string> protocols)
    {
        var result = TlsProfileHttpCompatibility.None;
        if (protocols.Contains("http/1.1", StringComparer.Ordinal))
        {
            result |= TlsProfileHttpCompatibility.Http11;
        }

        if (protocols.Contains("h2", StringComparer.Ordinal))
        {
            result |= TlsProfileHttpCompatibility.Http2;
        }

        return result;
    }

    private static string GetSharpTlsVersion()
    {
        var assembly = typeof(ClientHelloProfile).Assembly;
        return assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                   ?.InformationalVersion
               ?? assembly.GetName().Version?.ToString()
               ?? "unknown";
    }
}

/// <summary>Generates deterministic metadata and compatibility documents for profiles.</summary>
public static class TlsProfileCatalog
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly JsonSerializerOptions CompactJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly TlsProfileManifest[] BuiltInProfiles =
        TlsProfiles.All.Select(static profile => new TlsProfileManifest(profile)).ToArray();

    private static readonly IReadOnlyList<TlsProfileManifest> ReadOnlyProfiles =
        Array.AsReadOnly(BuiltInProfiles);

    /// <summary>Gets metadata for every built-in profile in stable name order.</summary>
    public static IReadOnlyList<TlsProfileManifest> Profiles => ReadOnlyProfiles;

    /// <summary>Derives a manifest from any TlsClient profile.</summary>
    public static TlsProfileManifest Inspect(TlsProfile profile) => new(profile);

    /// <summary>Exports the built-in catalog as deterministic JSON.</summary>
    /// <param name="writeIndented">Whether to format the JSON with indentation.</param>
    public static string ExportJson(bool writeIndented = true) =>
        JsonSerializer.Serialize(
            BuiltInProfiles,
            writeIndented ? IndentedJsonOptions : CompactJsonOptions);

    /// <summary>Exports the built-in compatibility table as Markdown.</summary>
    public static string ExportMarkdown()
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Generated TLS profile manifest");
        builder.AppendLine();
        builder.AppendLine(
            "This file is generated by `TlsClient.ProfileCatalog` directly from the " +
            "SharpTls `ClientHelloSpec` metadata. Do not edit the table by hand.");
        builder.AppendLine();
        builder.Append("SharpTls version: `")
            .Append(BuiltInProfiles[0].SharpTlsVersion)
            .AppendLine("`");
        builder.AppendLine();
        builder.AppendLine(
            "| TlsClient profile | SharpTls profile | TLS versions | ALPN | Original ALPN HTTP | " +
            "Suites | Groups | Key shares | Signatures | Extensions | GREASE | ECH GREASE | " +
            "Shuffle | Resumption | Early data | Spec SHA-256 |");
        builder.AppendLine(
            "|---|---|---|---|---|---:|---:|---:|---:|---:|:---:|:---:|:---:|:---:|:---:|---|");

        foreach (var profile in BuiltInProfiles)
        {
            builder.Append("| `").Append(profile.Name)
                .Append("` | `").Append(profile.SharpTlsProfileName)
                .Append("` | ").Append(Join(profile.TlsVersions))
                .Append(" | ").Append(Join(profile.AlpnProtocols))
                .Append(" | ").Append(FormatCompatibility(profile.HttpCompatibility))
                .Append(" | ").Append(profile.CipherSuites.Count)
                .Append(" | ").Append(profile.SupportedGroups.Count)
                .Append(" | ").Append(profile.KeyShareGroups.Count)
                .Append(" | ").Append(profile.SignatureAlgorithms.Count)
                .Append(" | ").Append(profile.ExtensionCount)
                .Append(" | ").Append(YesNo(profile.UsesGrease))
                .Append(" | ").Append(YesNo(profile.UsesGreaseEch))
                .Append(" | ").Append(YesNo(profile.ShufflesExtensions))
                .Append(" | ").Append(YesNo(profile.SupportsSessionResumption))
                .Append(" | ").Append(YesNo(profile.SupportsEarlyData))
                .Append(" | `").Append(profile.SpecificationSha256)
                .AppendLine("` |");
        }

        builder.AppendLine();
        builder.AppendLine(
            "`none` in Original ALPN HTTP means the source profile omitted ALPN. It does not " +
            "make the profile unusable: TlsClient derives an ALPN-coherent connection profile " +
            "from `TlsHttpVersionPolicy` without mutating the source metadata.");
        builder.AppendLine();
        builder.AppendLine(
            "The digest covers SharpTls's versioned, secret-free specification JSON. " +
            "It is a metadata regression key, not a hash of a live ClientHello: random, " +
            "key-share, binder, and per-connection GREASE bytes are intentionally absent.");
        return builder.ToString().ReplaceLineEndings("\n");
    }

    private static string Join(IReadOnlyList<string> values) =>
        values.Count == 0 ? "—" : string.Join(", ", values.Select(Escape));

    private static string Escape(string value) => value.Replace("|", "\\|", StringComparison.Ordinal);

    private static string YesNo(bool value) => value ? "yes" : "no";

    private static string FormatCompatibility(TlsProfileHttpCompatibility value) => value switch
    {
        TlsProfileHttpCompatibility.Http11 => "HTTP/1.1",
        TlsProfileHttpCompatibility.Http2 => "HTTP/2",
        TlsProfileHttpCompatibility.Http11 | TlsProfileHttpCompatibility.Http2 =>
            "HTTP/1.1 + HTTP/2",
        _ => "none",
    };
}
