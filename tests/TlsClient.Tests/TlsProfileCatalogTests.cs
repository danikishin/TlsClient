using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SharpTls;

namespace TlsClient.Tests;

public sealed class TlsProfileCatalogTests
{
    [Fact]
    public void Profiles_AreStableAndDerivedFromSharpTlsSpecs()
    {
        Assert.Equal(TlsProfiles.All.Count, TlsProfileCatalog.Profiles.Count);

        for (var index = 0; index < TlsProfiles.All.Count; index++)
        {
            var source = TlsProfiles.All[index];
            var manifest = TlsProfileCatalog.Profiles[index];
            var expectedHash = Convert.ToHexStringLower(
                SHA256.HashData(ClientHelloSpecJson.SerializeUtf8(source.ClientHello.Spec)));

            Assert.Equal(source.Name, manifest.Name);
            Assert.Equal(source.SharpTlsProfileName, manifest.SharpTlsProfileName);
            Assert.Equal(expectedHash, manifest.SpecificationSha256);
            Assert.Equal(source.ClientHello.Spec.Extensions.Count, manifest.ExtensionCount);
        }
    }

    [Fact]
    public void ChromeManifest_ReportsOriginalApplicationCompatibility()
    {
        var manifest = TlsProfileCatalog.Inspect(TlsProfiles.Chrome133);

        Assert.Equal(nameof(ClientHelloProfiles.UTlsChrome133), manifest.SharpTlsProfileName);
        Assert.Contains("h2", manifest.AlpnProtocols);
        Assert.Contains("http/1.1", manifest.AlpnProtocols);
        Assert.Equal(
            TlsProfileHttpCompatibility.Http11 | TlsProfileHttpCompatibility.Http2,
            manifest.HttpCompatibility);
    }

    [Fact]
    public void Exports_AreDeterministicAndContainCompatibilityData()
    {
        var firstJson = TlsProfileCatalog.ExportJson();
        var secondJson = TlsProfileCatalog.ExportJson();
        var markdown = TlsProfileCatalog.ExportMarkdown();

        Assert.Equal(firstJson, secondJson);
        using var document = JsonDocument.Parse(firstJson);
        Assert.Equal(TlsProfiles.All.Count, document.RootElement.GetArrayLength());
        Assert.Contains("| `chrome-133` | `UTlsChrome133` |", markdown, StringComparison.Ordinal);
        Assert.Contains("Spec SHA-256", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("\r\n", markdown, StringComparison.Ordinal);
        Assert.Equal(markdown, Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(markdown)));
    }
}
