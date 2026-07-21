using System.Security.Cryptography;
using System.Text.Json;
using SharpTls;

namespace TlsClient.Tests;

public sealed class TlsClientHelloTests
{
    private static readonly byte[] Seed = SHA256.HashData("tlsclient-tests"u8);

    [Fact]
    public void CaptureImport_UsesSharpTlsNormalizationAndPreservesProvenance()
    {
        var source = ClientHelloProfiles.ModernTls13.BuildDeterministicForTesting(
            "capture.example",
            Seed);

        var imported = TlsClientHello.ImportCapture(
            "captured-test",
            source,
            ClientHelloCaptureFormat.Handshake);

        Assert.Equal("captured-test", imported.Profile.Name);
        Assert.Equal("custom", imported.Profile.SharpTlsProfileName);
        Assert.Equal("capture.example", imported.Capture.CapturedServerName);
        Assert.False(imported.Capture.WasRecordFramed);
        Assert.Equal(
            ClientHelloProfiles.ModernTls13.Spec.CipherSuites,
            imported.Profile.ClientHello.Spec.CipherSuites);
    }

    [Fact]
    public void Json_RoundTripsThroughSharpTlsStrictFormat()
    {
        var json = TlsClientHello.ExportJson(
            TlsProfiles.Chrome133,
            new ClientHelloSpecJsonOptions { WriteIndented = false });
        var restored = TlsClientHello.ImportJson("restored", json);

        Assert.Contains("\"format\":\"sharptls-clienthello-spec\"", json, StringComparison.Ordinal);
        Assert.Equal(
            TlsProfileCatalog.Inspect(TlsProfiles.Chrome133).SpecificationSha256,
            TlsProfileCatalog.Inspect(restored).SpecificationSha256);
    }

    [Fact]
    public void Snapshot_IsDeterministicAndReturnsDefensiveCopies()
    {
        var first = TlsClientHello.BuildSnapshotForTesting(
            TlsProfiles.Chrome133,
            "snapshot.example",
            Seed);
        var second = TlsClientHello.BuildSnapshotForTesting(
            TlsProfiles.Chrome133,
            "snapshot.example",
            Seed);
        var bytes = first.GetEncodedHandshake();

        Assert.Equal(first.Sha256, second.Sha256);
        Assert.Equal(first.GetEncodedHandshake(), second.GetEncodedHandshake());
        Assert.Equal(first.Length, bytes.Length);
        bytes[0] ^= 0xff;
        Assert.NotEqual(bytes, first.GetEncodedHandshake());

        using var document = JsonDocument.Parse(first.ExportJson(writeIndented: false));
        Assert.Equal(first.Sha256, document.RootElement.GetProperty("sha256").GetString());
        Assert.Equal(
            Convert.ToBase64String(first.GetEncodedHandshake()),
            document.RootElement.GetProperty("encodedHandshakeBase64").GetString());
    }

    [Fact]
    public void Snapshot_ChangesWhenAlpnPolicyChanges()
    {
        var http11 = TlsClientHello.BuildSnapshotForTesting(
            TlsProfiles.Firefox148,
            "snapshot.example",
            Seed,
            TlsHttpVersionPolicy.Http11Only);
        var http2 = TlsClientHello.BuildSnapshotForTesting(
            TlsProfiles.Firefox148,
            "snapshot.example",
            Seed,
            TlsHttpVersionPolicy.Http2Only);

        Assert.NotEqual(http11.Sha256, http2.Sha256);
    }
}
