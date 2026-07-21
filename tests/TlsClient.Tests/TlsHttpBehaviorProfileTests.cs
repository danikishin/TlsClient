using System.Text.Json;

namespace TlsClient.Tests;

public sealed class TlsHttpBehaviorProfileTests
{
    [Fact]
    public void CaptureJsonImportApply_RoundTripsAllFingerprintRelevantHttpBehavior()
    {
        var source = TlsPresets.Firefox148.CreateOptions();
        var priorityFrame = new TlsHttp2PriorityFrame(3);
        priorityFrame.Priority.StreamDependency = 1;
        priorityFrame.Priority.Exclusive = true;
        priorityFrame.Priority.Weight = 201;
        source.Http2.InitialPriorityFrames = [priorityFrame];
        source.Http2.PriorityUpdate = "u=3, i";
        source.DefaultHeaders.Set("Authorization", "must-not-be-captured");

        var captured = TlsHttpBehaviorProfile.Capture("firefox-custom", source);
        var json = captured.ExportJson();
        var imported = TlsHttpBehaviorProfile.ImportJson(json);
        var target = new TlsSessionOptions();
        target.DefaultHeaders.Set("X-Keep", "caller-owned");
        imported.ApplyTo(target);
        var recaptured = TlsHttpBehaviorProfile.Capture("firefox-custom", target);

        Assert.Equal(json, recaptured.ExportJson());
        Assert.Equal(source.HeaderOrder, imported.HeaderOrder);
        Assert.Equal("u=3, i", imported.Http2.PriorityUpdate);
        Assert.Equal(201, imported.Http2.InitialPriorityFrames[0].Priority.Weight);
        Assert.True(target.DefaultHeaders.Contains("X-Keep"));
        Assert.DoesNotContain("must-not-be-captured", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Import_RejectsUnknownAndDuplicateProperties()
    {
        var json = TlsHttpBehaviorProfile
            .Capture("chrome", TlsPresets.Chrome133.CreateOptions())
            .ExportJson(writeIndented: false);
        var unknown = json.Replace(
            "\"version\":1,",
            "\"version\":1,\"unknown\":true,",
            StringComparison.Ordinal);
        var duplicate = json.Replace(
            "\"name\":\"chrome\",",
            "\"name\":\"chrome\",\"name\":\"duplicate\",",
            StringComparison.Ordinal);

        Assert.Throws<JsonException>(() => TlsHttpBehaviorProfile.ImportJson(unknown));
        Assert.Throws<JsonException>(() => TlsHttpBehaviorProfile.ImportJson(duplicate));
    }

    [Fact]
    public void Import_EnforcesUtf8DocumentLimit()
    {
        var json = TlsHttpBehaviorProfile
            .Capture("chrome", TlsPresets.Chrome133.CreateOptions())
            .ExportJson(writeIndented: false);

        Assert.Throws<JsonException>(() =>
            TlsHttpBehaviorProfile.ImportJson(json, maximumDocumentSize: 32));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TlsHttpBehaviorProfile.ImportJson(json, maximumDocumentSize: 4 * 1024 * 1024 + 1));
    }
}
