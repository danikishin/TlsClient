namespace TlsClient.Tests;

public sealed class TlsPresetTests
{
    [Fact]
    public void Chrome133_CreatesCoherentIndependentOptions()
    {
        var first = TlsPresets.Chrome133.CreateOptions();
        var second = TlsPresets.Chrome133.CreateOptions();

        first.Http2.SettingsOrder = [TlsHttp2Setting.InitialWindowSize];
        first.DefaultHeaders.Set("User-Agent", "changed");

        var snapshot = second.Snapshot();
        Assert.Same(TlsProfiles.Chrome133, snapshot.Profile);
        Assert.Equal(TlsHttpVersionPolicy.PreferHttp2, snapshot.HttpVersionPolicy);
        Assert.Equal(
            [
                TlsHttp2Setting.HeaderTableSize,
                TlsHttp2Setting.EnablePush,
                TlsHttp2Setting.InitialWindowSize,
                TlsHttp2Setting.MaxHeaderListSize,
            ],
            snapshot.Http2.SettingsOrder);
        Assert.Equal(15_663_105U, snapshot.Http2.ConnectionWindowIncrement);
        Assert.Equal(
            [":method", ":authority", ":scheme", ":path"],
            snapshot.Http2.PseudoHeaderOrder);
        Assert.Null(snapshot.Http2.HeaderPriority);
        Assert.StartsWith(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            second.DefaultHeaders["User-Agent"]);
    }

    [Fact]
    public void Firefox148_CreatesMatchingHttp2Shape()
    {
        var snapshot = TlsPresets.Firefox148.CreateOptions().Snapshot();

        Assert.Same(TlsProfiles.Firefox148, snapshot.Profile);
        Assert.Equal(65_536U, snapshot.Http2.HeaderTableSize);
        Assert.Equal(131_072U, snapshot.Http2.InitialWindowSize);
        Assert.Equal(16_384U, snapshot.Http2.MaxFrameSize);
        Assert.Equal(12_517_377U, snapshot.Http2.ConnectionWindowIncrement);
        Assert.Equal(
            [":method", ":path", ":authority", ":scheme"],
            snapshot.Http2.PseudoHeaderOrder);
        Assert.Equal(41, snapshot.Http2.HeaderPriority?.Weight);
    }

    [Fact]
    public void Android11_CreatesMatchingOkHttpShape()
    {
        var options = TlsPresets.Android11.CreateOptions();
        var snapshot = options.Snapshot();

        Assert.Same(TlsProfiles.Android11, snapshot.Profile);
        Assert.Equal(
            [TlsHttp2Setting.InitialWindowSize],
            snapshot.Http2.SettingsOrder);
        Assert.Equal(16_777_216U, snapshot.Http2.InitialWindowSize);
        Assert.Equal(16_711_681U, snapshot.Http2.ConnectionWindowIncrement);
        Assert.Equal(1, snapshot.Http2.HeaderPriority?.Weight);
        Assert.Equal("okhttp/4.10.0", options.DefaultHeaders["User-Agent"]);
    }

    [Fact]
    public void FamilyAliasesPointAtCurrentVersionedPresets()
    {
        Assert.Same(TlsPresets.Chrome133, TlsPresets.Chrome);
        Assert.Same(TlsPresets.Firefox148, TlsPresets.Firefox);
        Assert.Same(TlsPresets.Android11, TlsPresets.Android);
    }
}
