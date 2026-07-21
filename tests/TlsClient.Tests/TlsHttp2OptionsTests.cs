namespace TlsClient.Tests;

public sealed class TlsHttp2OptionsTests
{
    [Fact]
    public void Snapshot_PreservesExactSettingsAndPseudoHeaderOrder()
    {
        var options = new TlsHttp2Options
        {
            SettingsOrder =
            [
                TlsHttp2Setting.EnablePush,
                TlsHttp2Setting.HeaderTableSize,
            ],
            PseudoHeaderOrder = [":scheme", ":method", ":path", ":authority"],
            PriorityUpdate = "u=2",
        };

        var snapshot = options.Snapshot();

        Assert.Equal(options.SettingsOrder, snapshot.SettingsOrder);
        Assert.Equal(options.PseudoHeaderOrder, snapshot.PseudoHeaderOrder);
        Assert.Equal("u=2", snapshot.PriorityUpdate);
    }

    [Fact]
    public void Snapshot_AllowsOmittingEnablePushForProfilesThatCancelPush()
    {
        var options = new TlsHttp2Options
        {
            SettingsOrder = [TlsHttp2Setting.InitialWindowSize],
        };

        var snapshot = options.Snapshot();

        Assert.Equal([TlsHttp2Setting.InitialWindowSize], snapshot.SettingsOrder);
    }

    [Fact]
    public void Snapshot_RejectsSelfDependentInitialPriorityFrame()
    {
        var frame = new TlsHttp2PriorityFrame(3);
        frame.Priority.StreamDependency = 3;
        var options = new TlsHttp2Options { InitialPriorityFrames = [frame] };

        Assert.Throws<ArgumentException>(() => options.Snapshot());
    }
}
