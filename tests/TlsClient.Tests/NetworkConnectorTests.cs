using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace TlsClient.Tests;

public sealed class NetworkConnectorTests
{
    [Fact]
    public async Task Resolver_CachesDefensiveCopiesUntilRefreshIntervalExpires()
    {
        var now = new ManualTimeProvider(
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var resolutions = 0;
        var events = new List<TlsConnectEvent>();
        var resolver = new DnsEndpointResolver(
            TimeSpan.FromMinutes(5),
            2,
            (_, _) =>
            {
                resolutions++;
                return ValueTask.FromResult<IReadOnlyList<IPAddress>>(
                    [IPAddress.IPv6Loopback, IPAddress.Loopback]);
            },
            events.Add,
            now);

        var first = await resolver.ResolveAsync("dual.test", 443, Guid.NewGuid(), default);
        first[0] = IPAddress.Any;
        var cached = await resolver.ResolveAsync("dual.test", 443, Guid.NewGuid(), default);

        Assert.Equal(1, resolutions);
        Assert.Equal(IPAddress.IPv6Loopback, cached[0]);
        Assert.Contains(events, item => item.Kind == TlsConnectEventKind.DnsCacheHit);

        now.Advance(TimeSpan.FromMinutes(5));
        _ = await resolver.ResolveAsync("dual.test", 443, Guid.NewGuid(), default);
        Assert.Equal(2, resolutions);
    }

    [Fact]
    public async Task Resolver_EvictsLeastRecentlyUsedHostnameAtCapacity()
    {
        var now = new ManualTimeProvider(
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var resolutions = 0;
        var resolver = new DnsEndpointResolver(
            Timeout.InfiniteTimeSpan,
            2,
            (_, _) =>
            {
                resolutions++;
                return ValueTask.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
            },
            null,
            now);

        _ = await resolver.ResolveAsync("one.test", 443, Guid.NewGuid(), default);
        now.Advance(TimeSpan.FromSeconds(1));
        _ = await resolver.ResolveAsync("two.test", 443, Guid.NewGuid(), default);
        now.Advance(TimeSpan.FromSeconds(1));
        _ = await resolver.ResolveAsync("two.test", 443, Guid.NewGuid(), default);
        now.Advance(TimeSpan.FromSeconds(1));
        _ = await resolver.ResolveAsync("three.test", 443, Guid.NewGuid(), default);
        _ = await resolver.ResolveAsync("one.test", 443, Guid.NewGuid(), default);

        Assert.Equal(4, resolutions);
    }

    [Fact]
    public async Task HappyEyeballs_StartsNextFamilyWithinConfiguredDelay()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var connectionId = Guid.NewGuid();
        var events = new ConcurrentQueue<TlsConnectEvent>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var stopwatch = Stopwatch.StartNew();

        using var connected = await HappyEyeballsConnector.ConnectAsync(
            [IPAddress.IPv6Loopback, IPAddress.Loopback],
            "dual.test",
            port,
            TimeSpan.FromMilliseconds(100),
            connectionId,
            events.Enqueue,
            timeout.Token);
        using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2));
        Assert.Equal(2, events.Count(item => item.Kind == TlsConnectEventKind.TcpAttemptStarted));
        var winner = Assert.Single(events, item => item.Kind == TlsConnectEventKind.TcpConnected);
        Assert.Equal(IPAddress.Loopback, winner.Address);
        Assert.Equal(connectionId, winner.ConnectionId);
    }

    [Fact]
    public void Interleave_AlternatesAddressFamiliesWithoutChangingFamilyOrder()
    {
        var v4First = IPAddress.Parse("192.0.2.1");
        var v4Second = IPAddress.Parse("192.0.2.2");
        var v6First = IPAddress.Parse("2001:db8::1");
        var v6Second = IPAddress.Parse("2001:db8::2");

        var actual = HappyEyeballsConnector.Interleave(
            [v6First, v6Second, v4First, v4Second]);

        Assert.Equal([v6First, v4First, v6Second, v4Second], actual);
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan value) => _now += value;
    }
}
