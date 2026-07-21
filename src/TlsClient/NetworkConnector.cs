using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace TlsClient;

internal sealed class DnsEndpointResolver
{
    private readonly object _sync = new();
    private readonly Dictionary<string, CacheEntry> _cache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _refreshInterval;
    private readonly int _capacity;
    private readonly Func<string, CancellationToken, ValueTask<IReadOnlyList<IPAddress>>>? _resolver;
    private readonly Action<TlsConnectEvent>? _observer;
    private readonly TimeProvider _timeProvider;

    public DnsEndpointResolver(TlsSessionConfiguration configuration)
        : this(
            configuration.DnsRefreshInterval,
            configuration.MaximumDnsCacheEntries,
            configuration.DnsResolver,
            configuration.ConnectObserver,
            TimeProvider.System)
    {
    }

    internal DnsEndpointResolver(
        TimeSpan refreshInterval,
        int capacity,
        Func<string, CancellationToken, ValueTask<IReadOnlyList<IPAddress>>>? resolver,
        Action<TlsConnectEvent>? observer,
        TimeProvider timeProvider)
    {
        _refreshInterval = refreshInterval;
        _capacity = capacity;
        _resolver = resolver;
        _observer = observer;
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    public async ValueTask<IPAddress[]> ResolveAsync(
        string host,
        int port,
        Guid connectionId,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }

        var now = _timeProvider.GetUtcNow();
        IPAddress[]? cachedAddresses = null;
        lock (_sync)
        {
            if (_cache.TryGetValue(host, out var cached) && cached.ExpiresAt > now)
            {
                cached.LastUsed = now;
                cachedAddresses = (IPAddress[])cached.Addresses.Clone();
            }
        }
        if (cachedAddresses is not null)
        {
            TlsConnectTelemetry.Emit(
                _observer,
                connectionId,
                TlsConnectEventKind.DnsCacheHit,
                host,
                port,
                addressCount: cachedAddresses.Length);
            return cachedAddresses;
        }

        TlsConnectTelemetry.Emit(
            _observer,
            connectionId,
            TlsConnectEventKind.DnsResolutionStarted,
            host,
            port);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            var resolved = _resolver is null
                ? await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false)
                : await _resolver(host, cancellationToken).ConfigureAwait(false);
            if (resolved is null)
            {
                throw new InvalidOperationException("The custom DNS resolver returned null.");
            }
            var addresses = resolved
                .Where(address => address is not null && address.AddressFamily is
                    AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Distinct()
                .Take(64)
                .ToArray();
            if (addresses.Length == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }

            var expiresAt = _refreshInterval == Timeout.InfiniteTimeSpan
                ? DateTimeOffset.MaxValue
                : _timeProvider.GetUtcNow() + _refreshInterval;
            lock (_sync)
            {
                RemoveExpiredEntries(_timeProvider.GetUtcNow());
                if (!_cache.ContainsKey(host) && _cache.Count >= _capacity)
                {
                    var oldest = _cache.MinBy(pair => pair.Value.LastUsed);
                    _cache.Remove(oldest.Key);
                }
                _cache[host] = new CacheEntry(
                    (IPAddress[])addresses.Clone(),
                    expiresAt,
                    _timeProvider.GetUtcNow());
            }
            TlsConnectTelemetry.Emit(
                _observer,
                connectionId,
                TlsConnectEventKind.DnsResolutionCompleted,
                host,
                port,
                addressCount: addresses.Length,
                elapsed: stopwatch.Elapsed);
            return addresses;
        }
        catch (Exception exception)
        {
            TlsConnectTelemetry.Emit(
                _observer,
                connectionId,
                TlsConnectEventKind.DnsResolutionFailed,
                host,
                port,
                elapsed: stopwatch.Elapsed,
                exception: exception);
            throw;
        }
    }

    private void RemoveExpiredEntries(DateTimeOffset now)
    {
        foreach (var key in _cache
            .Where(pair => pair.Value.ExpiresAt <= now)
            .Select(pair => pair.Key)
            .ToArray())
        {
            _cache.Remove(key);
        }
    }

    private sealed class CacheEntry(
        IPAddress[] addresses,
        DateTimeOffset expiresAt,
        DateTimeOffset lastUsed)
    {
        public IPAddress[] Addresses { get; } = addresses;

        public DateTimeOffset ExpiresAt { get; } = expiresAt;

        public DateTimeOffset LastUsed { get; set; } = lastUsed;
    }
}

internal static class HappyEyeballsConnector
{
    public static async ValueTask<TcpClient> ConnectAsync(
        IReadOnlyList<IPAddress> addresses,
        string host,
        int port,
        TimeSpan attemptDelay,
        Guid connectionId,
        Action<TlsConnectEvent>? observer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        var ordered = Interleave(addresses);
        if (ordered.Length == 0)
        {
            throw new SocketException((int)SocketError.AddressFamilyNotSupported);
        }

        using var raceCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        var active = new List<Task<TcpAttempt>>();
        var failures = new List<Exception>();
        var nextAddress = 0;
        active.Add(AttemptAsync(ordered[nextAddress++], host, port, connectionId, observer,
            raceCancellation.Token));

        while (active.Count != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Task completed;
            CancellationTokenSource? delayCancellation = null;
            if (nextAddress < ordered.Length)
            {
                delayCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                    raceCancellation.Token);
                var delayTask = Task.Delay(attemptDelay, delayCancellation.Token);
                var candidates = active.Cast<Task>().Append(delayTask).ToArray();
                completed = await Task.WhenAny(candidates).ConfigureAwait(false);
                if (ReferenceEquals(completed, delayTask))
                {
                    delayCancellation.Dispose();
                    cancellationToken.ThrowIfCancellationRequested();
                    active.Add(AttemptAsync(
                        ordered[nextAddress++],
                        host,
                        port,
                        connectionId,
                        observer,
                        raceCancellation.Token));
                    continue;
                }
            }
            else
            {
                completed = await Task.WhenAny(active).ConfigureAwait(false);
            }

            if (delayCancellation is not null)
            {
                await delayCancellation.CancelAsync().ConfigureAwait(false);
                delayCancellation.Dispose();
            }
            var attemptTask = (Task<TcpAttempt>)completed;
            active.Remove(attemptTask);
            var attempt = await attemptTask.ConfigureAwait(false);
            if (attempt.Client is not null)
            {
                await raceCancellation.CancelAsync().ConfigureAwait(false);
                foreach (var other in active)
                {
                    var loser = await other.ConfigureAwait(false);
                    loser.Client?.Dispose();
                }
                TlsConnectTelemetry.Emit(
                    observer,
                    connectionId,
                    TlsConnectEventKind.TcpConnected,
                    host,
                    port,
                    attempt.Address,
                    elapsed: attempt.Elapsed);
                return attempt.Client;
            }
            if (attempt.Exception is not null)
            {
                failures.Add(attempt.Exception);
            }

            if (nextAddress < ordered.Length)
            {
                active.Add(AttemptAsync(
                    ordered[nextAddress++],
                    host,
                    port,
                    connectionId,
                    observer,
                    raceCancellation.Token));
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        throw new HttpRequestException(
            $"TCP connection to {host}:{port} failed for every resolved address.",
            failures.Count == 1 ? failures[0] : new AggregateException(failures));
    }

    internal static IPAddress[] Interleave(IReadOnlyList<IPAddress> addresses)
    {
        var ipv6 = new Queue<IPAddress>(addresses.Where(address =>
            address.AddressFamily == AddressFamily.InterNetworkV6));
        var ipv4 = new Queue<IPAddress>(addresses.Where(address =>
            address.AddressFamily == AddressFamily.InterNetwork));
        var preferIpv6 = addresses.FirstOrDefault(address => address.AddressFamily is
            AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)?.AddressFamily ==
            AddressFamily.InterNetworkV6;
        var output = new List<IPAddress>(ipv6.Count + ipv4.Count);
        while (ipv6.Count != 0 || ipv4.Count != 0)
        {
            var preferred = preferIpv6 ? ipv6 : ipv4;
            var alternate = preferIpv6 ? ipv4 : ipv6;
            if (preferred.Count != 0)
            {
                output.Add(preferred.Dequeue());
            }
            if (alternate.Count != 0)
            {
                output.Add(alternate.Dequeue());
            }
        }
        return output.ToArray();
    }

    private static async Task<TcpAttempt> AttemptAsync(
        IPAddress address,
        string host,
        int port,
        Guid connectionId,
        Action<TlsConnectEvent>? observer,
        CancellationToken cancellationToken)
    {
        TlsConnectTelemetry.Emit(
            observer,
            connectionId,
            TlsConnectEventKind.TcpAttemptStarted,
            host,
            port,
            address);
        var stopwatch = Stopwatch.StartNew();
        var client = new TcpClient(address.AddressFamily) { NoDelay = true };
        try
        {
            await client.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
            return new TcpAttempt(address, client, stopwatch.Elapsed, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            client.Dispose();
            return new TcpAttempt(address, null, stopwatch.Elapsed, null);
        }
        catch (Exception exception)
        {
            client.Dispose();
            TlsConnectTelemetry.Emit(
                observer,
                connectionId,
                TlsConnectEventKind.TcpAttemptFailed,
                host,
                port,
                address,
                elapsed: stopwatch.Elapsed,
                exception: exception);
            return new TcpAttempt(address, null, stopwatch.Elapsed, exception);
        }
    }

    private sealed record TcpAttempt(
        IPAddress Address,
        TcpClient? Client,
        TimeSpan Elapsed,
        Exception? Exception);
}
