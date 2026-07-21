using System.Net;
using SharpTls;

namespace TlsClient;

internal sealed class TlsConnectionPool : IAsyncDisposable
{
    private readonly TlsSessionConfiguration _configuration;
    private readonly Tls13SessionCache _tls13SessionCache = new();
    private readonly Tls12SessionCache _tls12SessionCache = new();
    private readonly DnsEndpointResolver _dnsResolver;
    private readonly SemaphoreSlim _poolGate = new(1, 1);
    private readonly SemaphoreSlim _poolChanged = new(0, int.MaxValue);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Dictionary<ConnectionKey, List<PooledConnection>> _connections = [];
    private readonly Dictionary<ConnectionKey, int> _pendingConnections = [];
    private int _reservedConnectionCount;
    private int _disposed;

    public TlsConnectionPool(TlsSessionConfiguration configuration)
    {
        _configuration = configuration;
        _dnsResolver = new DnsEndpointResolver(configuration);
    }

    public int Tls13SessionCount => _tls13SessionCache.Count;

    public byte[] ExportTls13SessionState(Tls13SessionStateProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return _tls13SessionCache.ExportEncrypted(protector);
    }

    public void ImportTls13SessionState(
        ReadOnlySpan<byte> protectedState,
        Tls13SessionStateProtector protector)
    {
        ArgumentNullException.ThrowIfNull(protector);
        _tls13SessionCache.ImportEncrypted(protectedState, protector);
    }

    public ValueTask<ConnectionResponse> SendAsync(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        CookieContainer cookies,
        object cookieSync,
        CancellationToken cancellationToken) => SendCoreAsync(
            request,
            sessionHeaders,
            cookies,
            cookieSync,
            null,
            cancellationToken);

    public ValueTask<ConnectionResponse> SendStreamingAsync(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        CookieContainer cookies,
        object cookieSync,
        StreamingResponseContext streamingResponse,
        CancellationToken cancellationToken) => SendCoreAsync(
            request,
            sessionHeaders,
            cookies,
            cookieSync,
            streamingResponse,
            cancellationToken);

    private async ValueTask<ConnectionResponse> SendCoreAsync(
        BufferedRequest request,
        HeaderEntry[] sessionHeaders,
        CookieContainer cookies,
        object cookieSync,
        StreamingResponseContext? streamingResponse,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var proxy = request.HasProxyOverride ? request.Proxy : _configuration.Proxy;
        var key = ConnectionKey.Create(
            request.Url,
            proxy,
            request.HttpVersionPolicy);
        string cookieHeader;
        lock (cookieSync)
        {
            cookieHeader = cookies.GetCookieHeader(request.Url);
        }

        var lease = await RentAsync(key, request.Url, proxy, cancellationToken)
            .ConfigureAwait(false);
        var connection = lease.Entry.Connection;
        try
        {
            var response = await connection.SendAsync(
                request,
                sessionHeaders,
                cookieHeader,
                streamingResponse,
                _configuration,
                cancellationToken).ConfigureAwait(false);
            var tlsInfo = connection.TlsInfo;
            if (!connection.IsReusable)
            {
                await RemoveAsync(lease.Entry).ConfigureAwait(false);
            }
            return new ConnectionResponse(response, tlsInfo);
        }
        catch (Exception exception)
        {
            if (!connection.IsReusable ||
                exception is StaleHttpConnectionException or ObjectDisposedException)
            {
                await RemoveAsync(lease.Entry).ConfigureAwait(false);
            }
            throw;
        }
        finally
        {
            await ReturnAsync(lease).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _lifetime.Cancel();

        await _poolGate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        PooledConnection[] entries;
        try
        {
            entries = _connections.Values.SelectMany(value => value).ToArray();
            _connections.Clear();
            foreach (var entry in entries)
            {
                entry.Removed = true;
                ReleaseConnectionSlotLocked(entry);
            }
        }
        finally
        {
            _poolGate.Release();
        }

        foreach (var entry in entries)
        {
            await entry.Connection.DisposeAsync().ConfigureAwait(false);
        }
        _tls13SessionCache.Dispose();
        _tls12SessionCache.Dispose();
    }

    private async ValueTask<ConnectionLease> RentAsync(
        ConnectionKey key,
        Uri origin,
        TlsProxy? proxy,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            PooledConnection? selected = null;
            List<IHttpConnection> dispose = [];
            var create = false;
            var wakeAnotherWaiter = false;

            await _poolGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                RemoveExpiredConnectionsLocked(key, dispose);

                if (_connections.TryGetValue(key, out var originConnections))
                {
                    selected = originConnections
                        .Where(CanAcceptRequest)
                        .OrderByDescending(entry =>
                            entry.Connection.MaximumConcurrentRequests > 1)
                        .ThenBy(entry => entry.Leases)
                        .ThenByDescending(entry => entry.Connection.LastUsed)
                        .FirstOrDefault();
                }

                if (selected is not null)
                {
                    selected.Leases++;
                    wakeAnotherWaiter = CanAcceptRequest(selected);
                }
                else if (GetPendingConnectionCountLocked(key) == 0 &&
                    GetOriginConnectionCountLocked(key) <
                    _configuration.MaximumConnectionsPerOrigin)
                {
                    if (_reservedConnectionCount >= _configuration.MaximumPooledConnections)
                    {
                        var evicted = FindOldestIdleConnectionLocked();
                        if (evicted is not null)
                        {
                            RemoveEntryLocked(evicted);
                            ReleaseConnectionSlotLocked(evicted);
                            dispose.Add(evicted.Connection);
                        }
                    }

                    if (_reservedConnectionCount < _configuration.MaximumPooledConnections)
                    {
                        ReservePendingConnectionLocked(key);
                        create = true;
                    }
                }
            }
            finally
            {
                _poolGate.Release();
            }

            await DisposeQuietlyAsync(dispose).ConfigureAwait(false);
            if (selected is not null)
            {
                if (wakeAnotherWaiter)
                {
                    SignalPoolChanged();
                }
                return new ConnectionLease(selected);
            }
            if (create)
            {
                return await CreateReservedConnectionAsync(
                    key,
                    origin,
                    proxy,
                    cancellationToken).ConfigureAwait(false);
            }

            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
            try
            {
                await _poolChanged.WaitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (
                _lifetime.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                throw new ObjectDisposedException(nameof(TlsConnectionPool));
            }
        }
    }

    private async ValueTask<ConnectionLease> CreateReservedConnectionAsync(
        ConnectionKey key,
        Uri origin,
        TlsProxy? proxy,
        CancellationToken cancellationToken)
    {
        IHttpConnection connection;
        try
        {
            connection = await HttpConnectionFactory.ConnectAsync(
                origin,
                key.VersionPolicy,
                proxy,
                _configuration,
                _tls13SessionCache,
                _tls12SessionCache,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await CancelPendingConnectionAsync(key).ConfigureAwait(false);
            throw;
        }

        PooledConnection? entry = null;
        await _poolGate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            CompletePendingConnectionLocked(key);
            if (Volatile.Read(ref _disposed) == 0)
            {
                entry = new PooledConnection(key, connection) { Leases = 1 };
                if (!_connections.TryGetValue(key, out var originConnections))
                {
                    originConnections = [];
                    _connections.Add(key, originConnections);
                }
                originConnections.Add(entry);
            }
            else
            {
                _reservedConnectionCount--;
            }
        }
        finally
        {
            _poolGate.Release();
        }

        if (entry is null)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw new ObjectDisposedException(nameof(TlsConnectionPool));
        }
        SignalPoolChanged();
        return new ConnectionLease(entry);
    }

    private async ValueTask CancelPendingConnectionAsync(ConnectionKey key)
    {
        await _poolGate.WaitAsync().ConfigureAwait(false);
        try
        {
            CompletePendingConnectionLocked(key);
            _reservedConnectionCount--;
        }
        finally
        {
            _poolGate.Release();
        }
        SignalPoolChanged();
    }

    private async ValueTask RemoveAsync(PooledConnection entry)
    {
        await _poolGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!entry.Removed)
            {
                RemoveEntryLocked(entry);
            }
        }
        finally
        {
            _poolGate.Release();
        }
        SignalPoolChanged();
    }

    private async ValueTask ReturnAsync(ConnectionLease lease)
    {
        IHttpConnection? dispose = null;
        await _poolGate.WaitAsync().ConfigureAwait(false);
        try
        {
            var entry = lease.Entry;
            if (entry.Leases <= 0)
            {
                throw new InvalidOperationException("A pooled connection lease was returned twice.");
            }
            entry.Leases--;
            if (!entry.Removed &&
                (!entry.Connection.IsReusable || entry.Connection.IsDisposed))
            {
                RemoveEntryLocked(entry);
            }
            if (entry.Removed && entry.Leases == 0 && entry.Counted)
            {
                ReleaseConnectionSlotLocked(entry);
                dispose = entry.Connection;
            }
        }
        finally
        {
            _poolGate.Release();
        }

        if (dispose is not null)
        {
            await DisposeQuietlyAsync([dispose]).ConfigureAwait(false);
        }
        SignalPoolChanged();
    }

    private void RemoveExpiredConnectionsLocked(
        ConnectionKey key,
        List<IHttpConnection> dispose)
    {
        if (!_connections.TryGetValue(key, out var originConnections))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        for (var index = originConnections.Count - 1; index >= 0; index--)
        {
            var entry = originConnections[index];
            var lifetimeExpired = _configuration.PooledConnectionLifetime !=
                Timeout.InfiniteTimeSpan &&
                now - entry.CreatedAt >= _configuration.PooledConnectionLifetime;
            if (lifetimeExpired)
            {
                originConnections.RemoveAt(index);
                entry.Removed = true;
                if (entry.Leases == 0)
                {
                    ReleaseConnectionSlotLocked(entry);
                    dispose.Add(entry.Connection);
                }
                continue;
            }
            if (entry.Leases != 0 ||
                entry.Connection.IsReusable &&
                !entry.Connection.IsDisposed &&
                now - entry.Connection.LastUsed <= _configuration.PooledConnectionIdleTimeout)
            {
                continue;
            }
            originConnections.RemoveAt(index);
            entry.Removed = true;
            ReleaseConnectionSlotLocked(entry);
            dispose.Add(entry.Connection);
        }
        if (originConnections.Count == 0)
        {
            _connections.Remove(key);
        }
    }

    private PooledConnection? FindOldestIdleConnectionLocked() => _connections.Values
        .SelectMany(value => value)
        .Where(entry => entry.Leases == 0)
        .OrderBy(entry => entry.Connection.LastUsed)
        .FirstOrDefault();

    private int GetOriginConnectionCountLocked(ConnectionKey key)
    {
        var live = _connections.TryGetValue(key, out var connections) ? connections.Count : 0;
        return live + GetPendingConnectionCountLocked(key);
    }

    private int GetPendingConnectionCountLocked(ConnectionKey key) =>
        _pendingConnections.TryGetValue(key, out var pending) ? pending : 0;

    private void ReservePendingConnectionLocked(ConnectionKey key)
    {
        _reservedConnectionCount++;
        _pendingConnections[key] =
            (_pendingConnections.TryGetValue(key, out var pending) ? pending : 0) + 1;
    }

    private void CompletePendingConnectionLocked(ConnectionKey key)
    {
        var pending = _pendingConnections[key];
        if (pending == 1)
        {
            _pendingConnections.Remove(key);
        }
        else
        {
            _pendingConnections[key] = pending - 1;
        }
    }

    private void RemoveEntryLocked(PooledConnection entry)
    {
        if (_connections.TryGetValue(entry.Key, out var originConnections))
        {
            originConnections.Remove(entry);
            if (originConnections.Count == 0)
            {
                _connections.Remove(entry.Key);
            }
        }
        entry.Removed = true;
    }

    private void ReleaseConnectionSlotLocked(PooledConnection entry)
    {
        if (!entry.Counted)
        {
            return;
        }
        entry.Counted = false;
        _reservedConnectionCount--;
    }

    private static bool CanAcceptRequest(PooledConnection entry) =>
        !entry.Removed &&
        entry.Connection.IsReusable &&
        !entry.Connection.IsDisposed &&
        entry.Leases < entry.Connection.MaximumConcurrentRequests;

    private static async ValueTask DisposeQuietlyAsync(IEnumerable<IHttpConnection> connections)
    {
        foreach (var connection in connections)
        {
            try
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Pool maintenance must not replace the request's result with a close failure.
            }
        }
    }

    private void SignalPoolChanged()
    {
        try
        {
            _poolChanged.Release();
        }
        catch (SemaphoreFullException)
        {
        }
    }

    private sealed class PooledConnection(ConnectionKey key, IHttpConnection connection)
    {
        public ConnectionKey Key { get; } = key;

        public IHttpConnection Connection { get; } = connection;

        public DateTimeOffset CreatedAt { get; } = DateTimeOffset.UtcNow;

        public int Leases { get; set; }

        public bool Removed { get; set; }

        public bool Counted { get; set; } = true;
    }

    private readonly record struct ConnectionLease(PooledConnection Entry);
}

internal sealed record ConnectionResponse(ParsedHttpResponse Http, TlsConnectionInfo Tls);

internal readonly record struct ConnectionKey(
    string Host,
    int Port,
    string? Proxy,
    TlsHttpVersionPolicy VersionPolicy)
{
    public static ConnectionKey Create(
        Uri uri,
        TlsProxy? proxy,
        TlsHttpVersionPolicy versionPolicy) => new(
        uri.IdnHost.ToLowerInvariant(),
        uri.Port,
        proxy?.PoolKey,
        versionPolicy);
}
