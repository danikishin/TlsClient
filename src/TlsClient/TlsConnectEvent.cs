using System.Net;

namespace TlsClient;

/// <summary>Identifies one stage of establishing a new network connection.</summary>
public enum TlsConnectEventKind
{
    /// <summary>A cached DNS result was reused.</summary>
    DnsCacheHit,

    /// <summary>DNS resolution started.</summary>
    DnsResolutionStarted,

    /// <summary>DNS resolution completed.</summary>
    DnsResolutionCompleted,

    /// <summary>DNS resolution failed.</summary>
    DnsResolutionFailed,

    /// <summary>One TCP address attempt started.</summary>
    TcpAttemptStarted,

    /// <summary>One TCP address attempt failed.</summary>
    TcpAttemptFailed,

    /// <summary>A TCP address attempt won the Happy Eyeballs race.</summary>
    TcpConnected,

    /// <summary>An HTTP CONNECT tunnel started.</summary>
    ProxyTunnelStarted,

    /// <summary>An HTTP CONNECT tunnel completed.</summary>
    ProxyTunnelCompleted,

    /// <summary>An HTTP CONNECT tunnel failed.</summary>
    ProxyTunnelFailed,

    /// <summary>The SharpTls handshake started.</summary>
    TlsHandshakeStarted,

    /// <summary>The SharpTls handshake completed.</summary>
    TlsHandshakeCompleted,

    /// <summary>The SharpTls handshake failed.</summary>
    TlsHandshakeFailed,
}

/// <summary>Reports a structured, non-secret connection-establishment event.</summary>
public sealed record TlsConnectEvent
{
    internal TlsConnectEvent(
        Guid connectionId,
        TlsConnectEventKind kind,
        string host,
        int port,
        IPAddress? address,
        int addressCount,
        TimeSpan elapsed,
        string? applicationProtocol,
        Exception? exception)
    {
        ConnectionId = connectionId;
        Kind = kind;
        Host = host;
        Port = port;
        Address = address;
        AddressCount = addressCount;
        Elapsed = elapsed;
        ApplicationProtocol = applicationProtocol;
        Exception = exception;
        Timestamp = DateTimeOffset.UtcNow;
    }

    /// <summary>Gets the identifier shared by events for one connection.</summary>
    public Guid ConnectionId { get; }

    /// <summary>Gets the event stage.</summary>
    public TlsConnectEventKind Kind { get; }

    /// <summary>Gets the host being resolved or connected.</summary>
    public string Host { get; }

    /// <summary>Gets the TCP port.</summary>
    public int Port { get; }

    /// <summary>Gets the attempted or selected IP address, when applicable.</summary>
    public IPAddress? Address { get; }

    /// <summary>Gets the number of addresses returned by DNS, when applicable.</summary>
    public int AddressCount { get; }

    /// <summary>Gets elapsed time for this stage or attempt.</summary>
    public TimeSpan Elapsed { get; }

    /// <summary>Gets the negotiated ALPN value after a completed TLS handshake.</summary>
    public string? ApplicationProtocol { get; }

    /// <summary>Gets the failure associated with a failed stage.</summary>
    public Exception? Exception { get; }

    /// <summary>Gets when the event was emitted.</summary>
    public DateTimeOffset Timestamp { get; }
}

internal static class TlsConnectTelemetry
{
    public static void Emit(
        Action<TlsConnectEvent>? observer,
        Guid connectionId,
        TlsConnectEventKind kind,
        string host,
        int port,
        IPAddress? address = null,
        int addressCount = 0,
        TimeSpan elapsed = default,
        string? applicationProtocol = null,
        Exception? exception = null)
    {
        var connectEvent = new TlsConnectEvent(
            connectionId,
            kind,
            host,
            port,
            address,
            addressCount,
            elapsed,
            applicationProtocol,
            exception);
        TlsDiagnostics.RecordConnectEvent(connectEvent);
        if (observer is null)
        {
            return;
        }
        try
        {
            observer(connectEvent);
        }
        catch (Exception)
        {
            // Instrumentation cannot change connection behavior.
        }
    }
}
