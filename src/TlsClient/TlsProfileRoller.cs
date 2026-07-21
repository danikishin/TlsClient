using SharpTls;

namespace TlsClient;

/// <summary>
/// Wraps SharpTls's bounded, origin-aware ClientHello profile Roller for a session.
/// </summary>
public sealed class TlsProfileRoller
{
    private readonly ClientHelloProfileRoller _roller;

    /// <summary>Creates a Roller named <c>sharptls-roller</c> with default SharpTls policy.</summary>
    public TlsProfileRoller()
        : this("sharptls-roller", new ClientHelloRollerOptions())
    {
    }

    /// <summary>Creates a named Roller and snapshots the supplied SharpTls policy.</summary>
    public TlsProfileRoller(string name, ClientHelloRollerOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(options);
        Name = name;
        _roller = new ClientHelloProfileRoller(options);
    }

    /// <summary>Gets the diagnostic name reported by successful TlsClient connections.</summary>
    public string Name { get; }

    /// <summary>Gets the number of successful origin profiles cached by SharpTls.</summary>
    public int CachedOriginCount => _roller.CachedOriginCount;

    /// <summary>Clears every origin-bound successful profile remembered by SharpTls.</summary>
    public void ClearCache() => _roller.ClearCache();

    internal ValueTask<CustomTlsClient> ConnectAsync(
        CustomTlsClientOptions options,
        string host,
        int port,
        CancellationToken cancellationToken) =>
        _roller.ConnectAsync(options, host, port, cancellationToken);
}
