using System.Net.Sockets;
using System.Diagnostics;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient;

internal sealed class SharpTlsTransport : IAsyncDisposable
{
    private readonly TcpClient? _tcpClient;
    private readonly CustomTlsClient _tlsClient;
    private int _disposed;

    private SharpTlsTransport(
        TcpClient? tcpClient,
        CustomTlsClient tlsClient,
        CustomTlsStream stream,
        TlsConnectionInfo tlsInfo)
    {
        _tcpClient = tcpClient;
        _tlsClient = tlsClient;
        Stream = stream;
        TlsInfo = tlsInfo;
    }

    public CustomTlsStream Stream { get; }

    public TlsConnectionInfo TlsInfo { get; }

    public string? ApplicationProtocol => _tlsClient.NegotiatedApplicationProtocol;

    public static async ValueTask<SharpTlsTransport> ConnectAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        DnsEndpointResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        var connectionId = Guid.NewGuid();
        using var activity = TlsDiagnostics.StartConnection(
            origin,
            connectionId,
            configuration.ProfileRoller?.Name ?? configuration.Profile.Name);
        try
        {
            var transport = await ConnectCoreAsync(
                origin,
                versionPolicy,
                proxy,
                configuration,
                tls13SessionCache,
                tls12SessionCache,
                dnsResolver,
                connectionId,
                activity,
                cancellationToken).ConfigureAwait(false);
            TlsDiagnostics.CompleteConnection(activity, transport.TlsInfo);
            return transport;
        }
        catch (Exception exception)
        {
            TlsDiagnostics.RecordFailure(activity, exception);
            throw;
        }
    }

    private static async ValueTask<SharpTlsTransport> ConnectCoreAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        DnsEndpointResolver dnsResolver,
        Guid connectionId,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        if (configuration.EchDnsResolver is not null)
        {
            return await ConnectWithEchDnsAsync(
                origin,
                versionPolicy,
                proxy,
                configuration,
                tls13SessionCache,
                tls12SessionCache,
                dnsResolver,
                activity,
                cancellationToken).ConfigureAwait(false);
        }

        if (configuration.ProfileRoller is not null)
        {
            return await ConnectWithRollerAsync(
                origin,
                versionPolicy,
                proxy,
                configuration,
                tls13SessionCache,
                tls12SessionCache,
                connectionId,
                activity,
                cancellationToken).ConfigureAwait(false);
        }

        TcpClient? tcpClient = null;
        CustomTlsClient? tlsClient = null;
        try
        {
            var connectHost = proxy?.Address.IdnHost ?? origin.IdnHost;
            var connectPort = proxy?.EffectivePort ?? origin.Port;
            var addresses = await dnsResolver.ResolveAsync(
                connectHost,
                connectPort,
                connectionId,
                cancellationToken).ConfigureAwait(false);
            tcpClient = await HappyEyeballsConnector.ConnectAsync(
                addresses,
                connectHost,
                connectPort,
                configuration.HappyEyeballsDelay,
                connectionId,
                configuration.ConnectObserver,
                cancellationToken).ConfigureAwait(false);
            var networkStream = tcpClient.GetStream();

            if (proxy is not null)
            {
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.ProxyTunnelStarted,
                    connectHost,
                    connectPort);
                var proxyStopwatch = Stopwatch.StartNew();
                try
                {
                    await ProxyTunnel.EstablishAsync(
                        networkStream,
                        origin,
                        proxy,
                        configuration.MaximumResponseHeaderBytes,
                        cancellationToken).ConfigureAwait(false);
                    TlsConnectTelemetry.Emit(
                        configuration.ConnectObserver,
                        connectionId,
                        TlsConnectEventKind.ProxyTunnelCompleted,
                        connectHost,
                        connectPort,
                        elapsed: proxyStopwatch.Elapsed);
                }
                catch (Exception exception)
                {
                    TlsConnectTelemetry.Emit(
                        configuration.ConnectObserver,
                        connectionId,
                        TlsConnectEventKind.ProxyTunnelFailed,
                        connectHost,
                        connectPort,
                        elapsed: proxyStopwatch.Elapsed,
                        exception: exception);
                    throw;
                }
            }

            var tlsOptions = new CustomTlsClientOptions
            {
                ServerName = origin.IdnHost,
                ClientHello = configuration.Profile.GetClientHello(origin.IdnHost, versionPolicy),
                TcpNoDelay = true,
            };
            tlsOptions.CertificateValidation.DangerouslySkipServerCertificateValidation =
                configuration.DangerouslySkipServerCertificateValidation;
            configuration.ConfigureTls?.Invoke(tlsOptions);
            configuration.ClientCertificates.Apply(tlsOptions);
            if (tlsOptions.SessionCache is null && tlsOptions.ClientHello.Spec.SupportsSessionResumption)
            {
                tlsOptions.SessionCache = tls13SessionCache;
            }
            if (tlsOptions.Tls12SessionCache is null &&
                tlsOptions.ClientHello.Spec.SupportedVersions.SequenceEqual(
                    [SharpTls.Protocol.TlsProtocolVersion.Tls12]))
            {
                tlsOptions.Tls12SessionCache = tls12SessionCache;
            }
            ApplyCertificatePins(tlsOptions, configuration.CertificatePins);
            TlsDiagnostics.AttachHandshakeObserver(
                tlsOptions,
                configuration.HandshakeObserver,
                connectionId,
                origin.IdnHost,
                origin.Port,
                activity);

            tlsClient = new CustomTlsClient(tlsOptions);
            TlsConnectTelemetry.Emit(
                configuration.ConnectObserver,
                connectionId,
                TlsConnectEventKind.TlsHandshakeStarted,
                origin.IdnHost,
                origin.Port);
            var handshakeStopwatch = Stopwatch.StartNew();
            try
            {
                await tlsClient.AuthenticateAsync(
                    networkStream,
                    origin.IdnHost,
                    leaveOpen: false,
                    cancellationToken).ConfigureAwait(false);
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeCompleted,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    applicationProtocol: tlsClient.NegotiatedApplicationProtocol);
            }
            catch (Exception exception)
            {
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeFailed,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    exception: exception);
                throw;
            }
            ValidateApplicationProtocol(tlsClient.NegotiatedApplicationProtocol, versionPolicy);

            var state = tlsClient.GetConnectionState();
            var tlsInfo = new TlsConnectionInfo(
                configuration.Profile.Name,
                state.ProtocolVersion,
                state.CipherSuite,
                state.Group,
                state.ApplicationProtocol,
                state.SessionWasResumed,
                state.UsedHelloRetryRequest,
                state.EncryptedClientHelloAccepted,
                state.PeerCertificateChain);
            var stream = tlsClient.OpenApplicationStream(leaveClientOpen: true);
            return new SharpTlsTransport(tcpClient, tlsClient, stream, tlsInfo);
        }
        catch
        {
            if (tlsClient is not null)
            {
                await tlsClient.DisposeAsync().ConfigureAwait(false);
            }
            tcpClient?.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await _tlsClient.CloseAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Closing is best-effort after a response or transport failure.
        }
        await Stream.DisposeAsync().ConfigureAwait(false);
        await _tlsClient.DisposeAsync().ConfigureAwait(false);
        _tcpClient?.Dispose();
    }

    private static async ValueTask<SharpTlsTransport> ConnectWithRollerAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        Guid connectionId,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        if (proxy is not null)
        {
            throw new InvalidOperationException(
                "ProfileRoller uses SharpTls direct connections and cannot route through a proxy.");
        }
        if (versionPolicy != TlsHttpVersionPolicy.PreferHttp2)
        {
            throw new InvalidOperationException(
                "ProfileRoller requires PreferHttp2 so the application can honor each candidate's ALPN.");
        }
        if (System.Net.IPAddress.TryParse(origin.IdnHost, out _))
        {
            throw new InvalidOperationException(
                "ProfileRoller requires a DNS origin because its candidates preserve their SNI layout.");
        }

        var roller = configuration.ProfileRoller!;
        var tlsOptions = new CustomTlsClientOptions
        {
            ServerName = origin.IdnHost,
            ClientHello = configuration.Profile.ClientHello,
            TcpNoDelay = true,
        };
        tlsOptions.CertificateValidation.DangerouslySkipServerCertificateValidation =
            configuration.DangerouslySkipServerCertificateValidation;
        configuration.ConfigureTls?.Invoke(tlsOptions);
        configuration.ClientCertificates.Apply(tlsOptions);
        if (tlsOptions.SessionCache is null && tlsOptions.ClientHello.Spec.SupportsSessionResumption)
        {
            tlsOptions.SessionCache = tls13SessionCache;
        }
        if (tlsOptions.Tls12SessionCache is null &&
            tlsOptions.ClientHello.Spec.SupportedVersions.SequenceEqual(
                [SharpTls.Protocol.TlsProtocolVersion.Tls12]))
        {
            tlsOptions.Tls12SessionCache = tls12SessionCache;
        }
        ApplyCertificatePins(tlsOptions, configuration.CertificatePins);
        TlsDiagnostics.AttachHandshakeObserver(
            tlsOptions,
            configuration.HandshakeObserver,
            connectionId,
            origin.IdnHost,
            origin.Port,
            activity);

        CustomTlsClient? tlsClient = null;
        try
        {
            tlsClient = await roller.ConnectAsync(
                tlsOptions,
                origin.IdnHost,
                origin.Port,
                cancellationToken).ConfigureAwait(false);
            ValidateApplicationProtocol(tlsClient.NegotiatedApplicationProtocol, versionPolicy);

            var state = tlsClient.GetConnectionState();
            var tlsInfo = new TlsConnectionInfo(
                roller.Name,
                state.ProtocolVersion,
                state.CipherSuite,
                state.Group,
                state.ApplicationProtocol,
                state.SessionWasResumed,
                state.UsedHelloRetryRequest,
                state.EncryptedClientHelloAccepted,
                state.PeerCertificateChain);
            var stream = tlsClient.OpenApplicationStream(leaveClientOpen: true);
            return new SharpTlsTransport(null, tlsClient, stream, tlsInfo);
        }
        catch
        {
            if (tlsClient is not null)
            {
                await tlsClient.DisposeAsync().ConfigureAwait(false);
            }
            throw;
        }
    }

    private static async ValueTask<SharpTlsTransport> ConnectWithEchDnsAsync(
        Uri origin,
        TlsHttpVersionPolicy versionPolicy,
        TlsProxy? proxy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        DnsEndpointResolver dnsResolver,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        if (proxy is not null)
        {
            throw new InvalidOperationException(
                "EchDnsResolver cannot route an alternative service through a proxy.");
        }
        if (System.Net.IPAddress.TryParse(origin.IdnHost, out _))
        {
            throw new InvalidOperationException("ECH DNS discovery requires a DNS origin.");
        }

        var resolution = await configuration.EchDnsResolver!
            .ResolveAsync(origin.IdnHost, origin.Port, cancellationToken)
            .ConfigureAwait(false);
        var failures = new List<Exception>();
        foreach (var endpoint in resolution.Endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await ConnectEchEndpointAsync(
                    origin,
                    endpoint,
                    versionPolicy,
                    configuration,
                    tls13SessionCache,
                    tls12SessionCache,
                    dnsResolver,
                    activity,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        throw new AggregateException(
            $"Every ECH DNS endpoint for '{origin.IdnHost}:{origin.Port}' failed.",
            failures);
    }

    private static async ValueTask<SharpTlsTransport> ConnectEchEndpointAsync(
        Uri origin,
        TlsEchDnsEndpoint endpoint,
        TlsHttpVersionPolicy versionPolicy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        DnsEndpointResolver dnsResolver,
        Activity? activity,
        CancellationToken cancellationToken)
    {
        var failures = new List<Exception>();
        var hints = endpoint.Ipv6Hints
            .Concat(endpoint.Ipv4Hints)
            .Distinct()
            .ToArray();
        if (hints.Length != 0)
        {
            try
            {
                return await ConnectEchAddressSetAsync(
                    origin,
                    endpoint,
                    hints,
                    versionPolicy,
                    configuration,
                    tls13SessionCache,
                    tls12SessionCache,
                    activity,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        try
        {
            var connectionId = Guid.NewGuid();
            var addresses = await dnsResolver.ResolveAsync(
                endpoint.TargetName,
                endpoint.Port,
                connectionId,
                cancellationToken).ConfigureAwait(false);
            return await ConnectEchAddressSetAsync(
                origin,
                endpoint,
                addresses,
                versionPolicy,
                configuration,
                tls13SessionCache,
                tls12SessionCache,
                activity,
                cancellationToken,
                connectionId).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        throw new AggregateException(
            $"ECH endpoint '{endpoint.TargetName}:{endpoint.Port}' failed.",
            failures);
    }

    private static async ValueTask<SharpTlsTransport> ConnectEchAddressSetAsync(
        Uri origin,
        TlsEchDnsEndpoint endpoint,
        IReadOnlyList<System.Net.IPAddress> addresses,
        TlsHttpVersionPolicy versionPolicy,
        TlsSessionConfiguration configuration,
        Tls13SessionCache tls13SessionCache,
        Tls12SessionCache tls12SessionCache,
        Activity? activity,
        CancellationToken cancellationToken,
        Guid? existingConnectionId = null)
    {
        var connectionId = existingConnectionId ?? Guid.NewGuid();
        TcpClient? tcpClient = null;
        CustomTlsClient? tlsClient = null;
        try
        {
            tcpClient = await HappyEyeballsConnector.ConnectAsync(
                addresses,
                endpoint.TargetName,
                endpoint.Port,
                configuration.HappyEyeballsDelay,
                connectionId,
                configuration.ConnectObserver,
                cancellationToken).ConfigureAwait(false);

            var tlsOptions = new CustomTlsClientOptions
            {
                ServerName = origin.IdnHost,
                ClientHello = configuration.Profile.GetClientHello(
                    origin.IdnHost,
                    versionPolicy),
                TcpNoDelay = true,
            };
            tlsOptions.CertificateValidation.DangerouslySkipServerCertificateValidation =
                configuration.DangerouslySkipServerCertificateValidation;
            configuration.ConfigureTls?.Invoke(tlsOptions);
            configuration.ClientCertificates.Apply(tlsOptions);
            if (tlsOptions.SessionCache is null && tlsOptions.ClientHello.Spec.SupportsSessionResumption)
            {
                tlsOptions.SessionCache = tls13SessionCache;
            }
            if (tlsOptions.Tls12SessionCache is null &&
                tlsOptions.ClientHello.Spec.SupportedVersions.SequenceEqual(
                    [SharpTls.Protocol.TlsProtocolVersion.Tls12]))
            {
                tlsOptions.Tls12SessionCache = tls12SessionCache;
            }
            ApplyCertificatePins(tlsOptions, configuration.CertificatePins);
            endpoint.ConfigureClient(tlsOptions);
            TlsDiagnostics.AttachHandshakeObserver(
                tlsOptions,
                configuration.HandshakeObserver,
                connectionId,
                origin.IdnHost,
                origin.Port,
                activity);

            tlsClient = new CustomTlsClient(tlsOptions);
            TlsConnectTelemetry.Emit(
                configuration.ConnectObserver,
                connectionId,
                TlsConnectEventKind.TlsHandshakeStarted,
                origin.IdnHost,
                origin.Port);
            var handshakeStopwatch = Stopwatch.StartNew();
            try
            {
                await tlsClient.AuthenticateAsync(
                    tcpClient.GetStream(),
                    origin.IdnHost,
                    leaveOpen: false,
                    cancellationToken).ConfigureAwait(false);
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeCompleted,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    applicationProtocol: tlsClient.NegotiatedApplicationProtocol);
            }
            catch (Exception exception)
            {
                TlsConnectTelemetry.Emit(
                    configuration.ConnectObserver,
                    connectionId,
                    TlsConnectEventKind.TlsHandshakeFailed,
                    origin.IdnHost,
                    origin.Port,
                    elapsed: handshakeStopwatch.Elapsed,
                    exception: exception);
                throw;
            }
            ValidateApplicationProtocol(tlsClient.NegotiatedApplicationProtocol, versionPolicy);

            var state = tlsClient.GetConnectionState();
            var tlsInfo = new TlsConnectionInfo(
                configuration.Profile.Name,
                state.ProtocolVersion,
                state.CipherSuite,
                state.Group,
                state.ApplicationProtocol,
                state.SessionWasResumed,
                state.UsedHelloRetryRequest,
                state.EncryptedClientHelloAccepted,
                state.PeerCertificateChain);
            var stream = tlsClient.OpenApplicationStream(leaveClientOpen: true);
            return new SharpTlsTransport(tcpClient, tlsClient, stream, tlsInfo);
        }
        catch
        {
            if (tlsClient is not null)
            {
                await tlsClient.DisposeAsync().ConfigureAwait(false);
            }
            tcpClient?.Dispose();
            throw;
        }
    }

    private static void ValidateApplicationProtocol(
        string? applicationProtocol,
        TlsHttpVersionPolicy versionPolicy)
    {
        var valid = versionPolicy switch
        {
            TlsHttpVersionPolicy.Http11Only => applicationProtocol is null or "http/1.1",
            TlsHttpVersionPolicy.Http2Only => applicationProtocol == "h2",
            _ => applicationProtocol is null or "http/1.1" or "h2",
        };
        if (!valid)
        {
            throw new TlsHttpProtocolException(
                $"The server selected unsupported ALPN '{applicationProtocol ?? "(none)"}'.");
        }
    }

    private static void ApplyCertificatePins(
        CustomTlsClientOptions options,
        TlsCertificatePins pins)
    {
        if (!pins.HasPins)
        {
            return;
        }

        var validation = options.CertificateValidation ??
            throw new InvalidOperationException("ConfigureTls set CertificateValidation to null.");
        var existing = validation.EvidenceValidator;
        validation.EvidenceValidator = async (evidence, cancellationToken) =>
        {
            var result = existing is null
                ? new TlsServerCertificateEvidenceValidationResult(
                    TlsStapledOcspValidationStatus.NotChecked,
                    0)
                : await existing(evidence, cancellationToken).ConfigureAwait(false);
            pins.Validate(evidence);
            return result;
        };
    }

}
