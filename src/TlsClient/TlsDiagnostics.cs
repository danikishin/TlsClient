using System.Diagnostics;
using System.Net;
using SharpTls;
using SharpTls.Protocol;

namespace TlsClient;

/// <summary>
/// Immutable, secret-free view of one SharpTls handshake event, enriched with the
/// connection and origin that produced it.
/// </summary>
public sealed record TlsHandshakeDiagnostic
{
    internal TlsHandshakeDiagnostic(
        Guid connectionId,
        string host,
        int port,
        TlsHandshakeEvent handshakeEvent)
    {
        ConnectionId = connectionId;
        Host = host;
        Port = port;
        SequenceNumber = handshakeEvent.SequenceNumber;
        Kind = handshakeEvent.Kind;
        Direction = handshakeEvent.Direction;
        ProtocolVersion = handshakeEvent.ProtocolVersion;
        EncodedLength = handshakeEvent.EncodedLength;
        ClientHelloFlight = handshakeEvent.ClientHelloFlight;
        Timestamp = DateTimeOffset.UtcNow;
    }

    /// <summary>Gets the identifier shared with connection events for this attempt.</summary>
    public Guid ConnectionId { get; }

    /// <summary>Gets the original HTTPS origin host used for SNI and validation.</summary>
    public string Host { get; }

    /// <summary>Gets the original HTTPS origin port.</summary>
    public int Port { get; }

    /// <summary>Gets the one-based SharpTls event order for this connection.</summary>
    public long SequenceNumber { get; }

    /// <summary>Gets the redacted handshake event classification.</summary>
    public TlsHandshakeEventKind Kind { get; }

    /// <summary>Gets the message direction or local-transition marker.</summary>
    public TlsHandshakeEventDirection Direction { get; }

    /// <summary>Gets the active TLS protocol version when known.</summary>
    public TlsProtocolVersion? ProtocolVersion { get; }

    /// <summary>Gets the encoded handshake length, or zero for local transitions.</summary>
    public int EncodedLength { get; }

    /// <summary>Gets the ClientHello flight for ClientHello events, or null.</summary>
    public TlsClientHelloFlight? ClientHelloFlight { get; }

    /// <summary>Gets when TlsClient observed the event.</summary>
    public DateTimeOffset Timestamp { get; }
}

/// <summary>OpenTelemetry-compatible tracing hooks emitted by TlsClient.</summary>
public static class TlsDiagnostics
{
    /// <summary>Gets the stable ActivitySource name used by TlsClient.</summary>
    public const string ActivitySourceName = "TlsClient";

    /// <summary>Gets the ActivitySource applications can subscribe to or register with OpenTelemetry.</summary>
    public static ActivitySource ActivitySource { get; } = new(
        ActivitySourceName,
        typeof(TlsDiagnostics).Assembly.GetName().Version?.ToString());

    internal static Activity? StartHttpRequest(
        BufferedRequest request,
        int attempt,
        int redirectHop)
    {
        var knownMethod = NormalizeHttpMethod(request.Method);
        var activity = ActivitySource.StartActivity(knownMethod, ActivityKind.Client);
        if (activity is null)
        {
            return null;
        }

        activity.SetTag("http.request.method", knownMethod);
        if (!string.Equals(knownMethod, request.Method, StringComparison.Ordinal))
        {
            activity.SetTag("http.request.method_original", request.Method);
        }
        activity.SetTag("server.address", request.Url.IdnHost);
        activity.SetTag("server.port", request.Url.Port);
        activity.SetTag("url.full", RedactUrl(request.Url));
        activity.SetTag("network.protocol.name", "http");
        activity.SetTag("tlsclient.retry.attempt", attempt);
        activity.SetTag("tlsclient.redirect.hop", redirectHop);
        return activity;
    }

    internal static void CompleteHttpRequest(
        Activity? activity,
        HttpStatusCode statusCode,
        Version version,
        TlsConnectionInfo tlsInfo)
    {
        if (activity is null)
        {
            return;
        }

        activity.SetTag("http.response.status_code", (int)statusCode);
        activity.SetTag("network.protocol.version", FormatHttpVersion(version));
        AddTlsTags(activity, tlsInfo);
        if ((int)statusCode >= 400)
        {
            activity.SetTag("error.type", ((int)statusCode).ToString(
                System.Globalization.CultureInfo.InvariantCulture));
            activity.SetStatus(ActivityStatusCode.Error);
        }
    }

    internal static Activity? StartConnection(Uri origin, Guid connectionId, string profile)
    {
        var activity = ActivitySource.StartActivity("tlsclient.connect", ActivityKind.Client);
        if (activity is null)
        {
            return null;
        }

        activity.SetTag("server.address", origin.IdnHost);
        activity.SetTag("server.port", origin.Port);
        activity.SetTag("network.transport", "tcp");
        activity.SetTag("tlsclient.connection.id", connectionId.ToString("D"));
        activity.SetTag("tlsclient.client_hello.profile", profile);
        return activity;
    }

    internal static void CompleteConnection(Activity? activity, TlsConnectionInfo tlsInfo)
    {
        if (activity is null)
        {
            return;
        }

        AddTlsTags(activity, tlsInfo);
        activity.SetStatus(ActivityStatusCode.Ok);
    }

    internal static void RecordFailure(Activity? activity, Exception exception)
    {
        if (activity is null)
        {
            return;
        }

        activity.SetTag("error.type", exception.GetType().FullName ?? exception.GetType().Name);
        activity.SetStatus(ActivityStatusCode.Error);
    }

    internal static void RecordConnectEvent(TlsConnectEvent connectEvent)
    {
        var activity = Activity.Current;
        if (activity is null)
        {
            return;
        }

        var tags = new ActivityTagsCollection
        {
            { "tlsclient.connection.id", connectEvent.ConnectionId.ToString("D") },
            { "server.address", connectEvent.Host },
            { "server.port", connectEvent.Port },
        };
        if (connectEvent.Address is not null)
        {
            tags.Add("network.peer.address", connectEvent.Address.ToString());
            tags.Add(
                "network.type",
                connectEvent.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    ? "ipv4"
                    : "ipv6");
        }
        if (connectEvent.AddressCount != 0)
        {
            tags.Add("tlsclient.dns.address_count", connectEvent.AddressCount);
        }
        if (connectEvent.Elapsed != default)
        {
            tags.Add("tlsclient.elapsed_ms", connectEvent.Elapsed.TotalMilliseconds);
        }
        if (connectEvent.ApplicationProtocol is not null)
        {
            tags.Add("tlsclient.alpn", connectEvent.ApplicationProtocol);
        }
        if (connectEvent.Exception is not null)
        {
            tags.Add(
                "error.type",
                connectEvent.Exception.GetType().FullName ?? connectEvent.Exception.GetType().Name);
        }

        activity.AddEvent(new ActivityEvent(
            $"tlsclient.connect.{ToEventName(connectEvent.Kind)}",
            connectEvent.Timestamp,
            tags));
    }

    internal static void AttachHandshakeObserver(
        CustomTlsClientOptions options,
        Action<TlsHandshakeDiagnostic>? observer,
        Guid connectionId,
        string host,
        int port,
        Activity? activity)
    {
        var existing = options.HandshakeEventObserver;
        if (existing is null && observer is null && activity is null)
        {
            return;
        }

        options.HandshakeEventObserver = handshakeEvent =>
        {
            // Preserve SharpTls's documented abort semantics for a raw observer configured
            // through ConfigureTls. TlsClient-owned diagnostics remain best-effort.
            existing?.Invoke(handshakeEvent);

            if (observer is not null)
            {
                try
                {
                    observer(new TlsHandshakeDiagnostic(
                        connectionId,
                        host,
                        port,
                        handshakeEvent));
                }
                catch (Exception)
                {
                    // Instrumentation cannot change handshake behavior.
                }
            }

            if (activity is not null)
            {
                try
                {
                    var tags = new ActivityTagsCollection
                    {
                        { "tlsclient.handshake.sequence", handshakeEvent.SequenceNumber },
                        { "tlsclient.handshake.direction", handshakeEvent.Direction.ToString() },
                        { "tlsclient.handshake.encoded_length", handshakeEvent.EncodedLength },
                    };
                    if (handshakeEvent.ProtocolVersion is { } version)
                    {
                        tags.Add("tls.protocol.version", FormatTlsVersion(version));
                    }
                    if (handshakeEvent.ClientHelloFlight is { } flight)
                    {
                        tags.Add("tlsclient.client_hello.flight", flight.ToString());
                    }
                    activity.AddEvent(new ActivityEvent(
                        $"tlsclient.handshake.{ToEventName(handshakeEvent.Kind)}",
                        tags: tags));
                }
                catch (Exception)
                {
                    // Instrumentation cannot change handshake behavior.
                }
            }
        };
    }

    private static void AddTlsTags(Activity activity, TlsConnectionInfo tlsInfo)
    {
        activity.SetTag("tls.protocol.name", "tls");
        activity.SetTag("tls.protocol.version", FormatTlsVersion(tlsInfo.ProtocolVersion));
        activity.SetTag("tls.cipher", tlsInfo.CipherSuite.ToString());
        activity.SetTag("tls.curve", tlsInfo.Group.ToString());
        activity.SetTag("tls.resumed", tlsInfo.SessionWasResumed);
        activity.SetTag("tlsclient.alpn", tlsInfo.ApplicationProtocol);
        activity.SetTag("tlsclient.hello_retry_request", tlsInfo.UsedHelloRetryRequest);
        activity.SetTag("tlsclient.ech.accepted", tlsInfo.EncryptedClientHelloAccepted);
        activity.SetTag("tlsclient.client_hello.profile", tlsInfo.ClientHelloProfile);
    }

    private static string NormalizeHttpMethod(string method) => method switch
    {
        "CONNECT" or "DELETE" or "GET" or "HEAD" or "OPTIONS" or "PATCH" or
        "POST" or "PUT" or "TRACE" => method,
        _ => "_OTHER",
    };

    private static string RedactUrl(Uri url)
    {
        var builder = new UriBuilder(url)
        {
            Fragment = string.Empty,
            Password = string.Empty,
            UserName = string.Empty,
            Query = string.IsNullOrEmpty(url.Query) ? string.Empty : "REDACTED",
        };
        return builder.Uri.AbsoluteUri;
    }

    private static string FormatHttpVersion(Version version) => version.Major switch
    {
        1 => $"1.{version.Minor}",
        _ => version.Major.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    private static string FormatTlsVersion(TlsProtocolVersion version) => version switch
    {
        TlsProtocolVersion.Tls12 => "1.2",
        TlsProtocolVersion.Tls13 => "1.3",
        _ => version.ToString(),
    };

    private static string ToEventName<T>(T value) where T : struct, Enum =>
        string.Concat(value.ToString().Select((character, index) =>
            char.IsUpper(character) && index != 0
                ? $"_{char.ToLowerInvariant(character)}"
                : char.ToLowerInvariant(character).ToString()));
}
