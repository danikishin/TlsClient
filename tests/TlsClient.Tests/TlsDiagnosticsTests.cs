using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsDiagnosticsTests
{
    [Fact]
    public async Task HandshakeObserverAndActivities_AreStructuredChainedAndRedacted()
    {
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var serverTask = ServeOnceAsync(listener, serverCredential, timeout.Token);
        var diagnostics = new ConcurrentQueue<TlsHandshakeDiagnostic>();
        var rawEvents = new ConcurrentQueue<TlsHandshakeEvent>();
        var stoppedActivities = new ConcurrentQueue<Activity>();
        using var activityListener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == TlsDiagnostics.ActivitySourceName,
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stoppedActivities.Enqueue,
        };
        ActivitySource.AddActivityListener(activityListener);

        var options = new TlsSessionOptions
        {
            Profile = TlsProfiles.Modern,
            HttpVersionPolicy = TlsHttpVersionPolicy.Http11Only,
            HandshakeObserver = diagnostic =>
            {
                diagnostics.Enqueue(diagnostic);
                throw new InvalidOperationException("Instrumentation must not abort TLS.");
            },
            ConfigureTls = tls =>
            {
                tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
                tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
                tls.CertificateValidation.DisableCertificateDownloads = true;
                tls.HandshakeEventObserver = rawEvents.Enqueue;
            },
        };
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://127.0.0.1:{port}/diagnostics?token=top-secret",
            timeout.Token);
        await serverTask;

        Assert.Equal("ok", response.Text);
        Assert.NotEmpty(diagnostics);
        Assert.Equal(rawEvents.Count, diagnostics.Count);
        Assert.Equal(
            diagnostics.Select(item => item.SequenceNumber).Order(),
            diagnostics.Select(item => item.SequenceNumber));
        Assert.Contains(diagnostics, item => item.Kind == TlsHandshakeEventKind.ClientHello);
        Assert.Contains(diagnostics, item => item.Kind == TlsHandshakeEventKind.ServerHello);
        Assert.Contains(diagnostics, item => item.Kind == TlsHandshakeEventKind.HandshakeCompleted);
        Assert.All(diagnostics, item =>
        {
            Assert.Equal("127.0.0.1", item.Host);
            Assert.Equal(port, item.Port);
            Assert.NotEqual(Guid.Empty, item.ConnectionId);
        });

        var requestActivity = Assert.Single(
            stoppedActivities,
            activity => activity.OperationName == "GET" &&
                Equals(activity.GetTagItem("server.port"), port));
        Assert.Equal(ActivityKind.Client, requestActivity.Kind);
        Assert.Equal("GET", requestActivity.GetTagItem("http.request.method"));
        Assert.Equal(200, requestActivity.GetTagItem("http.response.status_code"));
        Assert.Equal("1.1", requestActivity.GetTagItem("network.protocol.version"));
        Assert.Contains(
            "?REDACTED",
            Assert.IsType<string>(requestActivity.GetTagItem("url.full")),
            StringComparison.Ordinal);

        var connectionActivity = Assert.Single(
            stoppedActivities,
            activity => activity.OperationName == "tlsclient.connect" &&
                activity.ParentSpanId == requestActivity.SpanId);
        Assert.Equal(ActivityStatusCode.Ok, connectionActivity.Status);
        Assert.Equal("1.3", connectionActivity.GetTagItem("tls.protocol.version"));
        Assert.Contains(
            connectionActivity.Events,
            item => item.Name == "tlsclient.handshake.client_hello");
        Assert.Contains(
            connectionActivity.Events,
            item => item.Name == "tlsclient.connect.tls_handshake_completed");

        var telemetryText = string.Join(
            '\n',
            stoppedActivities.SelectMany(activity =>
                activity.TagObjects.Select(tag => $"{tag.Key}={tag.Value}")
                    .Concat(activity.Events.SelectMany(item =>
                        item.Tags.Select(tag => $"{tag.Key}={tag.Value}")))));
        Assert.DoesNotContain("top-secret", telemetryText, StringComparison.Ordinal);
    }

    private static async Task ServeOnceAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["http/1.1"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);
        await ReadHeadersAsync(stream, cancellationToken);
        await stream.WriteAsync(
            Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task ReadHeadersAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            length += read;
            if (length >= 4 && buffer.AsSpan(0, length).EndsWith("\r\n\r\n"u8))
            {
                return;
            }
        }
        throw new InvalidDataException("Request headers exceeded the test limit.");
    }
}
