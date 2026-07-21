using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SharpTls;
using SharpTls.Certificates;

namespace TlsClient.Tests;

public sealed class TlsPresetWireTests
{
    public static TheoryData<string, string> PresetFingerprints => new()
    {
        {
            "chrome-133",
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        },
        {
            "firefox-148",
            "1:65536;2:0;4:131072;5:16384|12517377|0:0:41|m,p,a,s"
        },
        {
            "okhttp4-android-11",
            "4:16777216|16711681|0:0:1|m,p,a,s"
        },
    };

    [Theory]
    [MemberData(nameof(PresetFingerprints))]
    public async Task Preset_EmitsCapturedHttp2Fingerprint(
        string presetName,
        string expectedFingerprint)
    {
        var preset = GetPreset(presetName);
        using var certificates = TlsSessionLoopbackTests.TestCertificates.Create();
        using var serverCredential = new TlsServerCertificate(
            certificates.Leaf,
            [certificates.Root]);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var responseReceived = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = CaptureAsync(
            listener,
            serverCredential,
            responseReceived.Task,
            timeout.Token);

        var options = preset.CreateOptions();
        options.HttpVersionPolicy = TlsHttpVersionPolicy.Http2Only;
        options.ConfigureTls = tls =>
        {
            tls.CertificateValidation.CustomTrustRoots = [certificates.Root];
            tls.CertificateValidation.RevocationMode = X509RevocationMode.NoCheck;
            tls.CertificateValidation.DisableCertificateDownloads = true;
        };
        await using var session = new TlsSession(options);

        var response = await session.GetAsync(
            $"https://127.0.0.1:{port}/capture",
            timeout.Token);
        responseReceived.TrySetResult();
        var capture = await serverTask;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(expectedFingerprint, capture.Fingerprint);
        Assert.Equal(presetName == "okhttp4-android-11", capture.RejectedServerPush);
        Assert.Equal(
            options.DefaultHeaders["User-Agent"],
            capture.Headers.Single(header => header.Name == "user-agent").Value);
    }

    private static TlsPreset GetPreset(string name) => name switch
    {
        "chrome-133" => TlsPresets.Chrome133,
        "firefox-148" => TlsPresets.Firefox148,
        "okhttp4-android-11" => TlsPresets.Android11,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static async Task<PresetCapture> CaptureAsync(
        TcpListener listener,
        TlsServerCertificate credential,
        Task responseReceived,
        CancellationToken cancellationToken)
    {
        using var tcpClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var server = new CustomTlsServer(new CustomTlsServerOptions
        {
            ServerCertificate = credential,
            AlpnProtocols = ["h2"],
            RequireAlpn = true,
            AutomaticSessionTicketCount = 0,
        });
        await server.AuthenticateAsync(
            tcpClient.GetStream(),
            leaveOpen: false,
            cancellationToken);
        await using var stream = server.AsStream(leaveServerOpen: true);

        var preface = new byte[24];
        await ReadExactlyAsync(stream, preface, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray(), preface);

        var settingsFrame = await ReadFrameAsync(stream, cancellationToken);
        Assert.Equal(Http2FrameType.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);
        var settings = ReadSettings(settingsFrame.Payload);

        await WriteFrameAsync(
            stream,
            Http2FrameType.Settings,
            0,
            0,
            [],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        uint connectionWindowIncrement = 0;
        Http2Frame headersFrame;
        do
        {
            headersFrame = await ReadFrameAsync(stream, cancellationToken);
            if (headersFrame.Type == Http2FrameType.WindowUpdate &&
                headersFrame.StreamId == 0)
            {
                connectionWindowIncrement = BinaryPrimitives.ReadUInt32BigEndian(
                    headersFrame.Payload) & 0x7fff_ffffU;
            }
        }
        while (headersFrame.Type != Http2FrameType.Headers);

        var priority = ReadPriority(headersFrame);
        var block = new List<byte>();
        block.AddRange(ReadFirstHeaderFragment(headersFrame));
        var continuation = headersFrame;
        while ((continuation.Flags & Http2FrameFlags.EndHeaders) == 0)
        {
            continuation = await ReadFrameAsync(stream, cancellationToken);
            Assert.Equal(Http2FrameType.Continuation, continuation.Type);
            Assert.Equal(headersFrame.StreamId, continuation.StreamId);
            block.AddRange(continuation.Payload);
        }

        var headers = new HpackDecoder(65_536).Decode(
            block.ToArray(),
            262_144);
        var pseudoOrder = string.Join(",", headers
            .TakeWhile(header => header.Name.StartsWith(':'))
            .Select(header => header.Name[1].ToString()));
        var settingsText = string.Join(
            ';',
            settings.Select(setting => $"{setting.Identifier}:{setting.Value}"));
        var priorityText = priority is null
            ? "0"
            : $"{priority.Value.Dependency}:{(priority.Value.Exclusive ? 1 : 0)}:{priority.Value.Weight}";

        var rejectedServerPush = false;
        if (settings.All(setting => setting.Identifier != (ushort)TlsHttp2Setting.EnablePush))
        {
            var pushPromise = new byte[5];
            BinaryPrimitives.WriteInt32BigEndian(pushPromise, 2);
            pushPromise[4] = 0x82; // :method: GET, enough to exercise the HPACK context.
            await WriteFrameAsync(
                stream,
                Http2FrameType.PushPromise,
                Http2FrameFlags.EndHeaders,
                headersFrame.StreamId,
                pushPromise,
                cancellationToken);
            await stream.FlushAsync(cancellationToken);

            Http2Frame reset;
            do
            {
                reset = await ReadFrameAsync(stream, cancellationToken);
            }
            while (reset.Type != Http2FrameType.RstStream);
            Assert.Equal(2, reset.StreamId);
            Assert.Equal(
                Http2ErrorCode.Cancel,
                (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(reset.Payload));
            rejectedServerPush = true;
        }

        await WriteFrameAsync(
            stream,
            Http2FrameType.Headers,
            Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
            headersFrame.StreamId,
            [0x88],
            cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await responseReceived.WaitAsync(cancellationToken);
        listener.Stop();

        return new PresetCapture(
            $"{settingsText}|{connectionWindowIncrement}|{priorityText}|{pseudoOrder}",
            headers,
            rejectedServerPush);
    }

    private static (ushort Identifier, uint Value)[] ReadSettings(byte[] payload)
    {
        Assert.Equal(0, payload.Length % 6);
        var settings = new (ushort Identifier, uint Value)[payload.Length / 6];
        for (var index = 0; index < settings.Length; index++)
        {
            var offset = index * 6;
            settings[index] = (
                BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset, 2)),
                BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 2, 4)));
        }
        return settings;
    }

    private static CapturedPriority? ReadPriority(Http2Frame frame)
    {
        if ((frame.Flags & Http2FrameFlags.Priority) == 0)
        {
            return null;
        }
        Assert.True(frame.Payload.Length >= 5);
        var rawDependency = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
        return new CapturedPriority(
            (int)(rawDependency & 0x7fff_ffffU),
            (rawDependency & 0x8000_0000U) != 0,
            frame.Payload[4] + 1);
    }

    private static byte[] ReadFirstHeaderFragment(Http2Frame frame)
    {
        var offset = (frame.Flags & Http2FrameFlags.Priority) == 0 ? 0 : 5;
        return frame.Payload[offset..];
    }

    private static async ValueTask<Http2Frame> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactlyAsync(stream, header, cancellationToken);
        var length = header[0] << 16 | header[1] << 8 | header[2];
        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken);
        return new Http2Frame(
            (Http2FrameType)header[3],
            header[4],
            BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & 0x7fff_ffff,
            payload);
    }

    private static async ValueTask WriteFrameAsync(
        Stream stream,
        Http2FrameType type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = (byte)type;
        header[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(5), streamId);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
    }

    private static async ValueTask ReadExactlyAsync(
        Stream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var read = await stream.ReadAsync(destination[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    private sealed record PresetCapture(
        string Fingerprint,
        IReadOnlyList<HpackHeader> Headers,
        bool RejectedServerPush);

    private readonly record struct CapturedPriority(int Dependency, bool Exclusive, int Weight);
}
