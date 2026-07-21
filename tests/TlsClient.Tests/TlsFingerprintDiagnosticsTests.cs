namespace TlsClient.Tests;

public sealed class TlsFingerprintDiagnosticsTests
{
    [Fact]
    public void InspectHandshake_MatchesPublishedJa3Example()
    {
        ushort[] ciphers = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4];
        var handshake = CreateClientHello(
            0x0301,
            ciphers,
            [
                new(0, []),
                new(10, UInt16Vector([23, 24, 25])),
                new(11, ByteVector([0])),
            ]);

        var result = TlsFingerprintDiagnostics.InspectHandshake(handshake);

        Assert.Equal(
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
            result.Ja3String);
        Assert.Equal("ada70206e40642a3e4461f35503241d5", result.Ja3Hash);
    }

    [Fact]
    public void InspectHandshake_MatchesPublishedJa4Example()
    {
        ushort[] ciphers =
        [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
            0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        ushort[] signatures = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
        var handshake = CreateClientHello(
            0x0303,
            ciphers,
            [
                new(0xff01, []),
                new(0x0033, []),
                new(0x002d, []),
                new(0x0005, []),
                new(0x4469, []),
                new(0x000d, UInt16Vector(signatures)),
                new(0x0010, Alpn("h2")),
                new(0x0023, []),
                new(0x001b, []),
                new(0x002b, ByteLengthUInt16Vector([0x0304, 0x0303])),
                new(0x0000, []),
                new(0x0012, []),
                new(0x000a, UInt16Vector([0x001d])),
                new(0x0017, []),
                new(0x000b, ByteVector([0])),
                new(0x0015, []),
            ]);

        var result = TlsFingerprintDiagnostics.InspectHandshake(handshake);

        Assert.Equal("t13d1516h2_8daaf6152771_e5627efa2ab1", result.Ja4);
        Assert.StartsWith("t13d1516h2_", result.Ja4Raw, StringComparison.Ordinal);
        Assert.Equal(["h2"], result.AlpnProtocols);
    }

    [Fact]
    public void InspectHandshake_RemovesGreaseFromJa3AndJa4()
    {
        var plain = CreateClientHello(
            0x0303,
            [0x1301, 0x1302],
            [
                new(0, []),
                new(10, UInt16Vector([0x001d])),
                new(11, ByteVector([0])),
            ]);
        var greased = CreateClientHello(
            0x0303,
            [0x0a0a, 0x1301, 0x1302],
            [
                new(0x1a1a, []),
                new(0, []),
                new(10, UInt16Vector([0x2a2a, 0x001d])),
                new(11, ByteVector([0])),
            ]);

        var plainResult = TlsFingerprintDiagnostics.InspectHandshake(plain);
        var greaseResult = TlsFingerprintDiagnostics.InspectHandshake(greased);

        Assert.Equal(plainResult.Ja3String, greaseResult.Ja3String);
        Assert.Equal(plainResult.Ja3Hash, greaseResult.Ja3Hash);
        Assert.Equal(plainResult.Ja4, greaseResult.Ja4);
        Assert.Contains((ushort)0x0a0a, greaseResult.CipherSuites);
        Assert.Contains((ushort)0x1a1a, greaseResult.ExtensionTypes);
    }

    [Fact]
    public void InspectHandshake_RejectsTruncationAndDuplicateExtensions()
    {
        var valid = CreateClientHello(
            0x0303,
            [0x1301],
            [new(0, [])]);
        var duplicate = CreateClientHello(
            0x0303,
            [0x1301],
            [new(0, []), new(0, [])]);

        Assert.Throws<InvalidDataException>(() =>
            TlsFingerprintDiagnostics.InspectHandshake(valid.AsSpan(0, valid.Length - 1)));
        Assert.Throws<InvalidDataException>(() =>
            TlsFingerprintDiagnostics.InspectHandshake(duplicate));
    }

    private static byte[] CreateClientHello(
        ushort legacyVersion,
        ushort[] ciphers,
        Extension[] extensions)
    {
        var bytes = new List<byte> { 1, 0, 0, 0 };
        AddUInt16(bytes, legacyVersion);
        bytes.AddRange(new byte[32]);
        bytes.Add(0);
        AddUInt16(bytes, checked((ushort)(ciphers.Length * 2)));
        foreach (var cipher in ciphers)
        {
            AddUInt16(bytes, cipher);
        }
        bytes.Add(1);
        bytes.Add(0);

        var encodedExtensions = new List<byte>();
        foreach (var extension in extensions)
        {
            AddUInt16(encodedExtensions, extension.Type);
            AddUInt16(encodedExtensions, checked((ushort)extension.Body.Length));
            encodedExtensions.AddRange(extension.Body);
        }
        AddUInt16(bytes, checked((ushort)encodedExtensions.Count));
        bytes.AddRange(encodedExtensions);

        var handshakeLength = bytes.Count - 4;
        bytes[1] = (byte)(handshakeLength >> 16);
        bytes[2] = (byte)(handshakeLength >> 8);
        bytes[3] = (byte)handshakeLength;
        return bytes.ToArray();
    }

    private static byte[] UInt16Vector(ushort[] values)
    {
        var bytes = new List<byte>();
        AddUInt16(bytes, checked((ushort)(values.Length * 2)));
        foreach (var value in values)
        {
            AddUInt16(bytes, value);
        }
        return bytes.ToArray();
    }

    private static byte[] ByteLengthUInt16Vector(ushort[] values)
    {
        var bytes = new List<byte> { checked((byte)(values.Length * 2)) };
        foreach (var value in values)
        {
            AddUInt16(bytes, value);
        }
        return bytes.ToArray();
    }

    private static byte[] ByteVector(byte[] values) => [checked((byte)values.Length), .. values];

    private static byte[] Alpn(string value)
    {
        var protocol = System.Text.Encoding.ASCII.GetBytes(value);
        return [0, checked((byte)(protocol.Length + 1)), checked((byte)protocol.Length), .. protocol];
    }

    private static void AddUInt16(List<byte> bytes, ushort value)
    {
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }

    private sealed record Extension(ushort Type, byte[] Body);
}
