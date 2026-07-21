using SharpTls;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace TlsClient;

/// <summary>Computes diagnostic JA3 and JA4 values from an encoded ClientHello handshake.</summary>
public static class TlsFingerprintDiagnostics
{
    private const int MaximumHandshakeSize = 1024 * 1024;

    /// <summary>
    /// Parses one bare, encoded ClientHello Handshake message and derives diagnostics.
    /// </summary>
    public static TlsClientHelloFingerprint InspectHandshake(ReadOnlySpan<byte> handshake)
    {
        if (handshake.Length is < 4 or > MaximumHandshakeSize)
        {
            throw new InvalidDataException("The ClientHello handshake size is invalid.");
        }

        var reader = new ClientHelloReader(handshake);
        if (reader.ReadByte() != 1)
        {
            throw new InvalidDataException("The handshake message is not a ClientHello.");
        }
        var declaredLength = reader.ReadUInt24();
        if (declaredLength != reader.Remaining)
        {
            throw new InvalidDataException("The ClientHello handshake length is inconsistent.");
        }

        var legacyVersion = reader.ReadUInt16();
        _ = reader.ReadBytes(32);
        _ = reader.ReadBytes(reader.ReadByte());

        var cipherBytes = reader.ReadUInt16();
        if ((cipherBytes & 1) != 0 || cipherBytes == 0)
        {
            throw new InvalidDataException("The ClientHello cipher-suite vector is invalid.");
        }
        var ciphers = ReadUInt16Vector(reader.ReadBytes(cipherBytes));

        var compressionLength = reader.ReadByte();
        if (compressionLength == 0)
        {
            throw new InvalidDataException("The ClientHello compression vector is empty.");
        }
        _ = reader.ReadBytes(compressionLength);

        var extensions = new List<ushort>();
        var groups = Array.Empty<ushort>();
        var pointFormats = Array.Empty<byte>();
        var signatureAlgorithms = Array.Empty<ushort>();
        var supportedVersions = Array.Empty<ushort>();
        var alpnProtocols = Array.Empty<byte[]>();
        var seenExtensions = new HashSet<ushort>();

        if (reader.Remaining != 0)
        {
            var extensionBytes = reader.ReadUInt16();
            if (extensionBytes != reader.Remaining)
            {
                throw new InvalidDataException("The ClientHello extension vector is invalid.");
            }

            var extensionReader = new ClientHelloReader(reader.ReadBytes(extensionBytes));
            while (extensionReader.Remaining != 0)
            {
                var type = extensionReader.ReadUInt16();
                if (!seenExtensions.Add(type))
                {
                    throw new InvalidDataException($"Duplicate ClientHello extension 0x{type:x4}.");
                }
                extensions.Add(type);
                var body = extensionReader.ReadBytes(extensionReader.ReadUInt16());
                switch (type)
                {
                    case 10:
                        groups = ParseUInt16ExtensionVector(body, "supported_groups");
                        break;
                    case 11:
                        pointFormats = ParseByteExtensionVector(body, "ec_point_formats");
                        break;
                    case 13:
                        signatureAlgorithms = ParseUInt16ExtensionVector(
                            body,
                            "signature_algorithms");
                        break;
                    case 16:
                        alpnProtocols = ParseAlpn(body);
                        break;
                    case 43:
                        supportedVersions = ParseByteLengthUInt16Vector(
                            body,
                            "supported_versions");
                        break;
                }
            }
        }

        if (reader.Remaining != 0)
        {
            throw new InvalidDataException("The ClientHello contains trailing bytes.");
        }

        return CreateFingerprint(
            legacyVersion,
            ciphers,
            extensions.ToArray(),
            groups,
            pointFormats,
            signatureAlgorithms,
            supportedVersions,
            alpnProtocols);
    }

    [SuppressMessage(
        "Security",
        "CA5351:Do Not Use Broken Cryptographic Algorithms",
        Justification = "The published JA3 diagnostic format specifically requires MD5.")]
    private static TlsClientHelloFingerprint CreateFingerprint(
        ushort legacyVersion,
        ushort[] ciphers,
        ushort[] extensions,
        ushort[] groups,
        byte[] pointFormats,
        ushort[] signatureAlgorithms,
        ushort[] supportedVersions,
        byte[][] alpnProtocols)
    {
        var ja3Ciphers = ciphers.Where(static value => !IsGrease(value)).ToArray();
        var ja3Extensions = extensions.Where(static value => !IsGrease(value)).ToArray();
        var ja3Groups = groups.Where(static value => !IsGrease(value)).ToArray();
        var ja3String = string.Join(",",
            legacyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture),
            JoinDecimal(ja3Ciphers),
            JoinDecimal(ja3Extensions),
            JoinDecimal(ja3Groups),
            string.Join('-', pointFormats));
        var ja3Hash = Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(ja3String)));

        var cleanCiphers = ja3Ciphers.Order().ToArray();
        var cleanExtensions = ja3Extensions.Order().ToArray();
        var cleanSignatures = signatureAlgorithms
            .Where(static value => !IsGrease(value))
            .ToArray();
        var maximumVersion = supportedVersions
            .Where(static value => !IsGrease(value))
            .DefaultIfEmpty(legacyVersion)
            .Max();
        var ja4A = string.Concat(
            "t",
            MapJa4Version(maximumVersion),
            extensions.Contains((ushort)0) ? "d" : "i",
            Math.Min(cleanCiphers.Length, 99).ToString("00", System.Globalization.CultureInfo.InvariantCulture),
            Math.Min(ja3Extensions.Length, 99).ToString("00", System.Globalization.CultureInfo.InvariantCulture),
            FormatJa4Alpn(alpnProtocols));
        var cipherText = JoinHex(cleanCiphers);
        var extensionText = JoinHex(cleanExtensions.Where(static value => value is not 0 and not 16));
        if (extensions.Contains((ushort)13) && cleanSignatures.Length != 0)
        {
            extensionText = string.Concat(extensionText, "_", JoinHex(cleanSignatures));
        }
        var ja4B = HashJa4Part(cipherText);
        var ja4C = HashJa4Part(extensionText);

        return new TlsClientHelloFingerprint(
            ja3String,
            ja3Hash,
            string.Concat(ja4A, "_", ja4B, "_", ja4C),
            string.Concat(ja4A, "_", cipherText, "_", extensionText),
            legacyVersion,
            ciphers,
            extensions,
            groups,
            pointFormats,
            signatureAlgorithms,
            supportedVersions,
            alpnProtocols.Select(static value => Encoding.ASCII.GetString(value)).ToArray());
    }

    private static ushort[] ParseUInt16ExtensionVector(ReadOnlySpan<byte> body, string name)
    {
        var reader = new ClientHelloReader(body);
        var length = reader.ReadUInt16();
        if (length != reader.Remaining || (length & 1) != 0)
        {
            throw new InvalidDataException($"The {name} extension vector is invalid.");
        }
        return ReadUInt16Vector(reader.ReadBytes(length));
    }

    private static ushort[] ParseByteLengthUInt16Vector(ReadOnlySpan<byte> body, string name)
    {
        var reader = new ClientHelloReader(body);
        var length = reader.ReadByte();
        if (length != reader.Remaining || (length & 1) != 0)
        {
            throw new InvalidDataException($"The {name} extension vector is invalid.");
        }
        return ReadUInt16Vector(reader.ReadBytes(length));
    }

    private static byte[] ParseByteExtensionVector(ReadOnlySpan<byte> body, string name)
    {
        var reader = new ClientHelloReader(body);
        var length = reader.ReadByte();
        if (length != reader.Remaining)
        {
            throw new InvalidDataException($"The {name} extension vector is invalid.");
        }
        return reader.ReadBytes(length).ToArray();
    }

    private static byte[][] ParseAlpn(ReadOnlySpan<byte> body)
    {
        var reader = new ClientHelloReader(body);
        var length = reader.ReadUInt16();
        if (length != reader.Remaining)
        {
            throw new InvalidDataException("The ALPN extension vector is invalid.");
        }

        var protocols = new List<byte[]>();
        while (reader.Remaining != 0)
        {
            var protocolLength = reader.ReadByte();
            if (protocolLength == 0)
            {
                throw new InvalidDataException("An ALPN protocol identifier is empty.");
            }
            protocols.Add(reader.ReadBytes(protocolLength).ToArray());
        }
        return protocols.ToArray();
    }

    private static ushort[] ReadUInt16Vector(ReadOnlySpan<byte> bytes)
    {
        var reader = new ClientHelloReader(bytes);
        var values = new ushort[bytes.Length / 2];
        for (var index = 0; index < values.Length; index++)
        {
            values[index] = reader.ReadUInt16();
        }
        return values;
    }

    private static bool IsGrease(ushort value) =>
        (value & 0x0f0f) == 0x0a0a && (byte)(value >> 8) == (byte)value;

    private static string JoinDecimal(IEnumerable<ushort> values) =>
        string.Join('-', values.Select(static value =>
            value.ToString(System.Globalization.CultureInfo.InvariantCulture)));

    private static string JoinHex(IEnumerable<ushort> values) =>
        string.Join(',', values.Select(static value =>
            value.ToString("x4", System.Globalization.CultureInfo.InvariantCulture)));

    private static string HashJa4Part(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(value)))[..12];

    private static string MapJa4Version(ushort value) => value switch
    {
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    };

    private static string FormatJa4Alpn(byte[][] protocols)
    {
        if (protocols.Length == 0)
        {
            return "00";
        }

        var protocol = protocols[0];
        if (protocol[0] > 127)
        {
            return "99";
        }
        return protocol.Length > 2
            ? string.Create(2, protocol, static (span, value) =>
            {
                span[0] = (char)value[0];
                span[1] = (char)value[^1];
            })
            : Encoding.ASCII.GetString(protocol);
    }

    private ref struct ClientHelloReader
    {
        private readonly ReadOnlySpan<byte> _bytes;
        private int _offset;

        public ClientHelloReader(ReadOnlySpan<byte> bytes)
        {
            _bytes = bytes;
        }

        public readonly int Remaining => _bytes.Length - _offset;

        public byte ReadByte()
        {
            Ensure(1);
            return _bytes[_offset++];
        }

        public ushort ReadUInt16()
        {
            Ensure(2);
            var value = (ushort)((_bytes[_offset] << 8) | _bytes[_offset + 1]);
            _offset += 2;
            return value;
        }

        public int ReadUInt24()
        {
            Ensure(3);
            var value = (_bytes[_offset] << 16) |
                (_bytes[_offset + 1] << 8) |
                _bytes[_offset + 2];
            _offset += 3;
            return value;
        }

        public ReadOnlySpan<byte> ReadBytes(int length)
        {
            Ensure(length);
            var value = _bytes.Slice(_offset, length);
            _offset += length;
            return value;
        }

        private readonly void Ensure(int length)
        {
            if (length < 0 || length > Remaining)
            {
                throw new InvalidDataException("The ClientHello is truncated.");
            }
        }
    }
}

/// <summary>JA3/JA4 diagnostics and parsed ClientHello components.</summary>
public sealed class TlsClientHelloFingerprint
{
    internal TlsClientHelloFingerprint(
        string ja3String,
        string ja3Hash,
        string ja4,
        string ja4Raw,
        ushort legacyVersion,
        ushort[] cipherSuites,
        ushort[] extensionTypes,
        ushort[] supportedGroups,
        byte[] ecPointFormats,
        ushort[] signatureAlgorithms,
        ushort[] supportedVersions,
        string[] alpnProtocols)
    {
        Ja3String = ja3String;
        Ja3Hash = ja3Hash;
        Ja4 = ja4;
        Ja4Raw = ja4Raw;
        LegacyVersion = legacyVersion;
        CipherSuites = Array.AsReadOnly(cipherSuites);
        ExtensionTypes = Array.AsReadOnly(extensionTypes);
        SupportedGroups = Array.AsReadOnly(supportedGroups);
        EcPointFormats = Array.AsReadOnly(ecPointFormats);
        SignatureAlgorithms = Array.AsReadOnly(signatureAlgorithms);
        SupportedVersions = Array.AsReadOnly(supportedVersions);
        AlpnProtocols = Array.AsReadOnly(alpnProtocols);
    }

    /// <summary>Gets the canonical JA3 source string.</summary>
    public string Ja3String { get; }

    /// <summary>Gets the lowercase MD5 digest required by the published JA3 format.</summary>
    public string Ja3Hash { get; }

    /// <summary>Gets the standard TCP JA4 fingerprint.</summary>
    public string Ja4 { get; }

    /// <summary>Gets the unhashed, sorted JA4 diagnostic representation.</summary>
    public string Ja4Raw { get; }

    /// <summary>Gets the legacy ClientHello version field.</summary>
    public ushort LegacyVersion { get; }

    /// <summary>Gets cipher suites in original wire order, including GREASE.</summary>
    public IReadOnlyList<ushort> CipherSuites { get; }

    /// <summary>Gets extension types in original wire order, including GREASE.</summary>
    public IReadOnlyList<ushort> ExtensionTypes { get; }

    /// <summary>Gets supported groups in original wire order, including GREASE.</summary>
    public IReadOnlyList<ushort> SupportedGroups { get; }

    /// <summary>Gets EC point formats in original wire order.</summary>
    public IReadOnlyList<byte> EcPointFormats { get; }

    /// <summary>Gets signature algorithms in original wire order, including GREASE.</summary>
    public IReadOnlyList<ushort> SignatureAlgorithms { get; }

    /// <summary>Gets supported versions in original wire order, including GREASE.</summary>
    public IReadOnlyList<ushort> SupportedVersions { get; }

    /// <summary>Gets ALPN identifiers in original wire order.</summary>
    public IReadOnlyList<string> AlpnProtocols { get; }
}

/// <summary>One exact pre-send SharpTls ClientHello observation and its diagnostics.</summary>
public sealed class TlsClientHelloObservation
{
    internal TlsClientHelloObservation(TlsClientHelloInspection inspection)
    {
        Flight = inspection.Flight;
        WireForm = inspection.WireForm;
        LegacyRecordVersion = inspection.LegacyRecordVersion;
        RecordFragmentSizes = Array.AsReadOnly(inspection.RecordFragmentSizes.ToArray());
        Fingerprint = TlsFingerprintDiagnostics.InspectHandshake(
            inspection.GetEncodedHandshake());
    }

    /// <summary>Gets whether this is the initial or post-HelloRetryRequest flight.</summary>
    public TlsClientHelloFlight Flight { get; }

    /// <summary>Gets the direct, ECH outer, or GREASE-ECH wire form.</summary>
    public TlsClientHelloWireForm WireForm { get; }

    /// <summary>Gets the planned TLSPlaintext legacy record version.</summary>
    public ushort LegacyRecordVersion { get; }

    /// <summary>Gets planned plaintext record fragment lengths in wire order.</summary>
    public IReadOnlyList<int> RecordFragmentSizes { get; }

    /// <summary>Gets JA3, JA4, and parsed structural diagnostics.</summary>
    public TlsClientHelloFingerprint Fingerprint { get; }
}
