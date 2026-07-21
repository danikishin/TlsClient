using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

const string PackageId = "TlsClient";
const string CorePropertiesPath =
    "package/services/metadata/core-properties/tlsclient.psmdcp";
const string CorePropertiesRelationshipId = "R54C53434F524550";
var canonicalTimestamp = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

try
{
    switch (args)
    {
        case ["normalize", .. var paths] when paths.Length > 0:
            foreach (var path in paths)
            {
                Normalize(path);
                Console.WriteLine($"Normalized {path}");
            }
            break;
        case ["verify", var packagePath, var symbolsPath]:
            Verify(packagePath, symbolsPath);
            Console.WriteLine($"Verified {packagePath} and {symbolsPath}");
            break;
        case ["compare", var firstPath, var secondPath]:
            Compare(firstPath, secondPath);
            Console.WriteLine($"Reproducible: {Path.GetFileName(firstPath)}");
            break;
        case ["sourcelink", var symbolsPath]:
            await VerifySourceLinkAsync(symbolsPath, fetchSources: false);
            Console.WriteLine($"Verified Source Link metadata in {symbolsPath}");
            break;
        case ["sourcelink", var symbolsPath, "--fetch"]:
            await VerifySourceLinkAsync(symbolsPath, fetchSources: true);
            Console.WriteLine($"Fetched and verified Source Link documents in {symbolsPath}");
            break;
        case ["pdbinfo", var symbolsPath]:
            PrintPdbInfo(symbolsPath);
            break;
        default:
            Console.Error.WriteLine(
                "Usage:\n" +
                "  TlsClient.PackageTool normalize <package> [package ...]\n" +
                "  TlsClient.PackageTool verify <package.nupkg> <package.snupkg>\n" +
                "  TlsClient.PackageTool compare <first-package> <second-package>\n" +
                "  TlsClient.PackageTool pdbinfo <package.snupkg>\n" +
                "  TlsClient.PackageTool sourcelink <package.snupkg> [--fetch]");
            Environment.ExitCode = 2;
            break;
    }
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception.Message);
    Environment.ExitCode = 1;
}

void Normalize(string path)
{
    ArgumentException.ThrowIfNullOrWhiteSpace(path);
    var package = new FileInfo(path);
    if (!package.Exists)
    {
        throw new FileNotFoundException("Package was not found.", package.FullName);
    }

    Dictionary<string, byte[]> entries;
    using (var input = ZipFile.OpenRead(package.FullName))
    {
        EnsureSafeUniqueNames(input);
        entries = input.Entries.ToDictionary(
            entry => entry.FullName,
            ReadEntry,
            StringComparer.Ordinal);
    }

    var corePaths = entries.Keys
        .Where(IsCorePropertiesPath)
        .ToArray();
    if (corePaths.Length != 1)
    {
        throw new InvalidDataException("Package must contain exactly one core-properties part.");
    }

    var originalCorePath = corePaths[0];
    var coreBytes = entries[originalCorePath];
    entries.Remove(originalCorePath);
    entries[CorePropertiesPath] = coreBytes;
    entries["_rels/.rels"] = CanonicalizeRelationships(
        GetRequiredBytes(entries, "_rels/.rels"),
        originalCorePath);
    foreach (var entryPath in entries.Keys.ToArray())
    {
        entries[entryPath] = CanonicalizeGeneratedText(entryPath, entries[entryPath]);
    }

    var temporaryPath = package.FullName + ".canonical.tmp";
    if (File.Exists(temporaryPath))
    {
        File.Delete(temporaryPath);
    }

    try
    {
        using (var output = new FileStream(
            temporaryPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None))
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: false))
        {
            foreach (var item in entries.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                var entry = archive.CreateEntry(item.Key, CompressionLevel.NoCompression);
                entry.LastWriteTime = canonicalTimestamp;
                entry.ExternalAttributes = 0;
                using var stream = entry.Open();
                stream.Write(item.Value);
            }
        }
        CanonicalizeZipPlatform(temporaryPath);

        File.Move(temporaryPath, package.FullName, overwrite: true);
    }
    finally
    {
        if (File.Exists(temporaryPath))
        {
            File.Delete(temporaryPath);
        }
    }
}

static void CanonicalizeZipPlatform(string path)
{
    const uint centralDirectorySignature = 0x02014b50;
    const uint endOfCentralDirectorySignature = 0x06054b50;
    const int endOfCentralDirectoryLength = 22;
    const int maximumCommentLength = ushort.MaxValue;

    var bytes = File.ReadAllBytes(path);
    var minimumOffset = Math.Max(
        0,
        bytes.Length - endOfCentralDirectoryLength - maximumCommentLength);
    var endOffset = -1;
    for (var offset = bytes.Length - endOfCentralDirectoryLength;
         offset >= minimumOffset;
         offset--)
    {
        if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)) ==
            endOfCentralDirectorySignature)
        {
            endOffset = offset;
            break;
        }
    }
    if (endOffset < 0)
    {
        throw new InvalidDataException("ZIP end-of-central-directory record is missing.");
    }

    var record = bytes.AsSpan(endOffset);
    var entryCount = BinaryPrimitives.ReadUInt16LittleEndian(record[10..]);
    var centralDirectorySize = BinaryPrimitives.ReadUInt32LittleEndian(record[12..]);
    var centralDirectoryOffset = BinaryPrimitives.ReadUInt32LittleEndian(record[16..]);
    if (entryCount == ushort.MaxValue ||
        centralDirectorySize == uint.MaxValue ||
        centralDirectoryOffset == uint.MaxValue)
    {
        throw new InvalidDataException("ZIP64 packages are not supported by the normalizer.");
    }

    var current = checked((int)centralDirectoryOffset);
    for (var index = 0; index < entryCount; index++)
    {
        var header = bytes.AsSpan(current);
        if (header.Length < 46 ||
            BinaryPrimitives.ReadUInt32LittleEndian(header) != centralDirectorySignature)
        {
            throw new InvalidDataException("ZIP central directory is malformed.");
        }

        // The high byte of "version made by" is the host system. Zero makes the
        // archive metadata identical on Windows and Unix without file-mode claims.
        header[5] = 0;
        var fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(header[28..]);
        var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(header[30..]);
        var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(header[32..]);
        current = checked(current + 46 + fileNameLength + extraLength + commentLength);
    }

    if (current != checked((int)(centralDirectoryOffset + centralDirectorySize)))
    {
        throw new InvalidDataException("ZIP central-directory size does not match its entries.");
    }
    File.WriteAllBytes(path, bytes);
}

static byte[] CanonicalizeGeneratedText(string path, byte[] content)
{
    if (!path.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
        !path.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) &&
        !path.EndsWith(".rels", StringComparison.OrdinalIgnoreCase) &&
        !path.EndsWith(".psmdcp", StringComparison.OrdinalIgnoreCase))
    {
        return content;
    }

    var preamble = Encoding.UTF8.GetPreamble();
    var text = content.AsSpan().StartsWith(preamble)
        ? Encoding.UTF8.GetString(content, preamble.Length, content.Length - preamble.Length)
        : new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
            .GetString(content);
    return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
        .GetBytes(text.ReplaceLineEndings("\n"));
}

void Verify(string packagePath, string symbolsPath)
{
    using var package = ZipFile.OpenRead(packagePath);
    using var symbols = ZipFile.OpenRead(symbolsPath);
    VerifyCanonicalArchive(package);
    VerifyCanonicalArchive(symbols);

    string[] requiredPackageEntries =
    [
        "TlsClient.nuspec",
        "lib/net9.0/TlsClient.dll",
        "lib/net9.0/TlsClient.xml",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "ROADMAP.md",
        "SECURITY.md",
        "THREAT-MODEL.md",
        "docs/SUPPLY-CHAIN.md",
        "docs/RELEASING.md",
        "docs/PROTOCOL-REVIEW.md",
    ];
    foreach (var required in requiredPackageEntries)
    {
        _ = GetRequiredEntry(package, required);
    }
    if (package.Entries.Any(entry => entry.FullName.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase)))
    {
        throw new InvalidDataException("The primary package must not contain PDB files.");
    }

    var symbolPdb = GetRequiredEntry(symbols, "lib/net9.0/TlsClient.pdb");
    var pdbBytes = ReadEntry(symbolPdb);
    if (pdbBytes.Length < 4 || !pdbBytes.AsSpan(0, 4).SequenceEqual("BSJB"u8))
    {
        throw new InvalidDataException("The symbol package must contain a portable PDB.");
    }

    var version = VerifyNuspec(GetRequiredEntry(package, "TlsClient.nuspec"), verifyReleaseMetadata: true);
    var symbolVersion = VerifyNuspec(
        GetRequiredEntry(symbols, "TlsClient.nuspec"),
        verifyReleaseMetadata: false);
    if (!string.Equals(version, symbolVersion, StringComparison.Ordinal) ||
        !string.Equals(Path.GetFileName(packagePath), $"TlsClient.{version}.nupkg", StringComparison.Ordinal) ||
        !string.Equals(Path.GetFileName(symbolsPath), $"TlsClient.{version}.snupkg", StringComparison.Ordinal))
    {
        throw new InvalidDataException("Package IDs, versions, or filenames do not agree.");
    }
}

void VerifyCanonicalArchive(ZipArchive archive)
{
    EnsureSafeUniqueNames(archive);
    var names = archive.Entries.Select(entry => entry.FullName).ToArray();
    if (!names.SequenceEqual(names.OrderBy(name => name, StringComparer.Ordinal)))
    {
        throw new InvalidDataException($"{archive} entries are not in canonical order.");
    }
    if (archive.Entries.Any(entry => entry.LastWriteTime.DateTime != canonicalTimestamp.DateTime))
    {
        throw new InvalidDataException($"{archive} contains a non-canonical timestamp.");
    }

    _ = GetRequiredEntry(archive, CorePropertiesPath);
    if (archive.Entries.Count(entry => IsCorePropertiesPath(entry.FullName)) != 1)
    {
        throw new InvalidDataException($"{archive} contains an unexpected core-properties part.");
    }

    var relationships = XDocument.Load(GetRequiredEntry(archive, "_rels/.rels").Open());
    XNamespace relationshipNamespace =
        "http://schemas.openxmlformats.org/package/2006/relationships";
    var coreRelationship = relationships
        .Descendants(relationshipNamespace + "Relationship")
        .Single(element =>
            ((string?)element.Attribute("Type"))?.EndsWith(
                "/metadata/core-properties",
                StringComparison.Ordinal) == true);
    if ((string?)coreRelationship.Attribute("Target") != "/" + CorePropertiesPath ||
        (string?)coreRelationship.Attribute("Id") != CorePropertiesRelationshipId)
    {
        throw new InvalidDataException($"{archive} has non-canonical core-properties metadata.");
    }
}

string VerifyNuspec(ZipArchiveEntry nuspecEntry, bool verifyReleaseMetadata)
{
    var document = XDocument.Load(nuspecEntry.Open());
    var metadata = document.Root?.Elements().Single(element => element.Name.LocalName == "metadata") ??
        throw new InvalidDataException("NuSpec metadata is missing.");
    string RequiredValue(string name) => metadata.Elements()
        .Single(element => element.Name.LocalName == name)
        .Value;

    if (RequiredValue("id") != PackageId)
    {
        throw new InvalidDataException("Unexpected package ID.");
    }
    var version = RequiredValue("version");
    if (!Regex.IsMatch(
        version,
        @"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$",
        RegexOptions.CultureInvariant))
    {
        throw new InvalidDataException("Package version is not valid semantic versioning.");
    }

    if (!verifyReleaseMetadata)
    {
        return version;
    }

    var repository = metadata.Elements().Single(element => element.Name.LocalName == "repository");
    if ((string?)repository.Attribute("type") != "git" ||
        (string?)repository.Attribute("url") != "https://github.com/danikishin/TlsClient" ||
        !Regex.IsMatch(
            (string?)repository.Attribute("commit") ?? string.Empty,
            "^[0-9a-f]{40}$",
            RegexOptions.CultureInvariant))
    {
        throw new InvalidDataException("NuSpec repository provenance is incomplete.");
    }

    var sharpTls = metadata
        .Descendants()
        .Single(element =>
            element.Name.LocalName == "dependency" &&
            (string?)element.Attribute("id") == "SharpTls");
    if ((string?)sharpTls.Attribute("version") != "[0.9.0-preview.5]")
    {
        throw new InvalidDataException("SharpTls must be an exact package dependency.");
    }
    return version;
}

static void Compare(string firstPath, string secondPath)
{
    var firstHash = SHA256.HashData(File.ReadAllBytes(firstPath));
    var secondHash = SHA256.HashData(File.ReadAllBytes(secondPath));
    if (!firstHash.SequenceEqual(secondHash))
    {
        throw new InvalidDataException(
            $"Package hashes differ: {Convert.ToHexString(firstHash)} != " +
            Convert.ToHexString(secondHash));
    }
}

static async Task VerifySourceLinkAsync(string symbolsPath, bool fetchSources)
{
    const string sourceLinkKindText = "CC110556-A091-4D38-9FEC-25AB9A351A6A";
    const string embeddedSourceKindText = "0E8A571B-6926-466E-B4AD-8AB04611F5FE";
    var sourceLinkKind = new Guid(sourceLinkKindText);
    var embeddedSourceKind = new Guid(embeddedSourceKindText);

    using var symbols = ZipFile.OpenRead(symbolsPath);
    var pdbBytes = ReadEntry(GetRequiredEntry(symbols, "lib/net9.0/TlsClient.pdb"));
    using var pdbStream = new MemoryStream(pdbBytes, writable: false);
    using var provider = MetadataReaderProvider.FromPortablePdbStream(pdbStream);
    var reader = provider.GetMetadataReader();
    var sourceLinkHandles = reader.CustomDebugInformation
        .Where(handle => reader.GetGuid(reader.GetCustomDebugInformation(handle).Kind) == sourceLinkKind)
        .ToArray();
    if (sourceLinkHandles.Length != 1)
    {
        throw new InvalidDataException("Portable PDB must contain exactly one Source Link record.");
    }

    var sourceLink = reader.GetCustomDebugInformation(sourceLinkHandles[0]);
    using var document = JsonDocument.Parse(reader.GetBlobBytes(sourceLink.Value));
    var mappings = document.RootElement
        .GetProperty("documents")
        .EnumerateObject()
        .Select(property => (Pattern: property.Name, Url: property.Value.GetString() ?? string.Empty))
        .OrderByDescending(mapping => mapping.Pattern.Length)
        .ToArray();
    if (mappings.Length == 0 || mappings.Any(mapping => !Uri.TryCreate(mapping.Url.Replace("*", "x"), UriKind.Absolute, out _)))
    {
        throw new InvalidDataException("Source Link contains an invalid document mapping.");
    }

    using var client = new HttpClient();
    client.DefaultRequestHeaders.UserAgent.ParseAdd("TlsClient-PackageTool/1.0");
    var mappedCount = 0;
    foreach (var documentHandle in reader.Documents)
    {
        var pdbDocument = reader.GetDocument(documentHandle);
        var name = reader.GetString(pdbDocument.Name);
        var url = MapDocument(name, mappings);
        if (url is null)
        {
            var embedded = reader.GetCustomDebugInformation(documentHandle)
                .Any(handle =>
                    reader.GetGuid(reader.GetCustomDebugInformation(handle).Kind) == embeddedSourceKind);
            if (!embedded)
            {
                throw new InvalidDataException(
                    $"PDB document is neither Source Link mapped nor embedded: {name}");
            }
            continue;
        }

        mappedCount++;
        if (!fetchSources)
        {
            continue;
        }

        var source = await client.GetByteArrayAsync(url);
        var expectedHash = reader.GetBlobBytes(pdbDocument.Hash);
        var algorithm = reader.GetGuid(pdbDocument.HashAlgorithm);
        var actualHash = algorithm switch
        {
            var value when value == new Guid("8829D00F-11B8-4213-878B-770E8597AC16") =>
                SHA256.HashData(source),
            _ => throw new InvalidDataException(
                $"Unsupported document checksum algorithm {algorithm} for {name}."),
        };
        if (!actualHash.SequenceEqual(expectedHash))
        {
            throw new InvalidDataException($"Source Link checksum mismatch for {name} from {url}.");
        }
    }

    if (mappedCount == 0)
    {
        throw new InvalidDataException("Source Link does not map any portable PDB document.");
    }
}

static void PrintPdbInfo(string symbolsPath)
{
    using var symbols = ZipFile.OpenRead(symbolsPath);
    var pdbBytes = ReadEntry(GetRequiredEntry(symbols, "lib/net9.0/TlsClient.pdb"));
    using var pdbStream = new MemoryStream(pdbBytes, writable: false);
    using var provider = MetadataReaderProvider.FromPortablePdbStream(pdbStream);
    var reader = provider.GetMetadataReader();

    Console.WriteLine($"PDB ID: {Convert.ToHexString(reader.DebugMetadataHeader!.Id.ToArray())}");
    foreach (var handle in reader.Documents)
    {
        var document = reader.GetDocument(handle);
        Console.WriteLine(
            $"{reader.GetString(document.Name)}\t" +
            Convert.ToHexString(reader.GetBlobBytes(document.Hash)));
    }
}

static string? MapDocument(
    string document,
    IEnumerable<(string Pattern, string Url)> mappings)
{
    foreach (var (pattern, url) in mappings)
    {
        var wildcard = pattern.IndexOf('*');
        if (wildcard < 0)
        {
            if (string.Equals(pattern, document, StringComparison.Ordinal))
            {
                return url;
            }
            continue;
        }
        if (wildcard != pattern.LastIndexOf('*'))
        {
            throw new InvalidDataException($"Source Link pattern has multiple wildcards: {pattern}");
        }

        var prefix = pattern[..wildcard];
        var suffix = pattern[(wildcard + 1)..];
        if (document.StartsWith(prefix, StringComparison.Ordinal) &&
            document.EndsWith(suffix, StringComparison.Ordinal) &&
            document.Length >= prefix.Length + suffix.Length)
        {
            var replacement = document[prefix.Length..(document.Length - suffix.Length)];
            return url.Replace("*", replacement, StringComparison.Ordinal);
        }
    }
    return null;
}

static void EnsureSafeUniqueNames(ZipArchive archive)
{
    var exactNames = new HashSet<string>(StringComparer.Ordinal);
    var portableNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var entry in archive.Entries)
    {
        var name = entry.FullName;
        if (string.IsNullOrEmpty(name) ||
            name.StartsWith('/') ||
            name.StartsWith('\\') ||
            name.Contains('\\') ||
            name.Split('/').Any(part => part is "." or "..") ||
            !exactNames.Add(name) ||
            !portableNames.Add(name))
        {
            throw new InvalidDataException($"Unsafe or duplicate package entry: {name}");
        }
    }
}

byte[] CanonicalizeRelationships(byte[] bytes, string originalCorePath)
{
    using var input = new MemoryStream(bytes, writable: false);
    var document = XDocument.Load(input, LoadOptions.PreserveWhitespace);
    XNamespace relationshipNamespace =
        "http://schemas.openxmlformats.org/package/2006/relationships";
    var relationship = document
        .Descendants(relationshipNamespace + "Relationship")
        .Single(element =>
            string.Equals(
                ((string?)element.Attribute("Target"))?.TrimStart('/'),
                originalCorePath,
                StringComparison.Ordinal));
    relationship.SetAttributeValue("Target", "/" + CorePropertiesPath);
    relationship.SetAttributeValue("Id", CorePropertiesRelationshipId);

    using var output = new MemoryStream();
    using (var writer = XmlWriter.Create(output, new XmlWriterSettings
    {
        Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        Indent = true,
        NewLineChars = "\n",
        NewLineHandling = NewLineHandling.Replace,
        OmitXmlDeclaration = false,
    }))
    {
        document.Save(writer);
    }
    return output.ToArray();
}

bool IsCorePropertiesPath(string path) =>
    path.StartsWith(
        "package/services/metadata/core-properties/",
        StringComparison.Ordinal) &&
    path.EndsWith(".psmdcp", StringComparison.Ordinal);

static byte[] ReadEntry(ZipArchiveEntry entry)
{
    using var input = entry.Open();
    using var output = new MemoryStream();
    input.CopyTo(output);
    return output.ToArray();
}

static byte[] GetRequiredBytes(IReadOnlyDictionary<string, byte[]> entries, string name) =>
    entries.TryGetValue(name, out var value)
        ? value
        : throw new InvalidDataException($"Package entry is missing: {name}");

static ZipArchiveEntry GetRequiredEntry(ZipArchive archive, string name) =>
    archive.GetEntry(name) ??
    throw new InvalidDataException($"Package entry is missing: {name}");
