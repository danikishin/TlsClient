using System.Diagnostics;
using System.Text.Json;
using TlsClient;

var verify = args.Contains("--verify", StringComparer.Ordinal);
var budgetPath = FindBudgetPath();
var budgets = JsonSerializer.Deserialize<Dictionary<string, PerformanceBudget>>(
    await File.ReadAllTextAsync(budgetPath),
    JsonSerializerOptions.Web) ??
    throw new InvalidDataException("Performance budget file is empty.");

var responseBytes =
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 23\r\n" +
    "Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n{\"status\":\"ok\",\"id\":42}";
var response = System.Text.Encoding.ASCII.GetBytes(responseBytes);
var request = new BufferedRequest(
    "GET",
    new Uri("https://example.com/api/items?page=1"),
    [new HeaderEntry("Accept", ["application/json"])],
    [],
    false);
HeaderEntry[] sessionHeaders =
[
    new("User-Agent", ["TlsClient.Performance/1.0"]),
    new("Accept-Encoding", ["gzip, deflate, br"]),
];
HpackHeader[] hpackHeaders =
[
    new(":status", "200"),
    new("content-type", "application/json"),
    new("cache-control", "no-cache"),
    new("content-length", "27"),
];
var hpackBlock = new HpackEncoder().Encode(hpackHeaders);
var clientHello = TlsClientHello.BuildSnapshotForTesting(
    TlsProfiles.Chrome133,
    "example.com",
    new byte[32]).GetEncodedHandshake();

var results = new[]
{
    Measure("http1-parse", 10_000, () => ParseHttp11(response)),
    Measure("http1-serialize", 30_000, () => Http11RequestWriter.SerializeHeaders(
        request,
        sessionHeaders,
        ["Host", "User-Agent", "Accept", "Accept-Encoding"],
        null).Length),
    Measure("hpack-decode", 30_000, () =>
        new HpackDecoder(4096).Decode(hpackBlock, 16 * 1024).Count),
    Measure("clienthello-diagnostics", 10_000, () =>
        TlsFingerprintDiagnostics.InspectHandshake(clientHello).ExtensionTypes.Count),
};

var failed = false;
Console.WriteLine("name\tops/s\tbytes/op\tbudget ops/s\tbudget bytes/op");
foreach (var result in results)
{
    var budget = budgets.TryGetValue(result.Name, out var configured)
        ? configured
        : throw new InvalidDataException($"No budget exists for '{result.Name}'.");
    var passed = result.OperationsPerSecond >= budget.MinimumOperationsPerSecond &&
        result.BytesPerOperation <= budget.MaximumBytesPerOperation;
    failed |= !passed;
    Console.WriteLine(
        $"{result.Name}\t{result.OperationsPerSecond:F0}\t{result.BytesPerOperation:F0}" +
        $"\t{budget.MinimumOperationsPerSecond:F0}\t{budget.MaximumBytesPerOperation:F0}" +
        (passed ? string.Empty : "\tFAIL"));
}

if (verify && failed)
{
    Environment.ExitCode = 1;
}

static int ParseHttp11(byte[] response)
{
    using var input = new MemoryStream(response, writable: false);
    var parsed = Http11ResponseReader.ReadAsync(
        new BufferedHttpReader(input),
        "GET",
        maximumHeaderBytes: 16 * 1024,
        maximumHeaderCount: 64,
        maximumBodyBytes: 64 * 1024,
        default).AsTask().GetAwaiter().GetResult();
    return parsed.Body.Length + parsed.Headers.Count;
}

static PerformanceResult Measure(string name, int iterations, Func<int> operation)
{
    for (var index = 0; index < Math.Min(iterations, 1000); index++)
    {
        _ = operation();
    }
    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();

    var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
    var checksum = 0;
    var stopwatch = Stopwatch.StartNew();
    for (var index = 0; index < iterations; index++)
    {
        checksum = unchecked(checksum + operation());
    }
    stopwatch.Stop();
    GC.KeepAlive(checksum);
    var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
    return new PerformanceResult(
        name,
        iterations / stopwatch.Elapsed.TotalSeconds,
        (double)allocated / iterations);
}

static string FindBudgetPath()
{
    var directory = new DirectoryInfo(AppContext.BaseDirectory);
    while (directory is not null)
    {
        var candidate = Path.Combine(directory.FullName, "eng", "performance-budgets.json");
        if (File.Exists(candidate))
        {
            return candidate;
        }
        directory = directory.Parent;
    }
    throw new FileNotFoundException("Could not locate eng/performance-budgets.json.");
}

internal sealed record PerformanceBudget(
    double MinimumOperationsPerSecond,
    double MaximumBytesPerOperation);

internal sealed record PerformanceResult(
    string Name,
    double OperationsPerSecond,
    double BytesPerOperation);
