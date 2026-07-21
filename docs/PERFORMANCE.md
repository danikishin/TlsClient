# Performance budgets

`tools/TlsClient.Performance` is a Release-mode regression gate for hot managed-code
paths. The thresholds live in `eng/performance-budgets.json` rather than being hidden in
the runner.

```bash
dotnet run --project tools/TlsClient.Performance -c Release -- --verify
```

The gate measures:

- complete bounded HTTP/1.1 response parsing;
- ordered HTTP/1.1 request-header serialization;
- HPACK/Huffman response-header decoding;
- ClientHello diagnostic/JA3/JA4 parsing.

Each case warms up first, measures elapsed throughput with `Stopwatch`, and measures
managed allocations on the executing thread with
`GC.GetAllocatedBytesForCurrentThread`. A checksum keeps results observable. A case
fails when either operations/second falls below its floor or bytes/operation exceeds its
ceiling.

The checked-in budgets deliberately include broad CI-machine headroom. They are
regression tripwires, not marketing benchmark claims and not a substitute for profiling
a real workload. Tightening a budget requires repeated measurements on all supported
architectures. Loosening one requires a review note explaining the changed algorithm,
measurement distribution, and user impact; changing the JSON merely to clear CI is not
accepted.

Network handshake/request benchmarks are excluded from the hard gate because scheduler,
kernel, entropy, and cryptographic-provider differences make absolute CI thresholds
misleading. Their correctness and concurrency behavior are covered by loopback and
interoperability tests. Release notes may include separately captured end-to-end
benchmarks when the environment and comparison commit are recorded.
