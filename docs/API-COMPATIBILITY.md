# Public API compatibility

`src/TlsClient/PublicAPI.Shipped.txt` is the normative TlsClient 1.0 API baseline. It
contains every public type, member, enum value, nullable annotation, default parameter,
and SharpTls type exposed by the package.

The `Microsoft.CodeAnalysis.PublicApiAnalyzers` build analyzer enforces the baseline:

- removing or changing a shipped signature fails the build;
- adding a public API without declaring it fails the build;
- accidental nullable-contract changes fail the build;
- additive APIs must first be reviewed in `PublicAPI.Unshipped.txt`.

Before a stable release, reviewed entries move from `PublicAPI.Unshipped.txt` into
`PublicAPI.Shipped.txt`. The unshipped file must be empty for `1.0.0`. After 1.0,
breaking changes require a new major version; additive APIs require a minor version;
compatible fixes use a patch version. Preview versions may still revise the baseline,
but the revision must be explicit in code review.

The analyzer is pinned as a development-only dependency and is not exposed to package
consumers. The API intentionally exposes selected SharpTls types for advanced TLS
configuration instead of maintaining a lossy parallel model. A SharpTls package update
therefore requires both API-baseline review and the interoperability/security gates in
this repository.

## Review procedure

1. Build the solution and inspect every `RS0016` or `RS0017` diagnostic.
2. Reject implementation details that escaped into the public surface.
3. Add accepted compatible APIs to `PublicAPI.Unshipped.txt` with their complete
   analyzer-provided signature.
4. Update XML documentation, tests, examples, and package release notes.
5. At release, move approved entries to `PublicAPI.Shipped.txt` and verify the unshipped
   file contains only `#nullable enable`.

Suppressing `RS0016`/`RS0017`, using wildcard baselines, or editing the baseline only to
make CI green is not an accepted compatibility decision.
