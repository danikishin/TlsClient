# Contributing to TlsClient

Thank you for helping improve TlsClient. Bug reports, interoperability evidence,
documentation fixes, tests, and focused pull requests are welcome.

## Before opening an issue

- Search existing issues and discussions first.
- Reproduce on the latest preview and include the TlsClient, SharpTls, .NET, operating
  system, and architecture versions.
- Remove credentials, cookies, private keys, session state, certificates containing
  private data, and sensitive traffic captures.
- Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Never place an
  unpatched vulnerability or exploit in a public issue.

## Development setup

Install the SDK pinned by `global.json`, then run:

```bash
dotnet tool restore
dotnet restore TlsClient.slnx --locked-mode
dotnet format whitespace --folder . --verify-no-changes
dotnet build TlsClient.slnx --configuration Release --no-restore
dotnet test TlsClient.slnx --configuration Release --no-build
```

Protocol/parser changes should also run:

```bash
dotnet run --project tools/TlsClient.Fuzz --configuration Release \
  --no-build -- --smoke 25000
dotnet run --project tools/TlsClient.Performance --configuration Release \
  --no-build -- --verify
```

## Pull requests

- Keep one change per pull request and explain user-visible behavior and wire impact.
- Add a regression test for every bug fix.
- Preserve bounds on hostile input; never weaken production limits to make a fixture
  pass.
- Do not introduce `SslStream`, native TLS, P/Invoke, helper processes, or a platform TLS
  fallback. SharpTls is the only TLS engine.
- Update XML docs, guides, API baselines, wire snapshots, and `CHANGELOG.md` when the
  public behavior changes.
- Let CI pass on Linux, macOS, and Windows before requesting merge.

Public API changes follow [docs/API-COMPATIBILITY.md](docs/API-COMPATIBILITY.md).
Protocol/security-sensitive changes should use the review checklist in
[docs/PROTOCOL-REVIEW.md](docs/PROTOCOL-REVIEW.md).

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
