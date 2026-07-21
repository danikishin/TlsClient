# Supply-chain integrity

TlsClient's release artifacts are built from a pinned .NET SDK, locked package graphs,
an exact SharpTls dependency, deterministic compiler inputs, portable symbols, and
GitHub-hosted source mappings. A tag release adds a software bill of materials (SBOM)
and GitHub artifact attestations before publishing the package.

## Dependency identity

The package declares `SharpTls [0.9.0-preview.5]`. NuGet's square-bracket syntax is an
exact range: consumers cannot silently resolve a newer, wire-incompatible SharpTls
preview. Every project commits `packages.lock.json`; CI restores with `--locked-mode`.
The SDK and repository-local tools are pinned by `global.json` and
`.config/dotnet-tools.json`.

## Reproducible package archives

`Deterministic` and `ContinuousIntegrationBuild` make the assembly and portable PDB
reproducible for the same source commit. They do not make the NuGet ZIP container
byte-reproducible by themselves: NuGet generates a random Open Packaging Convention
core-properties part and records filesystem timestamps.

`TlsClient.PackageTool normalize` removes those two sources of variance. It:

- rejects duplicate, case-colliding, absolute, backslash, and traversal entry names;
- assigns one stable core-properties path and relationship ID;
- writes entries in ordinal order with a fixed timestamp and no compression; and
- performs the transformation before signing or attestation.

The release workflow packs twice into separate directories, normalizes all four
archives, and requires SHA-256 equality for the two `.nupkg` files and the two
`.snupkg` files. `verify` additionally checks the NuSpec repository commit, exact
SharpTls range, expected payload, absence of PDBs in the primary package, and a
portable `BSJB` PDB in the symbol package.

Normalization changes package bytes and must run before NuGet author signing. This
project currently uses Sigstore-backed GitHub attestations rather than an exported
author-signing certificate.

## Source Link and symbols

`Microsoft.SourceLink.GitHub` writes repository and commit information into the
portable PDB. The `.snupkg` is kept separate from the primary package. The package tool
validates every PDB document as either Source Link mapped or embedded; the release
workflow also downloads each mapped file and compares its PDB checksum. A dirty local
checkout can validate the mapping, but complete source retrieval is intentionally
enforced after the release commit has been pushed.

## SBOM and provenance

The pinned Microsoft SBOM tool generates SPDX 2.2 JSON for the release drop and
validates the resulting manifest. The release workflow then uses `actions/attest` to
create:

- a build-provenance attestation for the `.nupkg` and `.snupkg`; and
- an SBOM attestation binding the same artifacts to the generated SPDX document.

The attestations are stored by GitHub, not embedded into the NuGet archive. For a
public repository, a downloaded artifact can be checked with:

```bash
gh attestation verify TlsClient.0.6.0-preview.1.nupkg \
  --repo danikishin/TlsClient
```

The package SHA-256, attestation subject digest, and SBOM package inventory must agree.
See [RELEASING.md](RELEASING.md) for the complete release ceremony.

## Trust boundary

GitHub Actions dependencies are pinned to immutable commit SHAs, with the corresponding
release version left in a comment and Dependabot configured to propose updates.

An attestation proves which GitHub workflow and commit produced a byte sequence; it
does not prove the source is vulnerability-free. The threat model, locked inputs,
dependency review, CodeQL, fuzz gates, performance gates, package verification, and
maintainer protocol review remain separate controls. Independent third-party review is
an optional additional control, not a claimed certification or release prerequisite.
