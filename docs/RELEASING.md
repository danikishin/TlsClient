# Releasing TlsClient

Releases are tag-driven and must come from a clean, reviewed commit reachable from
`main`. The release workflow rejects tags pointing outside that branch. The package
version in `src/TlsClient/TlsClient.csproj`, tag without its `v` prefix, release notes,
supported-version table, and API baseline must agree.

## Before tagging

1. Confirm every intended `ROADMAP.md` exit gate and record any explicit deferral.
2. Confirm the commit-bound maintainer evidence in `PROTOCOL-REVIEW.md` is current.
   Independent third-party review is welcome but is not a release gate.
3. Run the complete local verification set:

   ```bash
   dotnet tool restore
   dotnet restore TlsClient.slnx --locked-mode
   dotnet format whitespace --folder . --verify-no-changes
   dotnet build TlsClient.slnx --configuration Release --no-restore
   dotnet test TlsClient.slnx --configuration Release --no-build
   dotnet run --project tools/TlsClient.Fuzz --configuration Release \
     --no-build -- --smoke 25000
   dotnet run --project tools/TlsClient.Performance --configuration Release \
     --no-build -- --verify
   ```

4. Make sure `PublicAPI.Unshipped.txt` contains no signatures. Intentional public API
   changes must first move into the shipped baseline and follow the compatibility
   policy.

## Artifact construction

The authoritative `.github/workflows/release.yml` workflow performs these operations
on Ubuntu with the SDK and tool manifest pinned in the repository:

1. locked restore, formatting, build, and test;
2. two independent package operations from the same checkout;
3. canonical normalization and byte-for-byte comparison;
4. structural package verification and Source Link retrieval testing;
5. SPDX 2.2 SBOM generation and validation;
6. GitHub build-provenance and SBOM attestations;
7. artifact upload followed by optional NuGet publication from the protected `nuget`
   environment; and
8. an idempotent GitHub Release containing the package, symbols, SBOM, and validation
   result.

Create the tag only after all branch checks pass:

```bash
git tag -a v0.6.0-preview.1 -m "TlsClient 0.6.0-preview.1"
git push origin v0.6.0-preview.1
```

The `nuget` GitHub environment must restrict deployers and expose a scoped,
short-lived or regularly rotated `NUGET_API_KEY` secret. The key should allow pushes
only for the `TlsClient` package and must never be available to pull-request jobs.
When the secret is absent, the workflow emits a notice and skips nuget.org publication;
the verified GitHub Release is still created. Configure the environment before a tag
when NuGet publication is intended.

`workflow_dispatch` builds and attests an explicitly supplied version but creates no
GitHub Release and publishes nothing. This is the dry-run path for release-candidate
validation.

## Verification after publication

Download the exact artifacts uploaded by the workflow and compare them with the
NuGet download. Then verify provenance:

```bash
gh attestation verify TlsClient.0.6.0-preview.1.nupkg \
  --repo danikishin/TlsClient
```

Create a fresh project with only nuget.org as a source, install the exact version, and
compile a quick-start request. Confirm that the debugger resolves a TlsClient source
file from the tagged GitHub commit through the `.snupkg`.

If any digest, source mapping, dependency version, or smoke test differs, do not reuse
the version: NuGet packages are immutable. Correct the source and release a new version.
