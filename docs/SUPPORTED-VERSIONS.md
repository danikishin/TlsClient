# Supported versions

| Release line | Security support |
|---|---|
| Latest `0.x` preview | Supported until `1.0.0` |
| Older previews | Unsupported; reproduce on latest preview |
| Latest stable `1.x` minor | Supported after `1.0.0` ships |
| Older stable minors | Unsupported unless a backport is explicitly announced |

TlsClient targets .NET 9. The CI matrix runs the SDK feature band pinned by `global.json`
on current GitHub-hosted Ubuntu, macOS, and Windows images. Runtime/platform versions
outside Microsoft's support lifecycle are not supported even when an application still
runs there.

The direct SharpTls version and analyzer/test tooling are exact PackageReferences and
all projects commit NuGet lock files. A TlsClient security release may update SharpTls,
the .NET target, or another dependency when the vulnerability is owned below this
repository. Consumers should not override SharpTls to an older version; a newer override
is unsupported until TlsClient's API, wire snapshots, interoperability, and security
tests pass against it.

Security advisories identify exact affected and fixed versions. If this table conflicts
with a published GitHub Security Advisory for a particular vulnerability, the advisory's
version ranges take precedence.
