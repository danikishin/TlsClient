# Security policy

## Reporting a vulnerability

Do not open a public issue, pull request, discussion, or paste containing an unpatched
vulnerability, proof of concept, secret, certificate, traffic capture, or exploit detail.
Use GitHub's private vulnerability reporting for this repository:

<https://github.com/danikishin/TlsClient/security/advisories/new>

Include the affected TlsClient and SharpTls versions, operating system/architecture,
.NET SDK/runtime, configuration required, impact, reproducible steps or a minimized
input, and any suggested remediation. Remove real credentials, cookies, private keys,
session state, and user data. If private reporting is temporarily unavailable, open only
a content-free public issue asking the maintainers to enable a private channel; do not
include vulnerability details there.

If the defect is entirely inside SharpTls, report it privately to SharpTls as well. When
ownership is uncertain or the exploit crosses both libraries, report to TlsClient first
and let maintainers coordinate without forcing premature public disclosure.

## Response and disclosure process

Maintainers aim to acknowledge a report within three business days and provide an
initial triage within seven business days. Valid reports receive a severity assessment,
affected-version analysis, fix/mitigation plan, and a coordinated disclosure target.
These are response goals, not guarantees for an unpaid open-source project.

The normal embargo target is at most 90 days from acknowledgment, shortened for active
exploitation or an already public issue and extended by mutual agreement when users need
time to receive a coordinated dependency/runtime fix. A release advisory should credit
reporters who want credit, describe affected/fixed versions and mitigations, and avoid
publishing weaponized detail before users can update.

Please do not test against systems or data you do not own or have permission to assess.
Good-faith research that respects privacy, avoids service disruption, reports promptly,
and allows reasonable remediation time will not be pursued by this project solely for
circumventing a technical control during that research.

## Supported versions

Before `1.0.0`, only the latest published preview is supported with security fixes; users
may be asked to reproduce on it. Starting at `1.0.0`, the latest stable minor line receives
security fixes. Older minors may receive a backport only when maintainers explicitly
announce it. End-of-life versions receive no fixes or disclosure-date extensions.

The authoritative table and dependency policy are in
[docs/SUPPORTED-VERSIONS.md](docs/SUPPORTED-VERSIONS.md).

## Security invariants and scope

- SharpTls is the only TLS engine; there is no `SslStream`, native TLS, plaintext, or
  platform fallback.
- Certificate-chain and hostname validation are enabled by default. The deliberately
  named `DangerouslySkipServerCertificateValidation` option is an explicit caller-owned
  escape hatch for controlled testing; enabling it permits active man-in-the-middle
  attacks. Pins remain enforced but do not replace the skipped PKIX validation.
- HTTP/proxy/parser/decompression/pool limits are security boundaries. Raising them is a
  caller risk decision, not a parser workaround.
- Dangerous SharpTls features, including validation bypass and an NSS key-log sink, are
  explicit caller-controlled escape hatches. Reports that an application
  deliberately publishes its own secrets through such a hook are normally out of scope;
  bypassing the explicit acknowledgment or leaking secrets without it is in scope.
- TlsClient is not an SSRF allow-list, credential vault, endpoint authorization layer,
  browser sandbox, or anonymity guarantee. Cross-origin credential stripping and pool
  isolation remain in scope.

The repository threat model and severity examples are in
[THREAT-MODEL.md](THREAT-MODEL.md).
