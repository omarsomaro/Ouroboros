# Security Policy

## Private reporting

Report vulnerabilities privately:

- Email: `security@handshake-p2p.dev`

Do not report vulnerabilities via public issues/discussions/social channels.

## Scope and supported versions

- Supported for security fixes: latest stable release only.
- Best-effort triage: nightly snapshots.

## Response SLA

| Severity | Initial response | Target fix | Disclosure |
|---|---|---|---|
| Critical (RCE/key compromise) | 24h | 7 days | Coordinated |
| High (DoS/metadata exposure) | 48h | 30 days | After fix |
| Medium (limited info leak) | 7 days | 90 days | After fix |
| Low (hardening/best practices) | 30 days | Next planned release | Public |

## Disclosure workflow

1. Intake and acknowledge report.
2. Reproduce and assess impact/scope.
3. Assign severity and remediation owner.
4. Prepare fix, tests, and release notes.
5. Coordinate disclosure timing with reporter.
6. Publish patched release and advisory.

## Reporter checklist

Please include when possible:

- affected version/commit
- reproduction steps and prerequisites
- expected vs actual behavior
- exploitability notes and impact
- proof-of-concept (minimal)

## PGP encrypted reports

PGP reporting is planned but the project key is not yet provisioned in this repository.
Until then, email reports in plain text and avoid including sensitive user data.

Target deliverables for PGP rollout:

- public key block committed in this file
- fingerprint published in release notes and docs
- rotation/revocation procedure documented

## Security characteristics

- Noise XX session upgrade (forward secrecy)
- XChaCha20-Poly1305 authenticated encryption
- Argon2id derivation and replay protection
- RAM-oriented key handling and early-drop filtering

## Known limitations

- passphrase entropy remains user-dependent
- relay-assisted flows expose timing/metadata to relay operator
- UPnP/NAT-PMP mappings are visible to gateway infrastructure
- LAN discovery is observable on local segments (mitigated by stealth options)

Threat visibility details:
`docs/threat_model_visibility.md`
