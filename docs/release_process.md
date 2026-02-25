# Release Process

This repository uses two channels:

- `stable`: semver tags `vX.Y.Z` published as GitHub Releases
- `nightly`: scheduled snapshot builds from default branch

## Channel definitions

## Stable

- Trigger: push tag matching `v*`
- Workflow: `.github/workflows/release.yml`
- Output:
  - platform archives (`.tar.gz`, `.zip`)
  - `SHA256SUMS`
  - keyless signature files (`SHA256SUMS.sig`, `.pem`, `.bundle`)
  - SBOM files (`sbom/`)
  - build provenance attestation

## Nightly

- Trigger: `.github/workflows/nightly.yml` (daily schedule + manual dispatch)
- Output:
  - nightly archives with commit SHA in filename
  - `nightly-metadata.txt`
  - uploaded as short-retention workflow artifacts (14 days)

## Stable release checklist

1. Ensure `main` is green (CI + security + UI + perf workflows).
2. Update `CHANGELOG.md` under `[Unreleased]`.
3. Bump versions where needed.
4. Tag release:

```bash
git tag v0.1.1
git push origin v0.1.1
```

5. Verify GitHub Release assets and attestations.
6. Verify checksums/signatures using `docs/release_provenance.md`.
7. Announce release and link to changelog diff.

## Nightly checklist

1. Confirm `.github/workflows/nightly.yml` succeeded.
2. Download artifacts for smoke validation if needed.
3. If nightly fails, triage before next stable cut.

## Versioning policy

- Stable channel follows SemVer (`MAJOR.MINOR.PATCH`).
- Nightly builds are non-semver snapshots and are not supported for production.
