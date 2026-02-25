# Release Provenance And SBOM

This project publishes release artifacts with:

- packaged binaries for supported targets
- CycloneDX SBOM files
- `SHA256SUMS` for all uploaded files
- keyless signature for `SHA256SUMS` (`.sig`, `.pem`, `.bundle`)
- GitHub artifact attestations (SLSA provenance)

## Maintainer release flow

1. Update `CHANGELOG.md` and version metadata as needed.
2. Create and push a version tag:

```bash
git tag v0.1.1
git push origin v0.1.1
```

3. Wait for `.github/workflows/release.yml` to complete.
4. Verify that the GitHub release contains:
- platform archives
- `SHA256SUMS`
- SBOM files under `sbom/`
- attestation entry in the GitHub UI

## Consumer verification

1. Download target archive and `SHA256SUMS` from the release page.
2. Verify keyless signature and certificate identity on checksums:

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.bundle \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/.+/.+/.github/workflows/release.yml@.+" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

3. Verify checksums:

```bash
sha256sum -c SHA256SUMS
```

4. Verify artifact attestation from the GitHub release UI or with `gh attestation verify`:

```bash
gh attestation verify <artifact-file> --repo <owner>/<repo>
```

## Notes

- SBOM generation currently uses `cargo-cyclonedx` over the Rust workspace.
- Provenance is generated with `actions/attest-build-provenance`.
- Keyless signing uses `cosign` via GitHub OIDC identity.
