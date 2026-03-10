# Verification & Trust Model

## Trust Chain

The registry uses a three-layer cryptographic verification chain:

```
Signed Index (pages/index.yaml)
  ├── artifact hash (SHA-256)  ──→  Signed Artifact
  └── manifest hash (SHA-256)  ──→  Signed Manifest
```

Every object in the chain is independently signed with Sigstore using GitHub Actions OIDC identity. A consumer can verify any layer independently or verify the full chain.

## What Gets Signed

| Object | Signature Bundle | Signed By |
|--------|-----------------|-----------|
| Registry index (`index.yaml`) | `index.sigstore.json` | GitHub Actions OIDC |
| Module artifact (`{id}-linux-amd64`) | `{id}-linux-amd64.sigstore.json` | GitHub Actions OIDC |
| Module manifest (`manifest.yaml`) | `{id}-manifest.sigstore.json` | GitHub Actions OIDC |

All signatures are keyless (Sigstore Fulcio) and recorded in the Rekor transparency log.

## Index Structure

```yaml
version: 1
registry_url: https://bytemomo.github.io/kraken-modules
releases_url: https://github.com/bytemomo/kraken-modules/releases/download
modules:
  mqtt_auth_check:
    type: abi
    latest: 0.1.0
    manifest_url: manifests/mqtt_auth_check.yaml
    versions:
      0.1.0:
        tag: mqtt_auth_check-v0.1.0
        manifest:
          file: manifest.yaml
          sha256: <hash>
          bundle: mqtt_auth_check-manifest.sigstore.json
        artifacts:
          linux-amd64:
            file: mqtt_auth_check-linux-amd64
            sha256: <hash>
            bundle: mqtt_auth_check-linux-amd64.sigstore.json
```

## Verification Steps

### Automated (recommended)

```bash
./scripts/verify_module.sh mqtt_auth_check          # latest
./scripts/verify_module.sh mqtt_auth_check 0.1.0    # specific version
```

The script performs 5 checks:

1. **Index signature** — fetch `index.yaml` + `index.sigstore.json`, verify with cosign
2. **Artifact hash** — download artifact from release, compute SHA-256, compare against index
3. **Artifact signature** — download sigstore bundle, verify with cosign
4. **Manifest hash** — download manifest from release, compute SHA-256, compare against index
5. **Manifest signature** — download sigstore bundle, verify with cosign

Requirements: `cosign`, `curl`, `sha256sum`, `jq`, `python3` (with `pyyaml`)

### Manual

Each verification uses the same cosign command with GitHub OIDC parameters:

```bash
cosign verify-blob <file> \
  --bundle <file>.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"
```

#### Verify the index

```bash
curl -sL https://bytemomo.github.io/kraken-modules/index.yaml -o index.yaml
curl -sL https://bytemomo.github.io/kraken-modules/index.sigstore.json -o index.sigstore.json

cosign verify-blob index.yaml \
  --bundle index.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"
```

#### Verify an artifact

```bash
TAG="mqtt_auth_check-v0.1.0"
BASE="https://github.com/bytemomo/kraken-modules/releases/download/$TAG"

curl -sL "$BASE/mqtt_auth_check-linux-amd64" -o artifact
curl -sL "$BASE/mqtt_auth_check-linux-amd64.sigstore.json" -o artifact.sigstore.json

# Check hash against index
sha256sum artifact  # compare with index entry

# Check signature
cosign verify-blob artifact \
  --bundle artifact.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"
```

#### Verify a manifest

```bash
curl -sL "$BASE/manifest.yaml" -o manifest.yaml
curl -sL "$BASE/mqtt_auth_check-manifest.sigstore.json" -o manifest.sigstore.json

# Check hash against index
sha256sum manifest.yaml  # compare with index entry

# Check signature
cosign verify-blob manifest.yaml \
  --bundle manifest.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"
```

## Threat Model

| Attack | Mitigated By |
|--------|-------------|
| Tampered artifact on GitHub Releases | Artifact hash in signed index + artifact Sigstore signature |
| Tampered manifest (changed findings/params) | Manifest hash in signed index + manifest Sigstore signature |
| Tampered index (point to malicious artifact) | Index Sigstore signature |
| Compromised CI pipeline | Sigstore transparency log (Rekor) records all signatures publicly |
| Replay attack (serve old vulnerable version) | Version-specific hashes in index; consumers check `latest` field |
| Unauthorized release | GitHub OIDC identity ties signatures to this specific repository |

## What Is NOT Protected

- **Source code tampering before build** — if someone pushes malicious code to master, it gets built and signed legitimately. This is mitigated by branch protection (required PRs + reviews) and Semgrep static analysis.
- **Availability** — GitHub Pages or Releases going down is not addressed. The registry is read-only and can be mirrored.
