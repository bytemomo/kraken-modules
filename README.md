# Kraken Module Registry

Secure module registry with cryptographic supply chain verification.

## Module Types

| Type      | Description                    | Artifact  |
| --------- | ------------------------------ | --------- |
| abi       | Native shared library (C/Rust) | `.so`     |
| container | Containerized tool             | `.tar.gz` |
| grpc      | gRPC service (Go/Rust)         | Binary    |

## Structure

```
modules/
├── abi/
│   ├── mqtt_auth_check/
│   ├── cert_inspect/
│   └── ...
└── container/
    └── mqtt_boofuzz/
```

Each module has a `manifest.yaml`:

```yaml
id: mqtt_auth_check
version: 0.1.0
type: abi

build:
    system: cmake
    platforms: [linux-amd64]

runtime:
    protocol: mqtt
    timeout: 30s

findings:
    - id: MQTT-ANON
      severity: high
      description: Anonymous authentication allowed
```

## Release

**Manual:** Tag and push

```bash
git tag mqtt_auth_check-v0.1.0
git push origin mqtt_auth_check-v0.1.0
```

**Auto:** Bump version in `manifest.yaml` and push to master.

All releases include Sigstore signatures and SLSA provenance.

## Verify

### Full verification (recommended)

```bash
./scripts/verify_module.sh mqtt_auth_check        # latest version
./scripts/verify_module.sh cert_inspect 0.1.0     # specific version
```

This checks: index signature, artifact hash + signature, manifest hash + signature.

### Manual verification

```bash
# Verify artifact
cosign verify-blob <artifact> \
  --bundle <artifact>.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"

# Verify manifest
cosign verify-blob manifest.yaml \
  --bundle <module_id>-manifest.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"

# Verify index
cosign verify-blob index.yaml \
  --bundle index.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/bytemomo/kraken-modules"
```

## Links

- **Registry:** https://bytemomo.github.io/kraken-modules/index.yaml
- **Releases:** https://github.com/bytemomo/kraken-modules/releases
