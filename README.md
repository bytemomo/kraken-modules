# Kraken Module Registry

Secure module registry for ICS/IoT security testing tools with cryptographic supply chain verification.

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
│   ├── mqtt_auth_check/    # MQTT authentication checker
│   ├── cert_inspect/       # TLS certificate inspector
│   ├── ecat_dos/           # EtherCAT DoS tester
│   └── ...
└── container/
    └── mqtt_boofuzz/       # MQTT protocol fuzzer
```

Each module has a `manifest.yaml` validated against [`pages/manifests/schema.yaml`](pages/manifests/schema.yaml):

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

**Auto:** Push any change under `modules/` to master. The patch version auto-increments (e.g., `0.1.0` → `0.1.1`).

**Minor/Major bump:** Set the version in `manifest.yaml` before pushing (e.g., `0.2.0` or `1.0.0`). Auto-patch continues from there.

**Manual:** Go to Actions → Release Module → Run workflow, enter a module ID or check "Release all".

All releases include Sigstore signatures for artifacts, manifests, and the registry index.

See [docs/release-pipeline.md](docs/release-pipeline.md) for architecture details.

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

See [docs/verification.md](docs/verification.md) for the full trust model.

## Links

- **Registry:** https://bytemomo.github.io/kraken-modules/index.yaml
- **Releases:** https://github.com/bytemomo/kraken-modules/releases
