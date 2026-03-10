# Release Pipeline

## Overview

All releases flow through a single workflow (`release.yaml`). There is no duplicated logic.

```
push to modules/**  ──┐
workflow_dispatch   ──┼──→  release.yaml  ──→  detect → verify → release → deploy
release-all.yaml   ──┘
```

## Triggers

| Trigger                              | What happens                                  |
| ------------------------------------ | --------------------------------------------- |
| Push to `modules/**` on master       | Auto-detect changed modules from git diff     |
| Workflow dispatch with `module_id`   | Release a specific module                     |
| Workflow dispatch with `release_all` | Release all modules                           |
| `release-all.yaml` dispatch          | Calls `release.yaml` with `release_all: true` |

## Pipeline Stages

### 1. Detect Modules

Determines which modules to release based on the trigger:

- **Push:** `git diff --name-only HEAD~1 HEAD` filtered to `modules/` paths
- **Manual (module_id):** Finds the specified module directory
- **Release all:** `find modules -name "manifest.yaml"`

Each detected module produces: `module_id`, `version`, `module_path`, `module_type`.

### 2. Verify

Runs on every release, regardless of trigger:

- **Manifest validation:** `scripts/check_manifest.py` validates all manifests against the JSON Schema at `pages/manifests/schema.yaml`
- **Static analysis:** Semgrep scans the codebase with rules from `.semgrep/rules.yaml`

### 3. Release

A single job processes all modules sequentially in a loop. For each module:

#### Version Resolution

```
Read version from manifest.yaml
  ↓
Does tag MODULE_ID-vVERSION exist?
  ├── No  → use version as-is
  └── Yes → increment patch (0.1.0 → 0.1.1), update manifest, commit
```

The auto-bump keeps incrementing until it finds an unused version. This means you never need to manually bump patch versions — just push code changes.

To set a minor or major version, edit `manifest.yaml` before pushing. The workflow uses your version if no release exists for it.

#### Build

| Module Type          | Build System            | Output               |
| -------------------- | ----------------------- | -------------------- |
| abi + Cargo.toml     | `cargo build --release` | `lib{module_id}.so`  |
| abi + CMakeLists.txt | `cmake` + `make`        | `*.so`               |
| container            | `tar -czf`              | `{module_id}.tar.gz` |
| grpc + go.mod        | `go build`              | Binary               |

All artifacts are named `{module_id}-linux-amd64`.

#### Sign

Every release signs two objects with Sigstore (keyless, using GitHub OIDC):

1. **Artifact:** `cosign sign-blob` → `{module_id}-linux-amd64.sigstore.json`
2. **Manifest:** `cosign sign-blob` → `{module_id}-manifest.sigstore.json`

All signing operations retry 3 times with 10s backoff to handle transient OIDC failures.

#### Publish

1. Create/update git tag: `{module_id}-v{version}` (force-pushed)
2. Create GitHub release with 4 files:
    - `{module_id}-linux-amd64` (artifact)
    - `{module_id}-linux-amd64.sigstore.json` (artifact signature)
    - `manifest.yaml`
    - `{module_id}-manifest.sigstore.json` (manifest signature)

#### Index Update

After all modules are processed:

1. `scripts/update_index.py` adds/updates each module's entry in `pages/index.yaml` with artifact hash, manifest hash, and sigstore bundle references
2. Manifests are copied to `pages/manifests/{module_id}.yaml`
3. The index itself is signed: `pages/index.sigstore.json`
4. Changes are committed and pushed to master

### 4. Deploy Pages

Deploys the `pages/` directory to GitHub Pages, making the registry index publicly accessible at `https://bytemomo.github.io/kraken-modules/`.

## Concurrency

| Group            | Effect                                                                          |
| ---------------- | ------------------------------------------------------------------------------- |
| `module-release` | Only one release job runs at a time. Concurrent pushes queue instead of racing. |
| `pages-deploy`   | Only one Pages deployment at a time.                                            |

This prevents index corruption from concurrent writes.

## Caching

| Cache | What                                                   | Key                   |
| ----- | ------------------------------------------------------ | --------------------- |
| apt   | cmake, libssl-dev, libmosquitto-dev, protobuf-compiler | Static per OS         |
| Rust  | Cargo registry + compiled deps                         | Based on `Cargo.lock` |
| Go    | Module + build cache                                   | Based on `go.sum`     |
| pip   | Python packages                                        | Auto                  |

## Idempotency

The pipeline is designed to be safely re-run:

- Tags are force-pushed (`git tag -f` + `git push --force`)
- Releases are deleted before recreation (`gh release delete` + `gh release create`)
- The index update is additive (existing entries are overwritten, not duplicated)
- Version auto-bump prevents accidental re-release of the same version

There is no rollback mechanism. If something fails, fix the issue and re-run. The idempotent design means re-running produces the correct state.

## Files

| File                                 | Purpose                                                   |
| ------------------------------------ | --------------------------------------------------------- |
| `.github/workflows/release.yaml`     | Main release workflow (single source of truth)            |
| `.github/workflows/release-all.yaml` | Thin wrapper: calls release.yaml with `release_all: true` |
| `.github/workflows/cleanup.yaml`     | One-shot: deletes all releases and tags                   |
| `scripts/update_index.py`            | Updates `pages/index.yaml` with module metadata           |
| `scripts/check_manifest.py`          | Validates manifests against schema                        |
| `pages/manifests/schema.yaml`        | JSON Schema for module manifests                          |
