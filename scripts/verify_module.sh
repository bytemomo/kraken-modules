#!/usr/bin/env bash
set -euo pipefail

# Verify a Kraken module's artifact, manifest, and index integrity.
# Requires: cosign, curl, sha256sum, jq, yq (or python3+pyyaml)

REGISTRY_URL="https://bytemomo.github.io/kraken-modules"
RELEASES_URL="https://github.com/bytemomo/kraken-modules/releases/download"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
CERT_IDENTITY="github.com/bytemomo/kraken-modules"

usage() {
  cat <<EOF
Usage: $(basename "$0") <module_id> [version]

Verifies a Kraken module by checking:
  1. Index signature (Sigstore bundle)
  2. Artifact SHA256 hash against index
  3. Artifact Sigstore signature
  4. Manifest SHA256 hash against index
  5. Manifest Sigstore signature

If version is omitted, the latest version from the index is used.

Examples:
  $(basename "$0") mqtt_auth_check
  $(basename "$0") cert_inspect 0.1.0
EOF
  exit 1
}

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

pass() {
  echo "PASS: $1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but not found"
}

require_cmd cosign
require_cmd curl
require_cmd sha256sum
require_cmd jq

MODULE_ID="${1:-}"
VERSION="${2:-}"

if [ -z "$MODULE_ID" ]; then
  usage
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "=== Verifying module: $MODULE_ID ==="
echo ""

# Step 1: Fetch and verify the index
echo "--- Step 1: Index integrity ---"
curl -sSfL "$REGISTRY_URL/index.yaml" -o "$WORKDIR/index.yaml"
curl -sSfL "$REGISTRY_URL/index.sigstore.json" -o "$WORKDIR/index.sigstore.json"

cosign verify-blob "$WORKDIR/index.yaml" \
  --bundle "$WORKDIR/index.sigstore.json" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  --certificate-identity-regexp "$CERT_IDENTITY" \
  > /dev/null 2>&1 \
  || fail "Index signature verification failed"
pass "Index signature valid"

# Parse index (use python since yq isn't always available)
INDEX_JSON=$(python3 -c "
import yaml, json, sys
with open('$WORKDIR/index.yaml') as f:
    print(json.dumps(yaml.safe_load(f)))
")

# Resolve version
if [ -z "$VERSION" ]; then
  VERSION=$(echo "$INDEX_JSON" \
    | jq -r ".modules.\"$MODULE_ID\".latest // empty")
  if [ -z "$VERSION" ]; then
    fail "Module '$MODULE_ID' not found in index"
  fi
  echo "Using latest version: $VERSION"
fi

# Extract version entry from index
VERSION_ENTRY=$(echo "$INDEX_JSON" \
  | jq -e ".modules.\"$MODULE_ID\".versions.\"$VERSION\"" 2>/dev/null) \
  || fail "Version $VERSION not found for module $MODULE_ID"

TAG=$(echo "$VERSION_ENTRY" | jq -r '.tag')
EXPECTED_ARTIFACT_HASH=$(echo "$VERSION_ENTRY" \
  | jq -r '.artifacts."linux-amd64".sha256')
ARTIFACT_FILE=$(echo "$VERSION_ENTRY" \
  | jq -r '.artifacts."linux-amd64".file')
ARTIFACT_BUNDLE=$(echo "$VERSION_ENTRY" \
  | jq -r '.artifacts."linux-amd64".bundle')
EXPECTED_MANIFEST_HASH=$(echo "$VERSION_ENTRY" \
  | jq -r '.manifest.sha256 // empty')
MANIFEST_BUNDLE=$(echo "$VERSION_ENTRY" \
  | jq -r '.manifest.bundle // empty')

echo ""

# Step 2: Fetch and verify the artifact
echo "--- Step 2: Artifact integrity ---"
RELEASE_BASE="$RELEASES_URL/$TAG"

curl -sSfL "$RELEASE_BASE/$ARTIFACT_FILE" -o "$WORKDIR/$ARTIFACT_FILE"
ACTUAL_ARTIFACT_HASH=$(sha256sum "$WORKDIR/$ARTIFACT_FILE" | cut -d' ' -f1)

if [ "$ACTUAL_ARTIFACT_HASH" != "$EXPECTED_ARTIFACT_HASH" ]; then
  fail "Artifact hash mismatch: expected $EXPECTED_ARTIFACT_HASH, got $ACTUAL_ARTIFACT_HASH"
fi
pass "Artifact hash matches index ($ACTUAL_ARTIFACT_HASH)"

echo ""

# Step 3: Verify artifact signature
echo "--- Step 3: Artifact signature ---"
curl -sSfL "$RELEASE_BASE/$ARTIFACT_BUNDLE" -o "$WORKDIR/$ARTIFACT_BUNDLE"

cosign verify-blob "$WORKDIR/$ARTIFACT_FILE" \
  --bundle "$WORKDIR/$ARTIFACT_BUNDLE" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  --certificate-identity-regexp "$CERT_IDENTITY" \
  > /dev/null 2>&1 \
  || fail "Artifact signature verification failed"
pass "Artifact signature valid"

echo ""

# Step 4: Verify manifest (if manifest hash present in index)
echo "--- Step 4: Manifest integrity ---"
if [ -n "$EXPECTED_MANIFEST_HASH" ]; then
  curl -sSfL "$RELEASE_BASE/manifest.yaml" -o "$WORKDIR/manifest.yaml"
  ACTUAL_MANIFEST_HASH=$(sha256sum "$WORKDIR/manifest.yaml" | cut -d' ' -f1)

  if [ "$ACTUAL_MANIFEST_HASH" != "$EXPECTED_MANIFEST_HASH" ]; then
    fail "Manifest hash mismatch: expected $EXPECTED_MANIFEST_HASH, got $ACTUAL_MANIFEST_HASH"
  fi
  pass "Manifest hash matches index ($ACTUAL_MANIFEST_HASH)"
else
  echo "SKIP: No manifest hash in index (pre-verification release)"
fi

echo ""

# Step 5: Verify manifest signature
echo "--- Step 5: Manifest signature ---"
if [ -n "$MANIFEST_BUNDLE" ] && [ "$MANIFEST_BUNDLE" != "null" ]; then
  curl -sSfL "$RELEASE_BASE/$MANIFEST_BUNDLE" \
    -o "$WORKDIR/$MANIFEST_BUNDLE"

  cosign verify-blob "$WORKDIR/manifest.yaml" \
    --bundle "$WORKDIR/$MANIFEST_BUNDLE" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --certificate-identity-regexp "$CERT_IDENTITY" \
    > /dev/null 2>&1 \
    || fail "Manifest signature verification failed"
  pass "Manifest signature valid"
else
  echo "SKIP: No manifest bundle in index (pre-verification release)"
fi

echo ""
echo "=== All checks passed for $MODULE_ID v$VERSION ==="
