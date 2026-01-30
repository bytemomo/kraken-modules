#!/usr/bin/env python3
"""Validate module manifests against schema."""

import argparse
import sys
from pathlib import Path

import yaml
from jsonschema import Draft7Validator, ValidationError


def load_schema(schema_path: Path) -> dict:
    with open(schema_path) as f:
        return yaml.safe_load(f)


def validate_manifest(manifest_path: Path, schema: dict) -> list[str]:
    errors = []
    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    validator = Draft7Validator(schema)
    for error in validator.iter_errors(manifest):
        path = ".".join(str(p) for p in error.absolute_path)
        errors.append(f"{path}: {error.message}" if path else error.message)

    # Check manifest id matches directory name
    if manifest.get("id"):
        dir_name = manifest_path.parent.name
        if manifest["id"] != dir_name:
            errors.append(f"Manifest id '{manifest['id']}' does not match directory name '{dir_name}'")

    # Check type-specific requirements
    module_type = manifest.get("type")
    if module_type == "abi" and "abi" not in manifest:
        errors.append("Type 'abi' requires 'abi' section")
    if module_type == "container" and "container" not in manifest:
        errors.append("Type 'container' requires 'container' section")
    if module_type == "grpc" and "grpc" not in manifest:
        errors.append("Type 'grpc' requires 'grpc' section")

    return errors


def find_manifests(modules_dir: Path) -> list[Path]:
    return list(modules_dir.glob("**/manifest.yaml"))


def main():
    parser = argparse.ArgumentParser(description="Validate module manifests")
    parser.add_argument("--schema", default="pages/manifests/schema.yaml")
    parser.add_argument("--modules-dir", default="modules")
    parser.add_argument("--manifest", help="Validate single manifest")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    if not schema_path.exists():
        print(f"Schema not found: {schema_path}", file=sys.stderr)
        sys.exit(1)

    schema = load_schema(schema_path)

    if args.manifest:
        manifests = [Path(args.manifest)]
    else:
        manifests = find_manifests(Path(args.modules_dir))

    if not manifests:
        print("No manifests found", file=sys.stderr)
        sys.exit(1)

    failed = False
    for manifest_path in manifests:
        errors = validate_manifest(manifest_path, schema)
        if errors:
            failed = True
            print(f"\n{manifest_path}:")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"{manifest_path}: OK")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
