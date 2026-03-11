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

    # Validate params section consistency
    params = manifest.get("params")
    if params and isinstance(params, dict):
        errors.extend(_validate_params(params))

    return errors


VALID_PARAM_TYPES = {"string", "integer", "number", "boolean", "array"}
VALID_FORMATS = {"ipv4", "ipv6", "hostname", "uri", "file-path", "duration", "hex"}


def _validate_params(params: dict) -> list[str]:
    errors = []
    properties = params.get("properties", {})
    required = params.get("required", [])

    for name in required:
        if name not in properties:
            errors.append(
                f"params.required lists '{name}' but it is not in params.properties"
            )

    for name, prop in properties.items():
        prefix = f"params.properties.{name}"

        if not isinstance(prop, dict):
            errors.append(f"{prefix}: must be an object")
            continue

        if "type" not in prop:
            errors.append(f"{prefix}: missing required field 'type'")
        elif prop["type"] not in VALID_PARAM_TYPES:
            errors.append(
                f"{prefix}: invalid type '{prop['type']}', "
                f"must be one of {sorted(VALID_PARAM_TYPES)}"
            )

        if "description" not in prop:
            errors.append(f"{prefix}: missing required field 'description'")

        ptype = prop.get("type")
        if ptype == "string":
            for num_field in ("minimum", "maximum"):
                if num_field in prop:
                    errors.append(
                        f"{prefix}: '{num_field}' is not valid for type 'string'"
                    )
        elif ptype in ("integer", "number"):
            for str_field in ("minLength", "maxLength", "pattern", "format"):
                if str_field in prop:
                    errors.append(
                        f"{prefix}: '{str_field}' is not valid for type '{ptype}'"
                    )

        if "format" in prop and prop["format"] not in VALID_FORMATS:
            errors.append(
                f"{prefix}: invalid format '{prop['format']}', "
                f"must be one of {sorted(VALID_FORMATS)}"
            )

        if "default" in prop:
            errors.append(
                f"{prefix}: 'default' is not allowed "
                "(consumers must provide all parameters explicitly)"
            )

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
