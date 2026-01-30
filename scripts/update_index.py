#!/usr/bin/env python3
"""Update registry index after a release."""

import argparse
import yaml
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Update registry index")
    parser.add_argument("--module-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--module-type", required=True, choices=["abi", "container", "grpc"])
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--artifact-hash", required=True)
    parser.add_argument("--index-path", default="pages/index.yaml")
    args = parser.parse_args()

    index_path = Path(args.index_path)
    with open(index_path) as f:
        index = yaml.safe_load(f)

    index["generated"] = datetime.now(timezone.utc).isoformat()

    if args.module_id not in index["modules"]:
        index["modules"][args.module_id] = {
            "type": args.module_type,
            "latest": args.version,
            "manifest_url": f"manifests/{args.module_id}.yaml",
            "versions": {},
        }

    module = index["modules"][args.module_id]
    module["latest"] = args.version

    tag = f"{args.module_id}-v{args.version}"
    module["versions"][args.version] = {
        "tag": tag,
        "artifacts": {
            "linux-amd64": {
                "file": args.artifact_name,
                "sha256": args.artifact_hash,
                "bundle": f"{args.artifact_name}.sigstore.json",
            }
        },
    }

    with open(index_path, "w") as f:
        yaml.dump(index, f, default_flow_style=False, sort_keys=False)

    print(f"Updated index: {args.module_id} v{args.version}")


if __name__ == "__main__":
    main()
