#!/usr/bin/env python3
# Created by Antigravity using model Gemini 3.6 Flash on 2026-08-09

"""
Patch dependencies in OpenCanary's pyproject.toml file based on a JSON config.
"""

import argparse
import json
import os
import re
import sys


def apply_patch(patch: dict, content: str, target_path: str) -> tuple[str, bool]:
    """Apply a single patch rule to the content."""
    package = patch.get("package")
    old_ver = patch.get("old_version")
    new_ver = patch.get("new_version")

    if not package or not new_ver:
        print(f"Skipping invalid patch rule: {patch}", file=sys.stderr)
        return content, False

    if old_ver and old_ver != "*":
        target_str = f'"{package}=={old_ver}"'
        replacement_str = f'"{package}=={new_ver}"'
        if target_str in content:
            print(f"Patched {package}: {old_ver} -> {new_ver}")
            return content.replace(target_str, replacement_str), True

        pattern = re.compile(rf'"{re.escape(package)}=={re.escape(old_ver)}"')
        if pattern.search(content):
            print(f"Patched (regex) {package}: {old_ver} -> {new_ver}")
            return pattern.sub(f'"{package}=={new_ver}"', content), True

        print(f"Warning: Match for {target_str} not found in {target_path}")
        return content, False

    pattern = re.compile(
        rf'"{re.escape(package)}==[0-9.a-zA-Z]+"|"{re.escape(package)}>=[0-9.a-zA-Z]+"'
    )
    if pattern.search(content):
        print(f"Patched (wildcard) {package} -> {new_ver}")
        return pattern.sub(f'"{package}=={new_ver}"', content), True

    print(f"Warning: Dependency {package} not found in {target_path}")
    return content, False


def patch_pyproject(target_path: str, config_path: str) -> None:
    """Modify pyproject.toml according to rules defined in config_path."""
    if not os.path.exists(target_path):
        print(f"Error: Target file '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(config_path):
        print(f"Error: Config file '{config_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        patches = json.load(f)

    with open(target_path, "r", encoding="utf-8") as f:
        content = f.read()

    modified_content = content
    changes_count = 0

    for patch in patches:
        modified_content, applied = apply_patch(patch, modified_content, target_path)
        if applied:
            changes_count += 1

    if modified_content != content:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(modified_content)
        print(f"Successfully applied {changes_count} patch(es) to {target_path}")
    else:
        print(f"No changes made to {target_path}")


def main() -> None:
    """Parse CLI arguments and launch patching process."""
    parser = argparse.ArgumentParser(description="Patch pyproject.toml dependencies")
    parser.add_argument("--target", required=True, help="Path to target pyproject.toml file")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    args = parser.parse_args()

    patch_pyproject(args.target, args.config)


if __name__ == "__main__":
    main()
