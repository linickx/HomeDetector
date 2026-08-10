#!/usr/bin/env python3
# Created by Antigravity using model Gemini 3.6 Flash on 2026-08-09

"""
Synchronize the OpenCanary release version across project files.
"""

import argparse
import os
import re
import sys

# Default paths relative to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(BASE_DIR, "opencanary", "VERSION")
PYPROJECT_FILE = os.path.join(BASE_DIR, "pyproject.toml")
REQUIREMENTS_FILE = os.path.join(BASE_DIR, "opencanary", "requirements.txt")
DOCKERFILE_PATH = os.path.join(BASE_DIR, "Dockerfile")


def read_version(file_path: str = VERSION_FILE) -> str:
    """Read the target version tag from the VERSION file."""
    if not os.path.exists(file_path):
        print(f"Error: Version file '{file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read().strip()


def sync_pyproject(file_path: str, version: str) -> bool:
    """Update OpenCanary version in pyproject.toml."""
    if not os.path.exists(file_path):
        return False
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        r'("opencanary\s*@\s*git\+https://github\.com/thinkst/opencanary\.git)@[^"\']+'
    )
    new_content = pattern.sub(rf"\1@{version}", content)

    if new_content != content:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True
    return False


def sync_requirements(file_path: str, version: str) -> bool:
    """Update OpenCanary version in opencanary/requirements.txt."""
    if not os.path.exists(file_path):
        return False
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        r"(git\+https://github\.com/thinkst/opencanary\.git)@[^\s]+"
    )
    new_content = pattern.sub(rf"\1@{version}", content)

    if new_content != content:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True
    return False


def sync_all(version: str) -> None:
    """Synchronize all project files to match the given version."""
    py_updated = sync_pyproject(PYPROJECT_FILE, version)
    req_updated = sync_requirements(REQUIREMENTS_FILE, version)

    print(f"Synchronized version {version}:")
    print(f"  - pyproject.toml: {'Updated' if py_updated else 'In sync'}")
    print(f"  - opencanary/requirements.txt: {'Updated' if req_updated else 'In sync'}")
    print("  - Dockerfile: Dynamic (reads opencanary/VERSION automatically)")


def check_sync(version: str) -> bool:
    """Check if all files match the given version."""
    is_in_sync = True

    if os.path.exists(PYPROJECT_FILE):
        with open(PYPROJECT_FILE, "r", encoding="utf-8") as f:
            if f'@{version}"' not in f.read():
                print(f"Out of sync: pyproject.toml does not reference @{version}")
                is_in_sync = False

    if os.path.exists(REQUIREMENTS_FILE):
        with open(REQUIREMENTS_FILE, "r", encoding="utf-8") as f:
            if f"@{version}" not in f.read():
                print(f"Out of sync: opencanary/requirements.txt does not reference @{version}")
                is_in_sync = False

    if os.path.exists(DOCKERFILE_PATH):
        with open(DOCKERFILE_PATH, "r", encoding="utf-8") as f:
            docker_content = f.read()
            if "COPY opencanary/VERSION /tmp/OPENCANARY_VERSION" not in docker_content:
                print("Out of sync: Dockerfile does not copy opencanary/VERSION")
                is_in_sync = False

    if is_in_sync:
        print(f"All files are fully in sync with OpenCanary {version}!")
    return is_in_sync


def set_version(new_version: str) -> None:
    """Set new version in opencanary/VERSION and sync all files."""
    with open(VERSION_FILE, "w", encoding="utf-8") as f:
        f.write(f"{new_version}\n")
    rel_version_file = os.path.relpath(VERSION_FILE, BASE_DIR)
    print(f"Updated {rel_version_file} to {new_version}")
    sync_all(new_version)


def main() -> None:
    """CLI entry point for version synchronization."""
    parser = argparse.ArgumentParser(
        description="Synchronize OpenCanary version across project files"
    )
    parser.add_argument(
        "--set",
        dest="new_version",
        help="Set new version tag (e.g. v0.9.10) and sync all files",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify all project files match opencanary/VERSION",
    )

    args = parser.parse_args()
    target_version = read_version()

    if args.new_version:
        set_version(args.new_version)
    elif args.check:
        in_sync = check_sync(target_version)
        sys.exit(0 if in_sync else 1)
    else:
        sync_all(target_version)


if __name__ == "__main__":
    main()
