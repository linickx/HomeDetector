# OpenCanary Version Management and Dependency Patching
<!-- Created by Antigravity using model Gemini 3.6 Flash on 2026-08-09 -->

This document describes how OpenCanary versioning and dependency patching
are managed in HomeDetector.

---

## 1. Changing the OpenCanary Release Version

The release version tag for OpenCanary is defined in a single source of
truth file: [`opencanary/VERSION`](../opencanary/VERSION).

During Docker container builds, the [`Dockerfile`](../Dockerfile)
reads this version file directly to check out the specified git tag.

### Updating the Version Tag

To update OpenCanary to a new release tag (for example, `v0.9.10`), run
the synchronization script:

```bash
python3 opencanary/sync_version.py --set v0.9.10
```

This command automatically:

1. Updates the version tag in `opencanary/VERSION`.
2. Synchronizes dependency references in `pyproject.toml` and
   `opencanary/requirements.txt`.

### Checking Version Synchronization

To verify that all project files match the version tag in
`opencanary/VERSION`:

```bash
python3 opencanary/sync_version.py --check
```

---

## 2. Patching OpenCanary Dependencies

OpenCanary's upstream source repository specifies internal package
requirements in its `pyproject.toml` (for instance, pinning `simplejson==3.16.0`).
To resolve dependency conflicts with HomeDetector components, a patch
step modifies OpenCanary's `pyproject.toml` dynamically during container
builds.

### Adding or Modifying Dependency Patches

Dependency overrides are configured in
[`opencanary/dependency_patches.json`](../opencanary/dependency_patches.json):

```json
[
  {
    "package": "simplejson",
    "old_version": "3.16.0",
    "new_version": "4.1.1"
  }
]
```

- **`package`**: Name of the target Python package.
- **`old_version`**: Specific version string to replace (or `"*"` to match
  any version specifier).
- **`new_version`**: Replacement version string.

### How Patching Works During Build

When building the Docker image:

1. `Dockerfile` copies `dependency_patches.json` and
   [`opencanary/patch_dependencies.py`](../opencanary/patch_dependencies.py)
   into the build environment.
2. OpenCanary source code is cloned into `/tmp/opencanary`.
3. `patch_dependencies.py` executes against `/tmp/opencanary/pyproject.toml`
   to substitute the configured dependency versions.
4. `pip` installs the modified OpenCanary package into the virtual environment.
