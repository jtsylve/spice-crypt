# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pre-commit hook: verify version and classifier consistency.

Checks:
1. pyproject.toml [project].version == spice_crypt/__init__.py __version__
2. Development Status classifier matches version stability:
   - 0.x (initial development) → "Development Status :: 3 - Alpha"
   - Pre-release (rc/alpha/beta/dev) → "Development Status :: 4 - Beta"
   - Stable release (≥1.0) → "Development Status :: 5 - Production/Stable"
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "spice_crypt" / "__init__.py"

PRE_RELEASE_RE = re.compile(r"(a|alpha|b|beta|rc|dev)\d*", re.IGNORECASE)

CLASSIFIER_ALPHA = "Development Status :: 3 - Alpha"
CLASSIFIER_BETA = "Development Status :: 4 - Beta"
CLASSIFIER_STABLE = "Development Status :: 5 - Production/Stable"

_DEV_STATUS_PREFIX = "Development Status ::"


def _extract_init_version() -> str:
    for line in INIT.read_text().splitlines():
        m = re.match(r'^__version__\s*=\s*"(.+)"', line)
        if m:
            return m.group(1)
    sys.exit(f"error: could not find __version__ in {INIT}")


def main() -> int:
    errors: list[str] = []

    with PYPROJECT.open("rb") as f:
        pyproject = tomllib.load(f)

    project = pyproject.get("project", {})

    pyproject_ver: str | None = project.get("version")
    if pyproject_ver is None:
        sys.exit(f"error: could not find [project].version in {PYPROJECT}")

    classifiers: list[str] = project.get("classifiers", [])
    actual_classifier: str | None = next(
        (c for c in classifiers if c.startswith(_DEV_STATUS_PREFIX)), None
    )

    init_ver = _extract_init_version()

    if pyproject_ver != init_ver:
        errors.append(
            f"Version mismatch: pyproject.toml has {pyproject_ver!r}, __init__.py has {init_ver!r}"
        )

    major = int(pyproject_ver.split(".")[0])
    is_prerelease = bool(PRE_RELEASE_RE.search(pyproject_ver))

    if major < 1:
        expected_classifier = CLASSIFIER_ALPHA
    elif is_prerelease:
        expected_classifier = CLASSIFIER_BETA
    else:
        expected_classifier = CLASSIFIER_STABLE

    if actual_classifier is None:
        errors.append("No 'Development Status' classifier found in pyproject.toml")
    elif actual_classifier != expected_classifier:
        errors.append(
            f"Classifier mismatch for version {pyproject_ver!r}: "
            f"expected {expected_classifier!r}, found {actual_classifier!r}"
        )

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
