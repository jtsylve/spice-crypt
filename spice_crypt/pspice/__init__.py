# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""PSpice encryption format support."""

from spice_crypt.pspice.decrypt import PSpiceFileParser
from spice_crypt.pspice.des import PSpiceDES

__all__ = [
    "PSpiceDES",
    "PSpiceFileParser",
    "RecoveredKey",
    "recover_mode4_key",
]


def __getattr__(name: str):
    """Lazy-load attack module symbols to avoid requiring the Rust extension at import time."""
    if name in ("RecoveredKey", "recover_mode4_key"):
        from spice_crypt.pspice.attack import RecoveredKey, recover_mode4_key

        globals()["RecoveredKey"] = RecoveredKey
        globals()["recover_mode4_key"] = recover_mode4_key
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
