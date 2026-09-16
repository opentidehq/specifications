"""CLI exit-code partition for RFC 0005 (`opentide share`).

Oracle for the ordered table in the RFC, not the opentide CLI.
"""

from __future__ import annotations

from collections.abc import Sequence

SUCCESS_ACTIONS = frozenset({"created", "updated", "unchanged", "retracted"})
FAILURE_ACTIONS = frozenset({"failed"})
AUTH_REASONS = frozenset({"authentication", "connectivity"})


def share_exit_code(
    *,
    preflight: bool = False,
    actions: Sequence[str] = (),
    target_failed: bool = False,
    failure_reasons: Sequence[str] = (),
) -> int:
    """Return 0, 1, 2, or 3 using RFC 0005 §4 order.

    1. Preflight → 1
    2. Success and failure → 3
    3. No failures → 0
    4. Total failure: all auth/connectivity → 2; otherwise → 1
    """
    if preflight:
        return 1
    successes = any(action in SUCCESS_ACTIONS for action in actions)
    failures = target_failed or any(action in FAILURE_ACTIONS for action in actions)
    if successes and failures:
        return 3
    if not failures:
        return 0
    reasons = list(failure_reasons)
    if reasons and all(reason in AUTH_REASONS for reason in reasons):
        return 2
    return 1
