"""Zero vault skill: discover stored credential names from the kernel.

All vault state (encryption, storage) lives in the TypeScript host; this
function is a thin typed wrapper over the generic host bridge
(`rlm.host_request`). It only works inside the IPython kernel, and only ever
exposes credential *names* — values and placeholder tokens never flow through
this skill.
"""

from __future__ import annotations

from typing import Any

from rlm import host_request


async def list() -> dict[str, Any]:
    """List the names of credentials already stored in this project's vault.

    Returns `{"names": [str, ...]}`. Names only — never values, never
    placeholder tokens. A stored credential's value or placeholder can only be
    obtained via the `ask_user.ask(type="credential", ...)` call that stores
    it in the first place.
    """
    return await host_request("vault.list", {})
