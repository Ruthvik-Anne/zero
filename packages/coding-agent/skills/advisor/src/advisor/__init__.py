"""Zero advisor skill: consult a stronger, skeptical reviewer from the kernel.

All review state lives in the TypeScript host; this function is a thin typed
wrapper over the generic host bridge (`rlm.host_request`). It only works
inside the IPython kernel.
"""

from __future__ import annotations

from typing import Any

from rlm import host_request


async def consult(question: str | None = None) -> dict[str, Any]:
    """Ask a stronger, skeptical reviewer for a second opinion on recent work.

    The reviewer sees the full conversation transcript so far (every tool call
    and result) and is explicitly instructed to look for a wrong assumption, a
    missed simpler approach, an unconsidered risk, or evidence already in the
    transcript that contradicts the current plan — not to simply agree.

    Call this before committing to a non-trivial approach, when stuck, or
    before declaring a task complete. Omit `question` for a general review of
    recent approach and progress, or pass a specific question to focus the
    review.

    Returns `{"advice": str, "outcome": "complete" | "error" | "cancelled", "error_message": str | None}`.
    """
    payload: dict[str, Any] = {}
    if question is not None:
        if not isinstance(question, str):
            raise TypeError(f"question must be str or None, got {type(question).__name__}")
        payload["question"] = question
    return await host_request("advisor.consult", payload)
