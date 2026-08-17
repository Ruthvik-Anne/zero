"""Zero ask-user skill: ask the human a structured question from the kernel.

All UI state lives in the TypeScript host; these functions are thin typed
wrappers over the generic host bridge (`rlm.host_request`). They only work
inside the IPython kernel, and only when an interactive UI is attached to the
session (headless/print/daemon sessions raise instead of hanging).
"""

from __future__ import annotations

from typing import Any


from rlm import host_request


async def ask(
    question: str,
    type: str = "confirm",
    options: list[str | dict[str, str]] | None = None,
    placeholder: str | None = None,
    consequence: str | None = None,
) -> dict[str, Any]:
    """Ask the human a structured question and return their answer.

    `type` selects the question format:
    - "free_text": open-ended input. Use `placeholder` for an example answer.
    - "confirm": yes/no. Use `consequence` for a plain-language line describing
      what happens if the user says yes — required for anything risky.
    - "single_select": pick exactly one of `options`.
    - "multi_select": pick any number of `options`.

    `options` entries are either a plain string or `{"label": ..., "description": ...}`.

    Returns a dict: `{"type": ..., "answer": ...}` for free_text/confirm/
    single_select (`answer` is `None` if the user cancelled), or
    `{"type": "multi_select", "answer": "a, b", "selected": ["a", "b"]}`.
    """
    if not isinstance(question, str) or not question.strip():
        raise ValueError("question must be a non-empty string")
    payload: dict[str, Any] = {"type": type, "question": question}
    if options is not None:
        payload["options"] = options
    if placeholder is not None:
        payload["placeholder"] = placeholder
    if consequence is not None:
        payload["consequence"] = consequence
    return await host_request("ask_user.ask", payload)
