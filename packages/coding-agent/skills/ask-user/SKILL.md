---
name: ask-user
description: Ask the human a structured question (free text, yes/no, single choice, or multiple choice) instead of guessing. Use on a dilemma between materially different approaches, when input needed to proceed safely is missing, or when a risky action needs explicit confirmation with its consequence stated.
---

# Ask User

Guessing silently on a genuine fork in the road wastes more of the user's time
than a short question does. Call this instead of guessing whenever any of
these apply:

- **A dilemma between materially different valid approaches.** Two or more
  reasonable paths exist and picking wrong means redoing real work — use
  `single_select` (or `multi_select` if more than one can apply at once).
- **Judged-insufficient input.** A required value, preference, or piece of
  context is missing and cannot be safely inferred — use `free_text`.
- **A risky-but-legitimate action needs explicit confirmation.** This is the
  same shape a native harm-check soft-block confirmation uses — use `confirm`
  with `consequence` set to a plain-language line describing what happens if
  the user says yes (what changes, and whether it's reversible). Never ask a
  bare yes/no for something risky without stating the consequence.

Do **not** call this for questions you can answer yourself by reading the
codebase or reasoning about self-consistent instructions — asking when you
already have enough information to proceed is its own form of drift.

```python
await ask_user.ask("Which port should the dev server use?", type="free_text", placeholder="3000")

await ask_user.ask(
    "Delete the stale build cache before continuing?",
    type="confirm",
    consequence="This deletes ~400MB in .cache/ and cannot be undone unless a checkpoint covers it.",
)

await ask_user.ask(
    "Which testing approach should this task use?",
    type="single_select",
    options=[
        {"label": "unit tests only", "description": "fast, but misses integration issues"},
        {"label": "integration tests", "description": "slower, exercises the real database"},
    ],
)

await ask_user.ask(
    "Which of these optional features should be enabled?",
    type="multi_select",
    options=["dark mode", "offline support", "analytics"],
)
```

## API

- `await ask_user.ask(question, type="confirm", options=None, placeholder=None, consequence=None)`
  — returns `{"type": ..., "answer": ...}` (or, for `multi_select`, also
  `"selected": [...]`). `answer` is `None` when the user cancels without
  choosing.

## Rules

- Requires an interactive UI attached to the session. In a headless/print/
  daemon session, this raises an error telling you to make and state a
  reasonable assumption instead of hanging — do that rather than retrying.
- `options` entries are either a plain string or `{"label": ..., "description": ...}`.
- Prefer the narrowest format for the situation: `single_select` over
  `free_text` whenever the valid answers are enumerable — it's faster for the
  user and removes ambiguity in how you read their answer.
