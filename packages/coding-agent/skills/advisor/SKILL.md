---
name: advisor
description: Consult a stronger, skeptical reviewer that sees the full conversation transcript. Use before committing to a non-trivial approach, when stuck, or before declaring a task complete — the reviewer looks for wrong assumptions, missed simpler approaches, unconsidered risks, or contradicting evidence already in the transcript.
---

# Advisor

You have access to a reviewer that sees your full conversation transcript —
every tool call and result, the reasoning that led here — and gives a candid
second opinion. This is not a rubber stamp: the reviewer is explicitly
instructed to look for problems, not agree by default.

Call it:

- **Before substantive work** — before writing, before committing to an
  interpretation, before building on an assumption.
- **When stuck** — errors recurring, an approach not converging, results that
  don't fit.
- **When you believe a task is complete** — before declaring done, so a wrong
  assumption doesn't ship unnoticed.

```python
await advisor.consult()  # general review of recent approach and progress
await advisor.consult("Am I missing a simpler way to handle the retry logic?")
```

## API

- `await advisor.consult(question=None)` — returns
  `{"advice": str, "outcome": "complete" | "error" | "cancelled", "error_message": str | None}`.

## Rules

- Give the advice serious weight. If you follow a step and it fails
  empirically, or you have primary-source evidence that contradicts a
  specific claim, adapt — don't dismiss it because a self-test passed (a
  passing test is not evidence the advice is wrong; it may mean the test
  doesn't check what the advice is checking).
- On short, reactive steps where the next action is dictated by output you
  just read, you don't need to consult every time — the advisor adds most of
  its value before the approach crystallizes and before declaring done.
- The consultation does not touch or appear in the main conversation state;
  it is a side review, not a message the user sees.
