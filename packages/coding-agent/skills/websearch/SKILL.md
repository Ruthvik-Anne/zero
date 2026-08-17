---
name: websearch
description: Search Google via the Serper API. Configure access via /login, then MCP Connections, then Serper (web search). Takes one query and returns titles, URLs, snippets, and knowledge-graph data. Use websearch.research([...]) for several distinct queries run concurrently instead of calling this in a loop.
---

# Web Search

Search the web via the Serper Google Search API.

## Setup

Get a free API key at https://serper.dev, then run `/login` in Zero,
switch to **MCP Connections**, and choose **Serper (web search)** to paste it.
The key is stored in Zero and made available to this skill automatically.

If web search reports a missing key, walk the user through those two steps;
don't ask them to set environment variables.

Optional overrides (environment variables):

- `ZERO_WEBSEARCH_TIMEOUT` - HTTP timeout in seconds (default 45).
- `ZERO_WEBSEARCH_NUM_RESULTS` - number of organic results to return (default 5).

## Usage

Call the prepared `websearch` import directly in the IPython kernel:

```python
print(await websearch("latest Zero release"))
```

For a question that genuinely needs several distinct angles (a term's
definition, its most recent developments, and a specific counterexample),
call `websearch.research([...])` instead of calling `websearch(...)` in a
loop — the queries run concurrently, and one query failing does not lose the
others:

```python
print(await websearch.research([
    "RLM recursive language model definition",
    "RLM recursive language model 2026 developments",
    "RLM vs standard subagent delegation criticism",
]))
```

`research()` returns each query's results clearly labeled by section; it does
not synthesize an answer itself — cross-reference the sections yourself.
