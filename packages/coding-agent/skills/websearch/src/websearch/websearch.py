"""Websearch skill implementation."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx


def _env_int(name: str, default: int) -> int:
    """Read an int from the environment, falling back to default on bad values."""
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _agent_dir() -> Path:
    """Resolve the Zero config dir the same way the runtime does."""
    raw = os.environ.get("ZERO_CODING_AGENT_DIR") or str(Path.home() / ".zero" / "agent")
    return Path(raw).expanduser()


def _resolve_api_key() -> str:
    # Read auth.json on each call (not just the injected env var) so a key added
    # via /login after the kernel started is still picked up. Env var wins.
    env_key = os.environ.get("SERPER_API_KEY", "").strip()
    if env_key:
        return env_key

    try:
        auth = json.loads((_agent_dir() / "auth.json").read_text())
        cred = auth.get("serper") if isinstance(auth, dict) else None
        if isinstance(cred, dict) and cred.get("type") == "api_key":
            return _resolve_config_value(str(cred.get("key") or ""))
    except (OSError, ValueError):
        pass
    return ""


def _resolve_config_value(value: str) -> str:
    # Stored keys may be a literal or an env-var name; "!command" refs can't be run
    # safely here, so skip them (the agent injects those resolved at build time).
    value = value.strip()
    if not value or value.startswith("!"):
        return ""
    return (os.environ.get(value) or value).strip()


def _format_serper_results(data: dict, query: str, num_results: int = 5) -> str:
    """Format a Serper API response into readable text."""
    sections: list[str] = []

    kg = data.get("knowledgeGraph")
    if kg:
        kg_lines: list[str] = []
        title = (kg.get("title") or "").strip()
        if title:
            kg_lines.append(f"Knowledge Graph: {title}")
        description = (kg.get("description") or "").strip()
        if description:
            kg_lines.append(description)
        for key, value in (kg.get("attributes") or {}).items():
            text = str(value).strip()
            if text:
                kg_lines.append(f"{key}: {text}")
        if kg_lines:
            sections.append("\n".join(kg_lines))

    for i, result in enumerate((data.get("organic") or [])[:num_results]):
        title = (result.get("title") or "").strip() or "Untitled"
        lines = [f"Result {i}: {title}"]
        link = (result.get("link") or "").strip()
        if link:
            lines.append(f"URL: {link}")
        snippet = (result.get("snippet") or "").strip()
        if snippet:
            lines.append(snippet)
        sections.append("\n".join(lines))

    people_also_ask = data.get("peopleAlsoAsk") or []
    if people_also_ask:
        max_q = max(1, min(3, len(people_also_ask)))
        questions: list[str] = []
        for item in people_also_ask[:max_q]:
            question = (item.get("question") or "").strip()
            if not question:
                continue
            entry = f"Q: {question}"
            answer = (item.get("snippet") or "").strip()
            if answer:
                entry += f"\nA: {answer}"
            questions.append(entry)
        if questions:
            sections.append("People Also Ask:\n" + "\n".join(questions))

    if not sections:
        return f"No results returned for query: {query}"

    return "\n\n---\n\n".join(sections)


async def _fetch_serper(query: str, api_key: str, timeout: int = 45, num_results: int = 5) -> str:
    """Execute a single Serper API search."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                "https://google.serper.dev/search",
                json={"q": query},
                headers={
                    "X-API-KEY": api_key,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        body = e.response.text if e.response is not None else ""
        raise RuntimeError(f"Serper search error ({e.response.status_code}): {body}") from e

    return _format_serper_results(data, query, num_results=num_results)


async def run(
    query: str,
    *,
    max_output: int = 8192,
    timeout: int | None = None,
    num_results: int | None = None,
) -> str:
    """Run a Google search via Serper and return formatted results.

    Args:
        query: Google search query.
        max_output: Truncate output to this many chars.
        timeout: HTTP timeout in seconds.
        num_results: Organic results to return.

    Returns:
        Formatted search results.
    """
    api_key = _resolve_api_key()
    if not api_key:
        return (
            "Web search is not set up yet: no Serper API key is configured.\n"
            "Tell the user how to enable it:\n"
            "  1. Get a free API key at https://serper.dev (sign up, copy the key).\n"
            "  2. In Prime Agent, run /login, switch to MCP Connections, choose \"Serper (web search)\", and paste the key.\n"
            "Do not ask the user to set environment variables. Once the key is saved, web search works automatically."
        )

    if timeout is None:
        timeout = _env_int("ZERO_WEBSEARCH_TIMEOUT", 45)
    if num_results is None:
        num_results = _env_int("ZERO_WEBSEARCH_NUM_RESULTS", 5)

    try:
        result = await _fetch_serper(query, api_key, timeout=timeout, num_results=num_results)
    except Exception as e:
        result = f"Error searching for '{query}': {e}"
    output = f'Results for query "{query}":\n\n{result}'

    if len(output) > max_output:
        total = len(output)
        marker = f"\n... [output truncated, {total} chars total] ...\n"
        # Reserve room for the marker so the result stays within max_output.
        half = max(0, (max_output - len(marker)) // 2)
        output = output[:half] + marker + output[len(output) - half:]
        if len(output) > max_output:  # marker alone exceeds the budget
            output = output[:max_output]

    return output


def _truncate_section(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker = f"\n... [section truncated, {len(text)} chars total] ...\n"
    half = max(0, (max_chars - len(marker)) // 2)
    return text[:half] + marker + text[len(text) - half :]


async def research(
    queries: list[str],
    *,
    max_output: int = 16384,
    timeout: int | None = None,
    num_results: int | None = None,
) -> str:
    """Fan out several related search queries concurrently and combine the results.

    Use this instead of calling `run()` repeatedly in a loop when a question
    genuinely needs several distinct angles (e.g. a term's definition, its most
    recent developments, and a specific counterexample) — the queries run
    concurrently, not sequentially, and one query failing does not lose the
    others. This function does not synthesize an answer itself; it returns
    each query's results clearly labeled so you can cross-reference them.

    Args:
        queries: 2-8 distinct search queries. A single query should just use `run()`.
        max_output: Truncate the combined output to this many chars.
        timeout: HTTP timeout in seconds, per query.
        num_results: Organic results to return, per query.

    Returns:
        Combined, per-query-labeled search results.
    """
    if not queries:
        raise ValueError("research() requires at least one query")
    if len(queries) > 8:
        raise ValueError("research() supports at most 8 queries per call; split into multiple calls")

    api_key = _resolve_api_key()
    if not api_key:
        return (
            "Web search is not set up yet: no Serper API key is configured.\n"
            "Tell the user how to enable it:\n"
            "  1. Get a free API key at https://serper.dev (sign up, copy the key).\n"
            "  2. In Prime Agent, run /login, switch to MCP Connections, choose \"Serper (web search)\", and paste the key.\n"
            "Do not ask the user to set environment variables. Once the key is saved, web search works automatically."
        )

    if timeout is None:
        timeout = _env_int("ZERO_WEBSEARCH_TIMEOUT", 45)
    if num_results is None:
        num_results = _env_int("ZERO_WEBSEARCH_NUM_RESULTS", 5)

    async def run_one(query: str) -> str:
        try:
            return await _fetch_serper(query, api_key, timeout=timeout, num_results=num_results)
        except Exception as e:
            return f"Error searching for '{query}': {e}"

    results = await asyncio.gather(*(run_one(query) for query in queries))

    per_query_budget = max(512, max_output // len(queries))
    sections = [
        f'## Query {i + 1}: "{query}"\n\n{_truncate_section(result, per_query_budget)}'
        for i, (query, result) in enumerate(zip(queries, results))
    ]
    output = "\n\n---\n\n".join(sections)

    if len(output) > max_output:
        output = _truncate_section(output, max_output)

    return output
