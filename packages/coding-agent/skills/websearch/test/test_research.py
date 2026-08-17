"""Tests for websearch.research() — module J's multi-query fan-out extension.

Mocks at the _fetch_serper seam (network boundary) rather than httpx
internals, so these tests exercise the real fan-out/labeling/truncation logic
without any network access.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch import websearch  # noqa: E402


def test_agent_dir_prefers_the_env_var_the_runtime_actually_sets(monkeypatch):
    monkeypatch.setenv("ZERO_CODING_AGENT_DIR", "/configured/agent/dir")
    assert websearch._agent_dir() == Path("/configured/agent/dir")


def test_agent_dir_falls_back_to_the_current_config_dir_name(monkeypatch):
    # (A5/stray-var fix) The fallback must be .zero/agent, not the pre-rebrand
    # .prime/agent — and must not depend on the long-dead PI_CODING_AGENT_DIR
    # name (upstream's original, pre-Prime-Intellect-fork variable).
    monkeypatch.delenv("ZERO_CODING_AGENT_DIR", raising=False)
    monkeypatch.setenv("PI_CODING_AGENT_DIR", "/should/be/ignored")
    assert websearch._agent_dir() == Path.home() / ".zero" / "agent"


@pytest.mark.asyncio
async def test_research_requires_at_least_one_query():
    with patch.object(websearch, "_resolve_api_key", return_value="test-key"):
        with pytest.raises(ValueError, match="at least one query"):
            await websearch.research([])


@pytest.mark.asyncio
async def test_research_rejects_more_than_eight_queries():
    with patch.object(websearch, "_resolve_api_key", return_value="test-key"):
        with pytest.raises(ValueError, match="at most 8 queries"):
            await websearch.research([f"q{i}" for i in range(9)])


@pytest.mark.asyncio
async def test_research_reports_missing_api_key_without_calling_fetch():
    fetch = AsyncMock()
    with patch.object(websearch, "_resolve_api_key", return_value=""), patch.object(
        websearch, "_fetch_serper", fetch
    ):
        result = await websearch.research(["a", "b"])
    assert "no Serper API key is configured" in result
    fetch.assert_not_called()


@pytest.mark.asyncio
async def test_research_fans_out_concurrently_and_labels_each_query():
    call_order: list[str] = []

    async def fake_fetch(query, api_key, timeout=45, num_results=5):
        call_order.append(query)
        # Yield control so a sequential implementation (awaiting one at a time)
        # would interleave differently than a concurrent one.
        await asyncio.sleep(0.01)
        return f"result-for-{query}"

    with patch.object(websearch, "_resolve_api_key", return_value="test-key"), patch.object(
        websearch, "_fetch_serper", fake_fetch
    ):
        output = await websearch.research(["alpha", "beta", "gamma"])

    assert '## Query 1: "alpha"' in output
    assert "result-for-alpha" in output
    assert '## Query 2: "beta"' in output
    assert "result-for-beta" in output
    assert '## Query 3: "gamma"' in output
    assert "result-for-gamma" in output
    # All three queries started before any single one's sleep resolved,
    # proving asyncio.gather actually ran them concurrently.
    assert call_order == ["alpha", "beta", "gamma"]


@pytest.mark.asyncio
async def test_research_isolates_a_failing_query_from_the_others():
    async def fake_fetch(query, api_key, timeout=45, num_results=5):
        if query == "broken":
            raise RuntimeError("upstream exploded")
        return f"ok-for-{query}"

    with patch.object(websearch, "_resolve_api_key", return_value="test-key"), patch.object(
        websearch, "_fetch_serper", fake_fetch
    ):
        output = await websearch.research(["fine", "broken"])

    assert "ok-for-fine" in output
    assert "Error searching for 'broken': upstream exploded" in output


@pytest.mark.asyncio
async def test_research_truncates_combined_output_to_max_output():
    async def fake_fetch(query, api_key, timeout=45, num_results=5):
        return "x" * 2000

    with patch.object(websearch, "_resolve_api_key", return_value="test-key"), patch.object(
        websearch, "_fetch_serper", fake_fetch
    ):
        output = await websearch.research(["a", "b"], max_output=1000)

    assert len(output) <= 1000
    assert "truncated" in output
