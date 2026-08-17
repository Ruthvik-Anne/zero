"""Zero browser automation skill: control a real browser from the kernel.

All browser state (the actual Chromium process, via Playwright) lives in the
TypeScript host; these functions are thin typed wrappers over the generic
host bridge (`rlm.host_request`). One browser is launched lazily per session
on first use and stays open across calls until `close()`.

The browser itself is not a Python dependency of this skill or of
prime-agent-runtime — it's a native Playwright dependency of the host,
resolved at `npm install` time like the rest of the host's own code, not a
package this skill installs into the kernel venv at runtime.
"""

from __future__ import annotations

from typing import Any

from rlm import host_request


async def navigate(url: str) -> dict[str, Any]:
    """Navigate the browser to `url`. Returns `{"url": ..., "title": ...}`."""
    if not isinstance(url, str) or not url:
        raise ValueError("url must be a non-empty string")
    return await host_request("browser.navigate", {"url": url})


async def click(selector: str) -> dict[str, Any]:
    """Click the first element matching `selector` (a CSS selector)."""
    if not isinstance(selector, str) or not selector:
        raise ValueError("selector must be a non-empty string")
    return await host_request("browser.click", {"selector": selector})


async def type(selector: str, text: str) -> dict[str, Any]:  # noqa: A001 - matches the host request name
    """Fill the input/textarea matching `selector` with `text` (replaces any existing value)."""
    if not isinstance(selector, str) or not selector:
        raise ValueError("selector must be a non-empty string")
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    return await host_request("browser.type", {"selector": selector, "text": text})


async def get_value(selector: str) -> dict[str, Any]:
    """Read the current value of an input/textarea/select matching `selector`."""
    if not isinstance(selector, str) or not selector:
        raise ValueError("selector must be a non-empty string")
    return await host_request("browser.get_value", {"selector": selector})


async def extract_text(selector: str | None = None) -> dict[str, Any]:
    """Return visible text of the whole page, or of one element when `selector` is given."""
    payload: dict[str, Any] = {}
    if selector is not None:
        payload["selector"] = selector
    return await host_request("browser.extract_text", payload)


async def screenshot() -> dict[str, Any]:
    """Take a screenshot of the current page. Returns `{"data": base64_png, "mimeType": "image/png"}`."""
    return await host_request("browser.screenshot")


async def close() -> dict[str, Any]:
    """Close the browser. The next call to any other function relaunches it fresh."""
    return await host_request("browser.close")
