---
name: browser
description: Control a real headless browser — navigate, click, type, extract text, screenshot. Use for tasks that need to see or interact with actual rendered web pages (JS-rendered content, forms, logged-in flows), not for general web search (use websearch instead).
---

# Browser

Drives a real headless Chromium browser via the host (native Playwright, not
a Python package). One browser is launched lazily on first use and stays open
across calls in this session until you call `browser.close()`.

Use this when a task genuinely needs to see or interact with a rendered page
— JavaScript-rendered content, filling in a form, following a login flow, or
reading something `websearch` can't reach. For "what does the web say about
X", use the `websearch` skill instead; it's far cheaper than launching a
browser.

```python
result = await browser.navigate("https://example.com")
print(result["title"])

text = await browser.extract_text()          # whole page
heading = await browser.extract_text("#heading")  # one element

await browser.type("#search-input", "prime agent")
value = await browser.get_value("#search-input")  # verify it landed

await browser.click("#search-button")

shot = await browser.screenshot()             # {"data": base64_png, "mimeType": "image/png"}

await browser.close()                          # done — releases the browser process
```

## API

- `await browser.navigate(url)` → `{"url": ..., "title": ...}`
- `await browser.click(selector)` — CSS selector.
- `await browser.type(selector, text)` — replaces the field's existing value.
- `await browser.get_value(selector)` → `{"value": ...}` — read back an input's current value.
- `await browser.extract_text(selector=None)` → `{"text": ...}` — visible text of one element, or the whole page.
- `await browser.screenshot()` → `{"data": base64_png, "mimeType": "image/png"}`.
- `await browser.close()` — closes the browser; the next call to any function above relaunches it fresh.

## Rules

- Selectors are plain CSS selectors (`#id`, `.class`, `tag[attr=value]`, etc.).
  Use `extract_text()` on the whole page first to find the right selector
  before clicking/typing into something specific.
- `type()` replaces the field's existing content — it does not append.
- Close the browser when a task's browser work is done rather than leaving it
  open indefinitely; it relaunches on demand.
