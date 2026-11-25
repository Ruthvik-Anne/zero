# Tools

## Registry (`zero_agent::tools`)

Every tool carries metadata: name, description, JSON schema, tags, examples,
action class, read-only flag, deferral flag, namespace, source (native, kernel,
MCP), and version. Registration derives the metadata from the tool and the
registry lint rejects incomplete metadata, non-object schemas, and tools that
duplicate another tool's schema and description. MCP tools without a namespace
are flagged.

## Deferral

A deferrable tool is omitted from the wire schema list until search or context
activation selects it. Non-deferred core tools are always present. The agent loop
builds its request with `wire_schemas`, so a deferred tool cannot be called before
it is surfaced.

## Search

BM25 over name (weighted), tags, description, examples, and arguments. Native
tools win ties against kernel and MCP tools. A fixed six-tool corpus verifies
that "search the web", "edit file", and "git branch" rank the intended tool
first.

## Activation

Context rules: file extension → language, directory names, git presence,
explicit keywords, and recent use. The result is **advisory only**: it suggests
tools with reasons, and never removes anything from the catalogue.

## Cache-safe injection

The system prompt is split into a stable prefix and a tool tail. Tool schemas are
appended to the tail; the prefix hash is unchanged when tools load. A test
compares the hash before and after injection.

## Policy filtering and hygiene

`filter_denied` hides tools whose action class the current policy denies (plan
mode hides writes and mutating shell; asks remain visible). Hygiene flags
duplicate descriptions/schemas and unnamespaced MCP tools.

## Telemetry

Every route records surfaced, chosen, rejected, and failed outcomes. The rotation
report counts them per tool, and kernel and protocol routes produce identical
event shapes (TOOL-06).
