# Model routing: classes and capability floors

`zero_model::classify` classifies a task, and `zero_model::route` routes it to
the cheapest eligible model above the class floor, with overrides, budget, and
escalation. The code is `crates/zero-model/src/classify.rs` and
`crates/zero-model/src/router.rs`; this page is the contract they implement.

Requirements: MDL-02 (classify work and choose the cheapest model above the
floor), MDL-03 (a security-sensitive or destructive task has a minimum
capability and is never silently downgraded), MDL-04 (escalate with evidence),
MDL-10 (account for cache loss when switching models), MDL-12 (user overrides),
and MDL-14 (reroute on deprecation with a warning). T-MDL-04 adds roles:
`zero_model::roles` gives each role a default model, with pins and budgeted
upgrades above it (MDL-07). T-MDL-06 adds decision records (MDL-11): every turn
stores its model, version, parameters, router reason, and cost in an append-only
log that an audit can reconstruct, so an ensemble decision (MDL-06) is visible
per turn. T-MDL-08 adds model data freshness (MDL-15, MDL-01):
`zero_model::freshness` records the snapshot's source and age, warns on a stale
table, refuses an expired one, and reports the drift after a scheduled refresh.
T-MDL-07 adds budgets and measured routing (MDL-08, MDL-09):
`zero_model::measured` records call outcomes, routes on recorded success,
retries, latency, and cost only above a sample minimum, reconciles predicted
against actual cost, and refuses an over-budget dispatch before it happens.

## Classes

`WorkClass` has nine values. The labels below are the stable snake-case wire
names.

| Class | Meaning |
|---|---|
| `plan` | Design, decomposition, analysis with no edits. |
| `edit` | Change code or files. |
| `review` | Read-only examination of existing work. |
| `test` | Write or run tests. |
| `research` | Gather and compare internal or external information. |
| `summarize` | Condense material. |
| `visual_inspection` | Look at an image, screenshot, or rendered UI. |
| `security` | Secrets, credentials, auth, vulnerabilities. |
| `destructive` | Irreversible work. |

Capabilities are `coding`, `reasoning`, `instruction_following`, `tool_use`,
`vision`, `long_context`, and `latency`. Each is graded 0–5; higher is better on
every axis, and for `latency` a higher grade means a lower-latency (more
responsive) model. `Grade::new` clamps to 0–5. A capability a model does not
declare is treated as grade 0, which fails any non-zero requirement.

## Signal and priority matrix

`TaskSignals` carries the known facts about a task. The boolean flags are
authoritative; the classifier never reads the filesystem, the environment, or
the network. `text` is used only for whole-word keyword fallback, and the
matched fixed keyword (never the text) is recorded in the reasons.

The rules run in this order and the first match wins:

| Priority | Condition | Class |
|---|---|---|
| 1 | `irreversible == true` | `destructive` |
| 2 | `touches_shell` and a destructive keyword (`rm -rf`, `drop table`, `force push`, `mkfs`, `diskpart`, `purge`, `wipe`, …) | `destructive` |
| 3 | `touches_secrets == true` | `security` |
| 4 | `touches_network` and an auth keyword (`credential`, `token`, `password`, `oauth`, `login`, `auth`, …) | `security` |
| 5 | A security keyword (`vulnerability`, `cve`, `exploit`, `threat model`, `pentest`, `security review`, …) | `security` |
| 6 | `asks_for_plan` | `plan` |
| 7 | `asks_for_review` | `review` |
| 8 | `asks_for_tests` | `test` |
| 9 | `has_images` | `visual_inspection` |
| 10 | Keyword fallback, in order: plan, review, test, visual, research, summarize | that class |
| 11 | Default: `files_changed > 0` or `touches_shell` | `edit` |
| 12 | Default: otherwise (read-only) | `plan` |

Consequences:

- Security and destructive signals outrank plan, review, test, and edit
  signals. A task that plans a migration over secrets is `security`; a task that
  reviews something and deletes it is `destructive`.
- Shell access alone does not raise the class: nearly every edit runs a shell.
  Network access alone does not either: research legitimately uses the network.
  Set `irreversible` or `touches_secrets` when the truth is known; the keyword
  tables are only a conservative backstop.
- Explicit asks beat keywords, and keywords beat the default. When several asks
  are set, the order above decides and the reasons list the ask that won.
- Keyword matching is lexical and whole-word: `test` does not match `latest`,
  `auth` does not match `author`.

## Floors

`floor_for(class)` returns a `CapabilityFloor { minimums, may_downgrade }`.
`—` means the capability is not required. The table matches the code exactly.

| Class | Coding | Reasoning | Instr. following | Tool use | Vision | Long context | Latency | May downgrade |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `plan` | 3 | 4 | 4 | 2 | — | 3 | 2 | yes |
| `edit` | 4 | 3 | 4 | 4 | — | 2 | 2 | yes |
| `review` | 4 | 4 | 3 | — | — | 4 | 2 | yes |
| `test` | 4 | 3 | 3 | 4 | — | — | 2 | yes |
| `research` | 2 | 3 | 3 | 4 | — | 4 | 2 | yes |
| `summarize` | 2 | 2 | 3 | — | — | 4 | 4 | yes |
| `visual_inspection` | 2 | 3 | 3 | — | 4 | 2 | 2 | yes |
| `security` | 4 | 5 | 5 | 4 | — | 3 | 2 | **no** |
| `destructive` | 4 | 5 | 5 | 5 | — | 2 | 2 | **no** |

Rationale: planning needs reasoning; editing needs coding and tool use; review
needs coding and a long window; tests need coding and tool use; research needs
tool use and a long window; summarising needs a long window and low latency;
visual inspection needs vision. Security requires the top reasoning and
instruction-following grades; destructive adds the top tool-use grade because
the action cannot be undone.

## Selection

`choose(&mut classification, candidates, requested_downgrade)`:

1. Take the class floor (`Classification::floor`).
2. Apply the downgrade policy below, if a request is present.
3. Keep candidates for which `meets(model, floor)` reports no missing
   capability. Missing capability = grade 0, so it fails closed.
4. Pick the eligible candidate with the lowest `ModelGrades::cheapness`, the sum
   of its declared grades. Equal totals are broken by model name, so selection
   is deterministic.
5. Record `selected <model> (total grade <n>) for work class <class>` as a
   reason.

If no candidate clears the floor, the result is `zero.fnd.unavailable` naming
the class and its requirements, e.g. `coding>=4, tool_use>=4`. The sum is a cost
proxy: it is what the pool data in T-MDL-01 is expected to correlate with, and
it is replaced only by a documented cost field, not by an implicit rule.

## Downgrade policy

`requested_downgrade: Option<Grade>` is an explicit user or budget request to
route at no more than that grade. It never bypasses `choose`.

- **At or above the floor:** nothing changes; the request is recorded as
  `requested grade N is at or above every <class> requirement`.
- **Below the floor, `may_downgrade == false`** (`security`, `destructive`):
  refused with `zero.pol.denied`. The message names the class, the capability,
  its required grade, and the requested grade. The refusal is recorded as
  `downgrade refused: …`. This is the Done criterion of T-MDL-02: a security
  task never downgrades. The refusal happens before any candidate is examined,
  so a top-tier candidate does not make the request acceptable.
- **Below the floor, `may_downgrade == true`** (every other class): accepted
  within policy. Each affected requirement is lowered to the requested grade
  and the relaxation is recorded as
  `downgrade accepted within policy: <capability> X->Y, … lowered for <class>`,
  and selection continues against the lowered requirements.

User pinning, allowlists, and budgets may reach `choose`, but they cannot make a
`security` or `destructive` floor fall: the only path to a downgrade is this
function, and it refuses those classes. MDL-12 overrides therefore apply to the
eight downgradable classes only.

Errors and reasons never contain task text. Messages name classes,
capabilities, grades, and model names; reasons name signals and fixed keywords.

## Roles

A subagent declares a role; the role decides the work class it is routed as and
the default model it uses (T-MDL-04, MDL-07). The code is
`crates/zero-model/src/roles.rs`.

The agent role enum is `zero_model::roles::Role`. It is also re-exported as
`zero_model::AgentRole`, because `zero_model::Role` is the provider message role
(`system`, `user`, `assistant`, `tool`).

### Role table

| Role | Work class | Default model | Provider | Why |
|---|---|---|---|---|
| `planner` | `plan` | `gpt-5` | openai | Planning needs the strongest reasoning and instruction following. |
| `coder` | `edit` | `gpt-5-codex` | openai | Coding needs the top coding and tool-use grades. |
| `reviewer` | `review` | `claude-sonnet-4-5` | anthropic | Review needs coding, reasoning, and a long context window. |
| `tester` | `test` | `gpt-5-codex` | openai | Writing and running tests needs coding and tool use. |
| `researcher` | `research` | `gemini-2.5-pro` | google | Research needs tool use and a long context window. |
| `vision` | `visual_inspection` | `claude-sonnet-4-5` | anthropic | Visual inspection needs a vision-capable model. |

The model ids are representative and configurable; the table encodes no price.
Real availability, grades, limits, and prices belong to the pool (MDL-01).
`RoleTable::seeded()` is the default table; `with_default` replaces one entry.
`resolve` returns the entry for a role, and a missing role is
`zero.fnd.not_found` (the message lists the roles the table actually has).

### Precedence

`assign(role, table, user_pin, upgrade, catalogue)` applies, highest first:

1. **User pin.** Wins over the role default and over an upgrade request. An
   empty or whitespace-only pin is ignored.
2. **Upgrade request.** A scheduler-approved model replaces the default. It
   needs `budget_ok == true` and a non-empty `reason`: a request without budget
   approval is `zero.pol.ask`; an empty reason is `zero.pol.denied`.
3. **Role default.** Used when the model is available and clears the role's
   floor. This is the Done criterion of T-MDL-04: a subagent with no pin and no
   upgrade uses its role default.
4. **Fallback.** Used only when the default is unavailable or below the floor.
   The cheapest available model that clears the floor is chosen (ties by model
   id) and recorded as `fallback`. If none clears, the result is
   `zero.fnd.unavailable`.

Availability means the catalogue (`ModelCatalogue`) returns grades for the
model. The same grades feed the floor check, so "available" and "graded" are one
fact, not two.

If both a pin and an upgrade are supplied, the pin wins and the upgrade is not
recorded; the assignment reason names the pin and the role default it replaced.

### Floor enforcement

Every role maps to a `classify::WorkClass`, so `classify::floor_for` supplies
its floor. Pins and upgrades are checked with `classify::meets`; a model below
the floor is refused with `zero.pol.denied` naming the class and every missing
capability (`coding>=4 (has 2)`). Defaults and fallbacks are checked the same
way, so an assignment never sits below its role floor. `enforce_floor(class,
model, requested_by, catalogue)` exposes the check for work that is classified
directly: a security or destructive task can refuse a pin below its floor before
dispatch. `classify::choose` still applies the downgrade policy for non-role
work; `assign` has no downgrade input. No role maps to `security` or
`destructive`, so a role default can never stand in for a security-class route.

### Candidates and picking

- `role_candidates(role, table, catalogue)` lists the configured default first,
  then every available model that clears the floor, cheapest first (ties by
  model id). Listing a candidate is not permission: assignment still requires
  budget approval and a reason.
- `pick(role, table, request, catalogue)` calls `assign` and returns the
  assignment with a `Classification` whose class is `role.work_class()`, whose
  floor is `classify::floor_for(class)`, and whose reasons are the role-to-class
  mapping, the assignment reason, and `model <id> clears the <class> floor`.
  Reasons are deterministic and contain no prompt text.

### Role test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model roles -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`roles::tests` has 14 tests:

| Test | Evidence |
|---|---|
| `every_role_maps_to_a_work_class_and_parses` | All six roles map to the documented class; parsing is case-insensitive and trims. |
| `every_seeded_role_resolves_and_uses_its_default` | One default per role, each with a provider and reason; a subagent with no pin uses `Default` (Done). |
| `missing_role_is_a_typed_not_found_listing_available_roles` | `zero.fnd.not_found`, available roles listed; `assign` cannot invent a missing role. |
| `user_pin_wins_over_default_and_upgrade` | The pin wins even when an approved upgrade is present. |
| `pin_below_the_role_floor_is_refused` | `zero.pol.denied`, class and missing capabilities named. |
| `security_and_destructive_floors_survive_a_pin_like_request` | `enforce_floor` refuses a below-floor model for both non-downgradable classes. |
| `upgrade_with_budget_and_reason_is_accepted` | Budget plus reason yields `UpgradeRequested`. |
| `upgrade_without_budget_or_reason_is_refused` | Missing budget `zero.pol.ask`; empty reason `zero.pol.denied`; below-floor upgrade refused. |
| `fallback_used_only_when_the_default_is_unavailable` | Missing default yields `Fallback`; no clearing model yields `zero.fnd.unavailable`. |
| `a_default_below_the_floor_is_not_used` | A low-graded default falls back instead of routing below the floor. |
| `role_candidates_list_the_default_then_permitted_upgrades` | Default first, clearing upgrades cheapest first, below-floor models excluded. |
| `pick_ties_the_assignment_to_the_classifier_floor` | Class, floor, and reasons match `classify::floor_for`. |
| `role_table_round_trips_through_json` | Role names are stable snake-case wire names; the table survives JSON as a map with role keys. |
| `reasons_are_deterministic` | Repeated picks, candidates, and errors are identical. |

## Pool data

The router trusts the pool it is handed; T-MDL-01 is the checked data behind
that pool (MDL-01). The code is `crates/zero-model/src/pool.rs` and the seed is
`crates/zero-model/data/models.json`. Every row records its provider, family,
version, limits, list prices, rate limits, lifecycle, capability grades, and the
source it came from, so a route can be traced to a dated fact rather than to a
number someone remembered.

### Schema

`PoolSeed` is the versioned document:

| Field | Meaning |
|---|---|
| `schema_version` | Seed format version. Starts at 1; 0 is refused. |
| `table_version` | Data version, bumped when the table changes. Starts at 1. |
| `checked_on` | Date the whole table was checked, `YYYY-MM-DD`. |
| `sources` | `Source { id, url, checked_on }` records. Every model points at one by index. |
| `models` | `ModelEntry` rows. |

`ModelEntry` carries the registry facts:

| Field | Meaning |
|---|---|
| `provider`, `family`, `model`, `version` | Provider id, family, exact wire id, and version label. All required and non-blank. |
| `context_tokens`, `output_tokens` | Context window and maximum output. Both must be positive. |
| `cost` | `ModelCost` in micros per million tokens: required `input_micros_per_mtok` and `output_micros_per_mtok`; optional `cache_read_micros_per_mtok` and `cache_write_micros_per_mtok`. |
| `rate` | `RateLimits { rpm: Option<u32>, tpm: Option<u64> }`. `None` means unknown or unpublished, not zero. |
| `availability` | `Availability { ga, preview, deprecated, local_only }`. `ga`/`preview` mean servable; `deprecated` is never routed to; `local_only` requires a local provider. |
| `grades` | `classify::ModelGrades`, the same type the floor check uses. Its embedded `model` must equal `model`. |
| `source_ref` | Index into `sources`. A dangling index is refused. |

Costs are integer micros, so a negative price is unrepresentable in Rust and a
JSON row carrying one fails to parse. Zero is a **declared free rate** (a local
model), which is distinct from `None`, which means the price is unknown or the
provider does not offer that cache mode. `local_only` is not copied into
`PoolModel`; the router reads locality from the provider id
(`router::is_local_provider`), so there is one locality signal.

`PoolSeed::load_str` and `PoolSeed::load_path` parse and validate with a 256 KiB
bound (`MAX_SEED_BYTES`). `load_path` checks the file size before reading.
`PoolSeed::load` is the one-call form: a string starting with `{` is JSON text,
anything else is a path. `seed_default()` parses the checked-in file at compile
time (`include_str!`), so a broken seed fails a test rather than a user request.

### Validation and errors

`validate` checks a seed built by a struct literal or deserialized, not only one
loaded through the constructors. Rejections:

| Check | Code |
|---|---|
| `schema_version == 0`, `table_version == 0`, malformed `checked_on` | `zero.fnd.invalid_input` |
| blank source id or URL, malformed source date | `zero.fnd.invalid_input` |
| duplicate source id | `zero.fnd.already_exists` |
| blank model id/provider/family/version | `zero.fnd.invalid_input` |
| zero context or output limit | `zero.fnd.invalid_input` |
| empty grade map, or grades naming a different model | `zero.fnd.invalid_input` |
| `source_ref` outside `sources` | `zero.fnd.invalid_input` |
| `ga` and `preview` both set, or `local_only` on a remote provider | `zero.fnd.invalid_input` |
| duplicate model id | `zero.fnd.already_exists` |
| seed larger than 256 KiB | `zero.fnd.limit_exceeded` |
| malformed JSON | `zero.fnd.serialization` |
| unreadable seed file | `zero.fnd.io` |

Errors name model ids, source ids, and field names only; the seed carries no
prompt text.

### Source and date rule

Every model has exactly one `source_ref`, and every source records an exact URL
(and a `checked_on` date in `YYYY-MM-DD`). The date on a model is the date its
primary source was checked, not the date the file was written. A source cited by
a model may not be dated after the table's `checked_on`.

The rules for editing the seed:

- **Do not invent a number.** If a vendor does not publish a field, leave
  `cache_read`/`cache_write` or `rate` as `None`, or omit the model. A guess is
  worse than a gap because the router treats input and output cost as
  mandatory and exact.
- **Re-check before changing a price.** Prices are **list prices at
  `checked_on`**, not a bill and not a forecast. They drift, promotions end, and
  cache tiers change. `freshness` (MDL-15) decides when the snapshot is too old
  to route on; this seed only records the facts and the date.
- **Use the vendor page when it publishes the fact; otherwise use a dated
  tracker and say so.** The OpenAI model pages used here publish prices, rate
  limits, and qualitative positioning but not the context window, so the two
  hosted OpenAI rows cite dated trackers for context/output and the official
  pricing page is listed as a cross-check.

### Seed contents (checked 2026-11-25)

Seven representative models: two OpenAI hosted models, two Anthropic models, one
Google model, and two open-weight models served locally through Ollama. Prices
are USD per million tokens; `—` means the field is `None` (unknown or not
offered), not free.

| Model | Provider | Context | Max output | Input | Output | Cache read | Cache write | Tier | Local |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| `gpt-6.2-sol` | openai | 1,050,000 | 128,000 | $2.00 | $10.00 | $0.10 | $2.50 | 2 | no |
| `gpt-6-luna` | openai | 1,050,000 | 128,000 | $0.05 | $0.25 | $0.005 | $0.0625 | 1 | no |
| `claude-opus-5-5` | anthropic | 1,000,000 | 128,000 | $4.00 | $20.00 | $0.20 | $5.00 | 3 | no |
| `claude-sonnet-5-5` | anthropic | 1,000,000 | 128,000 | $2.00 | $10.00 | $0.10 | $2.50 | 2 | no |
| `gemini-4-argon` | google | 1,048,576 | 1,048,576 | $2.00 | $10.00 | $0.10 | — | 2 | no |
| `gpt-oss:120b` | ollama | 131,072 | 131,072 | 0 | 0 | 0 | 0 | 0 | yes |
| `qwen3.5:9b` | ollama | 262,144 | 262,144 | 0 | 0 | 0 | 0 | 0 | yes |

Facts that are deliberately bounded or marked unknown:

- `gemini-4-argon` has a **unified** 1,048,576-token input+output limit. The
  seed records that ceiling as both context and max output; a single foreground
  segment is 65,536 output tokens unless long decode is used. Its $2/$10 price
  is promotional through 2026-11-30 and becomes $4/$20 on 2026-12-01, which is
  exactly the drift the freshness task exists for.
- The two local rows have no vendor rate limit and no per-token price; their
  zero is a declared free route, not a missing value. `qwen3.5:9b` publishes a
  262,144-token native context and no separate output cap, so the context is
  recorded as the upper bound rather than inventing a smaller number.
- Anthropic and Google rate limits are left `None` (not fetched at build time);
  the OpenAI rows record the published **Build** tier limits
  (`gpt-6.2-sol`: 5,000 rpm / 1,000,000 tpm; `gpt-6-luna`: 5,000 rpm /
  2,000,000 tpm). A different account tier changes these, so they are a snapshot,
  not a guarantee.
- `gemini-4-argon` cache write is `None`: the model supports implicit caching
  only, so there is no explicit cache-write SKU at the check date.
- Capability grades are **internal routing judgments**, informed by the vendor's
  positioning and published benchmarks but not copied from a single number. The
  source/date rule applies to the factual fields (ids, limits, prices, rate
  limits); grades are revised by review, and the security/destructive floors
  make their consequences explicit.

Sources (all checked 2026-11-25):

| Source id | URL |
|---|---|
| `openai-gpt-6.2-sol-tracker` | https://llmmodels.org/models/gpt-6-2-sol |
| `openai-gpt-6-luna-tracker` | https://llmmodels.org/models/gpt-6-luna |
| `anthropic-opus-5-5` | https://platform.claude.com/docs/en/models/opus-5-5/overview |
| `anthropic-sonnet-5-5` | https://platform.claude.com/docs/en/models/sonnet-5-5/overview |
| `google-gemini-4-argon` | https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/4-argon |
| `openai-gpt-oss-120b` | https://developers.openai.com/api/docs/models/gpt-oss-120b |
| `qwen3.5-9b` | https://huggingface.co/Qwen/Qwen3.5-9B |
| `openai-pricing` | https://developers.openai.com/api/docs/pricing |
| `anthropic-pricing` | https://platform.claude.com/docs/en/about-claude/pricing |
| `anthropic-prompt-caching` | https://platform.claude.com/docs/en/build-with-claude/prompt-caching |
| `google-pricing` | https://cloud.google.com/model-garden/pricing |
| `ollama-gpt-oss-120b` | https://ollama.com/library/gpt-oss:120b |
| `ollama-qwen3.5` | https://ollama.com/library/qwen3.5 |

### Tier rule

`PoolSeed::to_pool` derives the escalation tier from the combined input+output
list rate, so tier and price cannot disagree by accident:

| Combined rate (micros/Mtok) | Tier |
|---|---:|
| 0 (declared free route) | 0 |
| 1 – 5,000,000 ($5) | 1 |
| 5,000,001 – 15,000,000 ($15) | 2 |
| above 15,000,000 | 3 |

`tier_for_combined_rate` is the exact function. The band is **price**, not
benchmark quality: two models in one band are escalation peers, and escalation
only moves to a strictly higher tier. A stronger model in the same band is an
`alternative`, not an escalation target. That is deliberate: a cost band is
stable data, while a quality score changes with every release.

### Conversion

`PoolSeed::to_pool()` returns `router::Pool`, mapping `available` from
`ga || preview`, `deprecated` from the lifecycle flag, and `tier` from the cost
band. `try_to_pool()` returns a `Result` for seeds loaded from storage;
`to_pool()` panics only on an invalid seed and is intended for the checked-in
default. The conversion preserves grades and input/output costs exactly, and
`Pool::new` re-checks the ids and grade maps, so a bad row cannot reach routing.

### Pool test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model pool -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`pool::tests` has 15 tests:

| Test | Evidence |
|---|---|
| `the_default_seed_loads_validates_and_is_the_size_the_task_asks_for` | The checked-in seed parses, validates, has 6–10 models, and records the table date. |
| `every_model_has_a_source_with_a_url_and_check_date` | Every model's `source_ref` resolves to a non-blank URL and a valid date no later than the table date. |
| `duplicate_model_ids_are_rejected` | A repeated id is `zero.fnd.already_exists`. |
| `invalid_dates_zero_limits_and_negative_prices_are_rejected` | Month 13 and a non-ISO date fail; zero context/output fail; a negative input price fails to parse. |
| `an_unknown_source_ref_is_rejected` | A dangling `source_ref` is `zero.fnd.invalid_input` naming the source index. |
| `blank_provider_family_and_mismatched_grades_are_rejected` | Blank provider/family and grades for a different model fail. |
| `a_local_only_marker_requires_a_local_provider` | A remote provider marked `local_only` is refused. |
| `to_pool_preserves_costs_grades_and_lifecycle` | Round trip preserves provider, grades, input/output cost, availability, deprecation, and tier. |
| `tier_follows_the_documented_cost_bands` | Every band boundary maps as documented; local is tier 0 and Opus is tier 3. |
| `the_seed_keeps_a_model_above_the_security_floor` | At least one seeded model clears the security floor and one clears destructive (Done: capability floor is satisfiable). |
| `at_least_one_model_is_local_only_and_free` | A local-only model exists, uses a local provider, costs zero, and is tier 0. |
| `a_deprecated_seed_model_is_excluded_by_the_router` | Marking a row deprecated makes the router skip it and report the reroute warning (MDL-14). |
| `the_seed_json_is_parseable_from_the_checked_in_file` | `data/models.json` parses directly with `serde_json` and equals `seed_default()`. |
| `load_path_reads_the_same_seed_and_enforces_the_size_bound` | A file load equals the embedded seed; an oversized file is `zero.fnd.limit_exceeded`; a missing file is `zero.fnd.io`. |
| `grades_cover_every_capability_axis_and_stay_on_scale` | Every row declares all seven capability axes and no grade exceeds 5. |

### Pool edge cases

- The OpenAI context/output numbers come from dated trackers because the vendor
  model pages used here do not publish them. The official OpenAI pricing page is
  a source for the prices, and both URLs are recorded; the tracker is the row's
  `source_ref` because it carries the limits.
- `gemini-4-argon`'s max output is the unified ceiling, not a per-request
  default. A caller that needs the foreground cap must use 65,536.
- Local prices are zero because the hardware and electricity are outside the
  token ledger. They are still a declared route, not an unknown one.
- A deprecated row stays in the seed until it is removed or replaced; the router
  excludes it and reports the reroute, so the withdrawal is visible rather than
  a silent disappearance.
- Re-checking the seed is manual today. A scheduled refresh is T-MDL-08's
  `freshness` path, which gates a snapshot by age before routing.
- The seed is data, not policy: `to_pool` assigns no allowlist, denylist, or
  privacy preference. Those are the caller's `Overrides`.

## Router

`router::route` turns a `Classification` and a `Pool` into a `RouteDecision`.
`router::escalate` moves up a tier when a call fails, with the failure evidence
attached. The code is `crates/zero-model/src/router.rs`. The router never reads
config files directly; the caller supplies the pool and overrides.

### Pool

`PoolModel` carries the routing fields:

| Field | Meaning |
|---|---|
| `model`, `provider` | Exact model id and provider id. |
| `grades` | `classify::ModelGrades`; the same type `classify::meets` checks. |
| `input_cost_micros_per_mtok`, `output_cost_micros_per_mtok` | Price in micros per million tokens. Required, never optional. |
| `available` | Whether the provider can serve the model now. |
| `deprecated` | Whether the model is withdrawn. |
| `tier` | Escalation level. Higher is stronger. |

`Pool::new` validates once:

- an empty model id is `zero.fnd.invalid_input`;
- an empty grade map is `zero.fnd.invalid_input` — a model without grades
  cannot be checked against a floor, so the entry is fixed or omitted;
- grades for a different model id are `zero.fnd.invalid_input`;
- a duplicate model id is `zero.fnd.already_exists`.

`Pool::new` is the validating constructor. A struct literal or a directly
deserialized `Pool` bypasses those checks, so a pool loaded from storage is
rebuilt through `Pool::new`.

Costs are mandatory in the type, so a missing price cannot be represented. A
zero rate is a **declared free route** (for example a local model), not
"unknown"; the router never invents a price. `pool.ordered()` is the
deterministic view: tier, then combined rate, then model id. `pool.get` returns
one model by id. `pool.len()` and `pool.is_empty()` report size.

The estimated cost applies the same token count to input and output:

```
cost_micros = (input_rate + output_rate) * estimate_tokens / 1_000_000
```

It truncates to whole micros and saturates instead of overflowing.

### Eligibility

A model is eligible when **all** of these hold, checked in this order:

1. `available` is true, otherwise it is excluded as unavailable;
2. `classify::meets(&grades, &classification.floor)` is ok, otherwise it is
   excluded as below the floor (missing grade = 0, so it fails closed);
3. it is not in the supplied failure history;
4. it is not in the denylist;
5. the allowlist is empty, or it is in the allowlist;
6. when `privacy_local_only` is set, its provider is local;
7. it is not deprecated (checked last, so only an otherwise-eligible
   deprecated model produces a reroute warning).

The router uses `classification.floor`, so a downgrade already recorded by
`classify::choose` is respected, while the `security` and `destructive` floors
still refuse any downgrade before a candidate is examined.

Local providers are `local`, `ollama`, `llamacpp`, `llama.cpp`, `lmstudio`, and
`vllm`, matched case-insensitively after trimming. This is the only locality
signal; the pool has no separate `local` flag.

Among eligible models the cheapest combined rate wins. Ties break on the model
id, so routing is deterministic. The rate order is also the cost order for any
positive token estimate, which keeps ordering stable when no estimate exists.

### Overrides (MDL-12)

`Overrides` is applied before selection:

- **Pin** (`pinned`) must name a model in the pool (`zero.fnd.not_found`
  otherwise). A pin is an override of preference, not of policy:
  - below the class floor, including `security` and `destructive`, it is
    refused with `zero.pol.denied` naming the class and missing capabilities;
  - denied by the denylist, outside a non-empty allowlist, or non-local under
    `privacy_local_only`, it is refused with `zero.pol.denied`;
  - deprecated, unavailable, or previously failed, it is rerouted to the
    cheapest eligible model and the reroute is reported in
    `RouteDecision::warnings` (MDL-14).
- **Denylist** (`deny`) wins over the pin and over the allowlist.
- **Allowlist** (`allow`) restricts eligibility when non-empty. Ids in the list
  that are not in the pool are ignored; a list with no matching model leaves
  nothing eligible.
- **Privacy** (`privacy_local_only`) restricts routing to local providers and
  applies to pins as well.

A pin never lowers a floor. `classify::choose` still owns the explicit
downgrade path for non-role work; the router has no downgrade input.

### Deprecation (MDL-14)

Deprecated models are never chosen. When a would-be-eligible model is
deprecated, or when the pinned model is deprecated, the route continues on an
eligible model and `RouteDecision::warnings` records the model id and the word
`deprecated`. A deprecated pinned model is rerouted, not dispatched, so
deprecation is never silent. A deprecated model that is also unavailable,
below the floor, denied, outside the allowlist, or non-local is reported under
that other exclusion instead; it cannot have been a viable route.

### Budget (SCH-06, MDL-08 surface)

`route` accepts `budget_micros: Option<u64>` as the **remaining** budget and an
`estimate_tokens` forecast. If the chosen model's estimated cost exceeds the
remaining budget, the result is `zero.fnd.limit_exceeded` before dispatch, and
the message names the estimate, the budget, and that nothing was dispatched.
The check is inclusive: a cost equal to the budget is allowed. With a budget,
`escalation_chain` and `alternatives` contain only models whose estimate also
fits, so the router never offers an escalation it would immediately refuse.
`route_with_failures` has no budget parameter; a caller that retries under a
budget re-checks it before dispatch.

### Escalation and evidence (MDL-04)

`RouteDecision::escalation_chain` lists eligible models strictly above the
chosen tier, in cost order. Same-tier models appear only in `alternatives`:
they are peers, not escalation targets.

`FailureEvidence` records only routing facts:

| Field | Meaning |
|---|---|
| `kind` | `failure`, `timeout`, `refusal`, or `low_confidence`. |
| `model` | The model that failed. |
| `attempts` | Attempts made on that model. |
| `message_summary` | Bounded diagnostic, never a prompt or transcript. |
| `cost_micros` | Cost already spent on the failed attempts. |

There is deliberately no prompt or message-content field. `FailureEvidence::new`
collapses whitespace, strips control characters, and truncates the summary to
200 characters on a char boundary; an empty summary falls back to the fixed
per-kind text. `FailureEvidence::for_kind` uses that canonical text directly.

`escalate(pool, decision, evidence)` returns an `Escalation`:

- `next` is the lowest eligible tier strictly above the failed model's tier,
  cheapest first within that tier; it is `None` when nothing remains;
- the failed model is skipped, so the same model is never retried;
- the tier is strictly greater, so escalation never downgrades;
- `exhausted` is true exactly when `next` is `None`;
- `evidence` is attached unchanged in every case, `exhausted` included.

Because the chain was built with the floor, overrides, deprecation, availability,
and budget applied, an escalation cannot undercut a security/destructive floor,
a denylist, or a privacy constraint.

`route_with_failures(pool, classification, overrides, failures)` applies a whole
history at once: it chooses the first non-failed eligible model in cost order and
reports the skipped ids in the reason. A repeated failure therefore walks up the
eligible order, never re-selects an earlier model, and reports
`zero.fnd.unavailable` with the failed ids when every model has failed.

### Router test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model router -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`router::tests` has 12 tests:

| Test | Evidence |
|---|---|
| `the_cheapest_eligible_model_above_the_floor_is_chosen` | Cheapest clearing model wins; a below-floor model is skipped; the chain and alternatives are cost ordered (Done: cheapest above floor). |
| `pin_is_honoured_only_when_eligible_and_below_floor_pins_are_refused` | A valid pin wins over the cheapest; an unknown pin is `zero.fnd.not_found`; a pin below the security floor is `zero.pol.denied` naming `reasoning>=5`, with no task text in the error. |
| `allow_deny_and_privacy_overrides_filter_the_pool` | Allowlist, denylist, and `privacy_local_only` each select the permitted model; a pin cannot override a denial or privacy. |
| `deprecated_models_are_excluded_and_the_reroute_is_reported` | The deprecated model is never chosen; the warning names it; a deprecated pin is rerouted with a warning (MDL-14). |
| `unavailable_models_are_excluded_and_reported` | An unavailable cheap model is skipped; with none available the error is `zero.fnd.unavailable` naming the class, floor, and `unavailable=1`. |
| `budget_refuses_before_dispatch_and_filters_the_chain` | A cost over the budget is `zero.fnd.limit_exceeded` before dispatch; the exact budget is inclusive; over-budget models leave the alternatives. |
| `escalation_moves_one_tier_up_and_attaches_evidence` | A fails → B, B fails → C; the evidence and its attempt/cost facts are attached (Done: a failure escalates with evidence). |
| `escalation_never_downgrades_or_retries_and_exhausts_with_evidence` | Above the top tier the result is `exhausted` with the evidence; the failed model is never returned; no move goes to a lower tier. |
| `route_with_failures_skips_failed_models_and_never_returns_them` | A failed → B, A+B failed → C; all failed → `zero.fnd.unavailable` with `previously_failed=3` and the failed ids. |
| `ties_and_ordering_are_deterministic` | `ordered()` sorts by tier, rate, then id; equal-cost ties choose the lexicographically first id; repeated routes are identical. |
| `failure_evidence_carries_no_prompt_text` | The summary is capped at 200 characters, whitespace is collapsed, the JSON has only the five documented keys, and no prompt/content field exists. |
| `pool_rejects_duplicate_ids_and_missing_grades` | Duplicate ids are `zero.fnd.already_exists`; empty grades and mismatched grade ids are `zero.fnd.invalid_input`. |

### Router edge cases

- `tier` is data quality: escalation moves only to a strictly higher tier. A
  pool where every model shares one tier routes correctly but cannot escalate;
  same-tier models are `alternatives` only.
- A zero token estimate makes every estimated cost zero, so budget checks pass
  and selection ties break by model id. Real budgets should use a positive
  forecast.
- The cost estimate applies one token count to both input and output. It is a
  prediction for gating, not a bill; `Usage` from the provider is authoritative.
- Deprecation warnings are raised only for models that pass every other filter,
  so a deprecated model that is already unavailable is counted as unavailable.
- `escalate` does not re-check the budget because `RouteDecision` does not carry
  one; the chain was budget-filtered at route time, and a caller that gains a
  new budget must re-route or call `route_with_failures` and check again.
- Escalation can change models mid-task, so the caller must account for cache
  loss on the switch (MDL-10) and for transcript translation (MDL-13).

## Translation

Escalation can change the provider in the middle of a task, so the transcript
has to be rewritten in the target's shape without losing a tool call that is
still in flight (T-MDL-05; MDL-13, MDL-05). The code is
`crates/zero-model/src/translation.rs`. The input is a canonical transcript, so
`from` labels the source for the report; `to` decides the id shape, system
placement, and which blocks are portable. `Transcript::render` is the separate
provider-wire projection, as a `serde_json::Value`.

### Canonical transcript

| Type | Shape |
|---|---|
| `Block::Text` | `{ text }` |
| `Block::ToolUse` | `{ id, name, arguments }` |
| `Block::ToolResult` | `{ tool_use_id, content, is_error }` |
| `Block::Image` | `{ media_type, data_b64 }` |
| `Block::Thinking` | `{ text }` |
| `Block::System` | `{ text }` |
| `Message` | `{ role: user \| assistant, blocks }` (re-exported as `TranscriptMessage`) |
| `Transcript` | `{ messages, tool_ids }` |

`Transcript::new(messages)` validates and computes `tool_ids`. `validate`
re-checks a transcript built by a struct literal or deserialized. Invariants:

- tool-use ids are unique;
- every tool result follows a tool use with the same id, and at most one result
  exists per call;
- a tool use is in an assistant message and a tool result in a user message;
- ids are non-empty, at most 512 bytes, and contain no control characters;
- text, thinking, and system blocks are at most 1 MiB; image base64 is at most
  8 MiB; tool arguments and tool-result content are at most 1 MiB each; tool
  names are at most 128 bytes; media types are at most 128 bytes;
- an image media type is an `image/*` type and its data is base64 text.

Pairing violations (orphan result, duplicate id, repeated result, wrong role)
are `zero.prv.protocol`; a malformed field or a `tool_ids` index that does not
match the blocks is `zero.fnd.invalid_input`; an oversized field is
`zero.fnd.limit_exceeded`. Errors name block positions and fixed field names
only, never text, arguments, or tool output.

System content is a block rather than a third message role. A leading user
message containing one `Block::System` is the canonical system slot. `translate`
collects every system block, merges the non-empty texts with a blank line, and
inserts that one slot; `system_text()` returns the merged instruction.

### Provider mappings

| Canonical | OpenAI | Anthropic | Gemini |
|---|---|---|---|
| System | leading `role: system` message | top-level `system` | `systemInstruction.parts[].text` |
| Text | `content` string or text part | `type: text` block | `parts[].text` |
| Tool use | assistant `tool_calls[]` with `id`, `type: function`, `function.name`, `function.arguments` (JSON string) | `type: tool_use` block with `id`, `name`, `input` | `functionCall` part with `name`, `args` |
| Tool result | `role: tool` message with `tool_call_id`, `content` | `type: tool_result` block with `tool_use_id`, `content`, `is_error` | `functionResponse` part with `name`, `response` |
| Image | `image_url` data URL | `type: image` with a base64 `source` | `inlineData` with `mimeType`, `data` |
| Thinking | not portable (dropped) | `type: thinking` with `thinking` text | not portable (dropped) |

`Transcript::render(format)` produces that wire shape. It refuses a block the
target cannot carry (a thinking block for OpenAI or Gemini, an unsupported
image media type) rather than silently omitting it; run `translate` first so
the loss is recorded.

### ID preservation and remapping

OpenAI and Anthropic tool ids are arbitrary strings, so `translate` preserves
an id that is non-empty, at most 40 (OpenAI) or 64 (Anthropic) characters, and
made of `[A-Za-z0-9_-]`. Anything else is remapped deterministically to a
`call_…` id, with a numeric suffix on collision.

Gemini pairs a function result with a function call by **name**, not by an id.
A translation to Gemini therefore maps each tool-use id to a name-keyed id
(`<sanitized-name>__<ordinal>`) and rewrites every tool result with the old id
to the same new id. The pair is recorded in
`TranslationReport::remapped_ids`; `mapped_id(old)` returns the new id, or
`None` when the id was preserved. Two calls to the same function receive
different ordinals, but Gemini's wire `functionResponse` carries only the
function name, so the wire itself cannot distinguish them. The canonical
transcript can, and the call order is preserved.

### Drops

A block the target cannot represent is removed and recorded in
`TranslationReport::dropped` as `{ index, kind, reason }`, where `index` is the
zero-based flattened block position in the input transcript. Nothing is dropped
silently.

- Thinking is Anthropic-specific in this model. A translation to OpenAI or
  Gemini drops it with a reason naming the target. A translation to Anthropic
  preserves the text; the provider signature is not part of the canonical block,
  and the report notes that limitation.
- Images are portable to all three formats for the media types each accepts
  (PNG, JPEG, WebP, GIF; Gemini also HEIC and HEIF). An unsupported media type
  is dropped with a reason naming the type and the target.
  `translate_with_capabilities` accepts a narrower `TargetCapabilities`, so a
  text-only target drops every image with a reason. Capabilities can only
  narrow target support; thinking is always clamped to the target.
- Tool use and tool result are never dropped: losing either half would break
  the pairing. If a target could not accept tools, translation would fail
  rather than lose a call.
- Empty messages left after a drop or after system hoisting are removed; the
  block-level report still names every drop.

An OpenAI `role: tool` message has no error flag. The canonical
`ToolResult::is_error` is kept, and `render(OpenAi)` writes an error result as
a JSON object string `{"is_error": true, "content": …}`. Gemini renders the flag
as an `error` field in `functionResponse.response`. Anthropic has the native
`is_error` field. The report adds a note when the target lacks the Anthropic
flag.

### Escalation

`translate_for_escalation(transcript, from, to)` is `translate` plus an explicit
pairing audit of the output and an escalation note. It is the Done criterion of
T-MDL-05: after a model switch, a pending tool call and its result stay paired.
If the target preserved the ids, nothing changes; if it remapped them, the
report's `remapped_ids` / `mapped_id` give the caller the new id to apply to a
tool result that arrives after the switch. The translated transcript carries
the new id on both sides, so re-validating it with `Transcript::new` passes.

### Translation test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model translation -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`translation::tests` has 21 tests:

| Test | Evidence |
|---|---|
| `every_provider_pair_preserves_text_roles_tool_pairing_and_images` | All nine source/target pairs keep text, roles, a PNG image, and one tool use/result pair; Gemini ids are the recorded remap. |
| `system_is_hoisted_and_merged_for_every_target` | Two system blocks in different messages become one leading slot with `one\n\ntwo`; OpenAI, Anthropic, and Gemini render it in their own field. |
| `openai_render_uses_system_tool_calls_and_tool_messages` | Leading system message, assistant `tool_calls` with `id` and string arguments, `role: tool` with `tool_call_id`, and an `image_url` data URL. |
| `anthropic_render_uses_tool_use_and_tool_result_blocks` | Top-level `system`, `tool_use` with `input`, `tool_result` with `tool_use_id`/`is_error`, and a base64 image source. |
| `gemini_render_uses_function_call_and_response` | `systemInstruction`, `functionCall` with `args`, `functionResponse` with the function name, and `inlineData`; the canonical pair uses the remapped id. |
| `thinking_is_dropped_for_targets_without_it_with_a_reason` | OpenAI and Gemini drop one thinking block with a reason naming the target; Anthropic keeps it and notes the missing signature. |
| `images_are_portable_but_unsupported_media_types_are_dropped` | PNG survives every target; `image/svg+xml` to Anthropic is dropped with the media type and target in the reason. |
| `a_text_only_target_drops_images_and_thinking_with_reasons` | `TargetCapabilities::text_only` drops the image and the thinking block with capability reasons, keeps text and tool pairing, and records both drops. |
| `tool_error_flags_are_preserved_and_projected_into_each_wire_shape` | Canonical `is_error` survives; OpenAI renders a JSON error object, Gemini an `error` field, and a round trip to Anthropic keeps the flag. |
| `invalid_and_oversized_ids_are_remapped_for_openai_and_anthropic` | An id with spaces remaps for both targets with a `call_` id and a recorded pair; a 50-character id remaps for OpenAI but is preserved by Anthropic. |
| `gemini_remaps_ids_consistently_even_for_repeated_function_names` | Two `read` calls map to `read__1` / `read__2`; tool uses and results agree; the duplicate-name limitation is noted. |
| `round_trip_reports_lossy_first_leg_and_preserves_text_roles_and_pairing` | Anthropic → OpenAI drops thinking in the first leg; OpenAI → Anthropic reports no further drop and keeps text, roles, system, and pairing. |
| `round_trip_through_gemini_keeps_pairing_and_ordering` | Gemini → Anthropic keeps the remapped ids (already valid for Anthropic), pairing, ordering, and text. |
| `escalation_mid_task_keeps_paired_tool_ids_valid` | `translate_for_escalation` preserves ids for OpenAI and remaps them for Gemini; every result still matches its use (Done). |
| `escalation_with_a_pending_tool_call_keeps_the_future_result_pairable` | A tool use with no result survives escalation; a later result using the mapped id validates, and escalation back keeps the pending call. |
| `invalid_pairing_and_duplicate_ids_are_typed_errors` | Orphan result, duplicate id, repeated result, and wrong role are `zero.prv.protocol`; a stale `tool_ids` index is `zero.fnd.invalid_input`; no prompt text leaks. |
| `oversized_and_malformed_blocks_are_rejected_without_prompt_text` | Oversized text/image/name/arguments and bad base64, media type, empty id, and control-char id are typed errors with no prompt text. |
| `render_refuses_non_portable_blocks_instead_of_losing_them` | Rendering a thinking block to OpenAI or an SVG image to OpenAI is `zero.prv.protocol`, not a silent omission. |
| `translation_is_deterministic` | Two translations and two escalations of the same input are identical. |
| `empty_transcripts_translate_and_render` | An empty transcript translates with no drops and renders as empty messages/contents. |
| `formats_use_stable_wire_labels` | `openai` is the wire label; parsing is case-insensitive (`google` → Gemini); a block serialises with the `tool_use` tag. |

### Translation edge cases

- `from` is a report label, because the input is the canonical transcript. The
  provider adapters own wire-JSON parsing; this layer owns the canonical
  invariants and the target rewrite.
- Gemini's `functionResponse` is name-keyed. Two in-flight calls to the same
  function have distinct canonical ids but the same wire name; the canonical
  transcript and the call order are the disambiguator.
- Anthropic thinking blocks require a provider signature that the canonical
  block does not carry. The text is preserved and the signature loss is noted;
  a caller that needs the signature must keep it outside the canonical block.
- OpenAI and Anthropic id bounds are conservative runtime bounds, not provider
  guarantees. An id outside them is remapped rather than rejected.
- `render` is intentionally stricter than `translate`: it refuses a block the
  target cannot carry, so a lossy translation must be run first and its report
  retained.
- OpenAI requires a tool result message immediately after the assistant tool
  call. `render(OpenAi)` therefore emits the tool messages before any user text
  that shares the same canonical message. Text-only OpenAI content is rendered
  as a string; an image forces the array-of-parts shape.
- Tool names are validated for emptiness, control characters, and the size
  bound only. A name outside a target's naming rule is passed through and may be
  refused by that provider; translation does not rename tools because the
  caller's tool registry is keyed by name.

## Freshness

A pool is only as good as the snapshot it came from. `zero_model::freshness`
makes the snapshot's origin and age part of routing, so a table fetched once and
never refreshed cannot keep pricing a model that changed last month, silently
(T-MDL-08; MDL-15, MDL-01). The code is `crates/zero-model/src/freshness.rs`.

### Snapshot and source

`ModelData` is one versioned table:

| Field | Meaning |
|---|---|
| `schema_version` | Snapshot format version. Starts at 1; 0 is refused. |
| `table_version` | Table version. `refresh` bumps it by one. |
| `source` | Where it came from: a URL, or a documented offline label such as `offline:seed`. Required, never blank. |
| `fetched_ms` | Fetch time in milliseconds since the Unix epoch. Ages are measured from it. |
| `models` | The `router::PoolModel` entries. |

`ModelData::new(schema_version, table_version, source, fetched_ms, models)`
validates before returning `Ok`. `ModelData::validate` re-checks a snapshot that
was built by a struct literal or deserialized, and `ModelData::pool` rebuilds it
through `Pool::new` for routing. The checks, in order:

- a blank `source` is `zero.fnd.invalid_input` — a table with no recorded origin
  cannot be refreshed or audited, so it is not a snapshot;
- `schema_version == 0` is `zero.fnd.invalid_input`;
- `fetched_ms == 0` or `fetched_ms > MAX_TIMESTAMP_MS` is `zero.fnd.invalid_input`
  — a fetch at the Unix epoch or after the year 3000 is impossible data, not a
  very old or very new table;
- an empty model id is `zero.fnd.invalid_input`;
- a duplicate model id is `zero.fnd.already_exists`.

`refresh` records the source label and fetch time in the new snapshot, so every
table names its origin and every age is traceable to a fetch.

### Policy and thresholds

`FreshnessPolicy { max_age_ms, hard_expiry_ms }` has two thresholds:

| Age | State | Routing |
|---|---|---|
| `<= max_age_ms` | `Fresh` | Allowed, no warning. |
| `> max_age_ms`, `<= hard_expiry_ms` | `Stale` | Allowed with a warning naming the source and age. |
| `> hard_expiry_ms` | `Expired` | Refused with `zero.fnd.unavailable` naming the source and asking for a refresh. |

The documented default (`FreshnessPolicy::default`) is 24 hours
(`DEFAULT_MAX_AGE_MS`) and 7 days (`DEFAULT_HARD_EXPIRY_MS`). `FreshnessPolicy::new`
refuses `hard_expiry_ms < max_age_ms` with `zero.fnd.invalid_input`: a hard
expiry inside the fresh window would make the stale state unreachable. Equal
thresholds are allowed and mean there is no warn-only window — every stale age
is expired.

Boundaries are inclusive. An age exactly equal to `max_age_ms` is still `Fresh`;
an age exactly equal to `hard_expiry_ms` is still `Stale`; one millisecond later
is `Expired`. Ages are `now_ms.saturating_sub(fetched_ms)`, so a clock that moves
backwards, or a `now` before the fetch, reads as age 0 and stays fresh instead of
producing a huge age. `freshness(data, now)` applies the default policy;
`freshness_with(data, policy, now)` applies a configured one.

### Gate and warning

`gate(data, policy, now)` validates the snapshot and then classifies it:

- `Fresh` returns `GateResult { data, warning: None }`;
- `Stale` returns `GateResult { data, warning: Some(..) }` where the warning
  names the source and the age in milliseconds, e.g.
  `model data source "https://…/models.json" is stale: age 10800000 ms exceeds
  the 7200000 ms freshness limit; a refresh is due and routing continues with
  this table in the meantime`;
- `Expired` returns `zero.fnd.unavailable` naming the source and the age and
  asking to `refresh the model data from <source> before routing`.

The warning text contains no prompt or task text; it names only the source, the
age, and the policy threshold.

### Refresh and drift

`RefreshSource` is the injectable fetch: `fetch(&self) -> Result<Vec<PoolModel>>`.
Nothing in this module opens a socket, so a scheduler wires the real fetch and a
test supplies a fixed table — no network is needed to exercise a refresh.

`refresh(current, source, source_label, now_ms)` fetches, validates the new
table through `ModelData::new`, keeps the schema version, sets `table_version` to
`current.table_version + 1` (saturating), and records `source_label` and
`now_ms`. It returns `RefreshReport { data, drift }`. A fetch error is returned
unchanged; an empty `source_label` is `zero.fnd.invalid_input`; neither records
anything.

`Drift` lists what changed between two tables:

| Field | Meaning |
|---|---|
| `added` | Model ids only in the new table, ascending. |
| `removed` | Model ids only in the old table, ascending. |
| `changed` | Models in both whose routing fields differ, ascending by id. |
| `table_version_from`, `table_version_to` | The versions compared. |

Each `DriftChange { model, fields }` lists its changed fields in the fixed order
`available`, `deprecated`, `grades`, `input_cost_micros_per_mtok`,
`output_cost_micros_per_mtok`, `provider`, `tier`. Deprecation, availability,
cost, and grade changes therefore always appear. An unchanged model produces no
`changed` entry, and an unchanged table produces an empty drift (with only the
version numbers differing). `drift(from, to)` exposes the comparison directly and
is what `refresh` uses, so a caller can diff two stored snapshots.

### Router wrapper

`route_fresh(data, policy, classification, overrides, budget, estimate,
now_ms) -> Result<(RouteDecision, Option<String>)>` gates the table and then calls
the unchanged `router::route`:

- fresh: the decision plus `None`;
- stale: the decision plus `Some(warning)`. The same warning is appended to
  `RouteDecision::warnings`, so a caller that already prints router warnings
  cannot drop it. This is the Done criterion of T-MDL-08: a stale table warns
  instead of routing on it silently;
- expired: `zero.fnd.unavailable` and no decision.

**A caller that has a `FreshnessPolicy` must use `route_fresh`, not `router::route`.**
`route` has no age input, so it cannot warn; routing around the gate reintroduces
the silent-stale failure this section exists to prevent. `route_fresh` validates
the snapshot and rebuilds the pool, so a table with duplicate ids, a blank
source, or a missing grade map fails before a model is considered.

Two helpers drive a scheduled refresh: `is_stale_and_unrefreshed(data, policy,
now)` is true exactly for `Stale` (due for a refresh, still routable with a
warning), and `needs_refresh(data, policy, now)` is true for `Stale` or `Expired`.
An expired table is worse than stale, so it is not "merely stale".

### Freshness test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model freshness -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`freshness::tests` has 9 tests:

| Test | Evidence |
|---|---|
| `freshness_boundaries_are_inclusive_and_ages_clamp` | Age at `max_age_ms` is fresh, at `hard_expiry_ms` is stale, one millisecond past each flips; a `now` before the fetch clamps to 0; the default policy is 24 h / 7 d. |
| `policy_rejects_hard_expiry_before_max_age` | Equal thresholds are accepted; a hard expiry inside the window is `zero.fnd.invalid_input`. |
| `a_stale_table_warns_with_its_source_and_age` | A fresh gate has no warning; a stale gate warns with the source and the age in milliseconds. |
| `an_expired_table_is_refused_with_a_refresh_request` | `zero.fnd.unavailable` naming the source, the age, and the refresh request. |
| `refresh_records_the_source_and_time_and_reports_drift` | New source, fetch time, schema, and `table_version + 1`; added/removed/changed lists, deprecation/cost/grade/availability fields; a fetch error changes nothing; an empty label is refused. |
| `drift_order_is_deterministic` | Added and removed ascending, changed ascending by id, fields in fixed order; identical inputs give identical reports. |
| `model_data_rejects_duplicates_empty_source_and_impossible_timestamps` | Duplicate ids `zero.fnd.already_exists`; blank source, epoch 0, past year 3000 `zero.fnd.invalid_input`; the boundary timestamp and an `offline:` label are accepted; `validate` catches a bypassed literal. |
| `route_fresh_warns_on_a_stale_table_and_refuses_an_expired_one` | Stale routes with the warning in the tuple and in `RouteDecision::warnings` (Done: not silent); fresh is silent; expired refuses. |
| `refresh_helpers_track_staleness` | `is_stale_and_unrefreshed` is stale only; `needs_refresh` is stale or expired. |

### Freshness edge cases

- "Impossible timestamp" is a structural bound, not a clock check: `validate`
  has no `now`, so a fetch time later than the wall clock is still accepted. The
  age clamp turns that into age 0, not into a negative age.
- A stale warning and an expired refusal name the `source` verbatim. A source
  that embeds a token in its URL would be echoed into the warning; sources are
  URLs or documented labels, not credential carriers.
- `refresh` bumps `table_version` even when the drift is empty: the version
  records that a refresh happened, not that the data changed.
- A refresh is a full replacement, not a merge. A model missing from the fetched
  table is reported as `removed` and disappears from routing.
- The policy is deliberately not embedded in `ModelData`, because two callers
  can reasonably hold different tolerances for the same table. The snapshot
  records the facts; the policy records the tolerance.

## Measured routing

The router picks the cheapest eligible model, but a model that keeps failing,
timing out, or costing more than predicted should not keep winning on price
alone. `zero_model::measured` makes recorded outcomes part of routing without
letting a handful of samples rewrite it (T-MDL-07; MDL-08, MDL-09). The code is
`crates/zero-model/src/measured.rs`. The decision entry point is
`zero_model::measured::choose`; it is namespaced because `zero_model::choose`
is already the classifier's selection function. The types and helpers are
re-exported from the crate root. A role (MDL-07) routes as its work class, so
role traffic is measured under the same classes the router already uses.

### Outcomes and the outcome log

`Outcome` is one recorded call. There is no prompt, message, or response field;
`deny_unknown_fields` makes a planted `prompt` key malformed instead of stored.

| Field | Meaning |
|---|---|
| `model` | The model that served the call. Required, never blank. |
| `class` | The `WorkClass` the call was routed as. |
| `success` | Whether the call produced a usable result. |
| `retries` | Retries spent before the result. |
| `latency_ms` | Observed latency in milliseconds. |
| `cost_micros` | Actual cost in micros. |
| `at_ms` | Wall-clock time in milliseconds since the Unix epoch. Negative is refused. |

`Outcome::new` validates the model id and timestamp. `Outcome::stable_id` is a
64-bit FNV-1a hash of a length-prefixed encoding of every field, so replaying
the same outcome does not add a second sample. A hash collision is treated as a
duplicate; at 64 bits that is negligible for an outcome log.

`OutcomeLog` is bounded, in memory, with an optional JSONL file:

- the in-memory bound is `DEFAULT_MAX_OUTCOMES` (100,000) or an explicit
  `with_max_entries` value; the oldest outcome is evicted first;
- `with_path` loads an existing JSONL log (a missing file is empty) and appends
  every accepted outcome as one line, flushed and fsynced, mode `0600` on Unix;
- the file is bounded by `MAX_OUTCOME_LOG_BYTES` (16 MiB); an append that would
  cross it is `zero.fnd.limit_exceeded` and writes nothing — rotate the log;
- `append` returns `true` when stored and `false` for an exact duplicate, so a
  retried observation is idempotent;
- loading is lenient: a malformed or torn line is skipped, so recording can
  continue; non-UTF-8 bytes are `zero.fnd.corrupt`.

### Statistics

`ModelStats` is computed per `(model, class)` from the outcomes inside a window:

| Field | Meaning |
|---|---|
| `model`, `class` | The key. Classes are never mixed. |
| `samples` | Samples inside the window. |
| `successes` | Samples that succeeded. |
| `retries` | Summed retries across the samples. |
| `avg_latency_ms`, `avg_cost_micros` | Integer floors of the sums divided by `samples`. |
| `success_rate_bps` | `successes * 10_000 / samples`, floored; 10,000 is perfect. |

`model_stats(outcomes, class, window_ms, now_ms)` and
`OutcomeLog::stats(class, window_ms, now_ms)` aggregate. A sample is inside the
window when `at_ms <= now_ms` and `now_ms - at_ms <= window_ms`; a timestamp in
the future is ignored, and boundaries are inclusive. A negative window is
clamped to 0. Sums saturate instead of overflowing. Stats are ordered by model
id, so the output is deterministic.

`prediction_error(stats)` is the standard error of the success rate, in basis
points: `floor(sqrt(rate * (10_000 - rate) / samples))`. It falls as samples
grow (80% over 100 samples is 400 bps), so a caller can compare it with
`min_improvement_bps` before treating a gap as real. Zero samples or a perfect
record is 0.

### Policy

`MeasuredPolicy` sets the evidence rules:

| Field | Meaning |
|---|---|
| `min_samples` | Samples a candidate needs to count as measured. At least 1. |
| `explore_bps` | Exploration rate in basis points, `0..=10_000`. |
| `min_improvement_bps` | Success-rate gain required to switch, `0..=10_000`. |
| `window_ms` | Stats window in milliseconds. Must be positive. |

`MeasuredPolicy::new` rejects `min_samples == 0` (`zero.fnd.invalid_input`) —
a switch with no samples is not evidence-based — and the other out-of-range
values with the same code. `MeasuredPolicy::default()` is five samples, 5%
exploration, a 5% improvement threshold, and a seven-day window.

### Choosing

`choose(candidates, policy, fallback_model, rng_seed) -> MeasuredChoice`:

1. **Insufficient evidence.** When no candidate has `min_samples` samples, the
   fallback is kept and the reason starts with `insufficient evidence`. This is
   the Done criterion: routing does not change without evidence. A model with
   zero samples is never chosen as a measured result.
2. **Exploit.** The best measured candidate wins when its success rate beats
   the fallback's measured rate by at least `min_improvement_bps`. "Best" is
   highest success rate, then lower average cost, then lower average latency,
   then the lexicographically smaller model id. The winner's stats are attached
   as `evidence`.
3. **Keep.** Below the threshold the fallback stays, and the reason names the
   gain, both rates, and the threshold.
4. **Explore.** Only when no switch is warranted, a seeded roll below
   `explore_bps` picks a measured model other than the best and the fallback,
   recording `explored = true` and its stats as the evidence. Exploration never
   overrides a switch that already cleared the threshold; when no such third
   candidate exists the roll is a no-op.

`MeasuredChoice` carries `chosen`, `reason`, `evidence: Option<ModelStats>`, and
`explored`. The reason is deterministic for the same inputs and seed and names
model ids, classes, rates, costs, latencies, and thresholds only.

Two edge cases are explicit:

- A fallback with no samples in the window has no measured baseline to defend,
  so the best measured candidate is chosen, with its evidence. This is a change
  to a measured model, never to an unmeasured one, and it avoids pinning
  routing forever to an unobserved incumbent.
- When the fallback is already the best measured candidate it stays, with its
  stats attached as evidence; exploration may still sample an alternative.

The work class comes from the fallback's stats when present, else from the
first candidate; candidates of any other class are ignored. Callers normally
pass one class's stats from `OutcomeLog::stats`.

### Reconciliation and budget

`reconcile(predicted_micros, actual_micros)` returns:

| Field | Meaning |
|---|---|
| `delta` | `actual - predicted`, saturated to the `i64` range. |
| `ratio_bps` | `actual / predicted` in basis points. |
| `within_tolerance` | Absolute delta divided by the prediction is at most `RECONCILIATION_TOLERANCE_BPS` (2,000 bps, 20%). |

The tolerance is inclusive and relative to the prediction; `reconcile_with_tolerance`
sets it explicitly. A zero prediction is a special case: a zero actual is a
perfect prediction (`ratio_bps = 10_000`, within tolerance), while a non-zero
actual is out of tolerance and reports `ratio_bps = u32::MAX` rather than
dividing by zero. `prediction_error` above reports the sampling error of the
success-rate input, not of the cost.

`preflight_budget(remaining_micros, predicted_micros)` is the dispatch gate. A
prediction equal to the remaining budget is allowed; a larger one is
`zero.fnd.limit_exceeded` naming both numbers and `nothing was dispatched`,
before any provider call. This is the MDL-08 predicted-cost check, separate
from the router's per-route budget filter.

### Recording then routing

`record_and_choose(log, outcome, policy, fallback_model, rng_seed, now_ms)`
appends the outcome and then chooses for that outcome's class using the updated
stats. The just-recorded sample is visible to the choice, so a turn's result can
change the next turn's route. A duplicate outcome does not add a sample, but the
choice still reflects the log as it stands.

### Measured routing test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model measured -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`measured::tests` has 17 tests:

| Test | Evidence |
|---|---|
| `insufficient_samples_keep_the_fallback` | Two-sample candidates under a three-sample minimum keep the fallback with `insufficient evidence` and no evidence; no outcomes at all behaves the same (Done: no change without evidence). |
| `clear_improvement_switches_with_evidence` | 9,000 bps over the incumbent's 6,000 bps clears a 1,000 bps threshold; the winner and its stats are attached; an unmeasured fallback loses to the measured candidate without exploration overriding it. |
| `improvement_below_the_minimum_does_not_switch` | A 500 bps gain under a 501 bps threshold keeps the fallback and names both numbers. |
| `a_regression_does_not_switch_and_a_drop_reverts` | A regressed candidate cannot displace a perfect incumbent; when the incumbent's recent success drops, the measured model wins. |
| `exploration_is_deterministic_at_a_seeded_rate` | A 100% exploration policy always picks a non-best measured model, the same seed repeats exactly, seeds reach more than one target, and `explore_bps = 0` never explores. |
| `cost_then_latency_then_id_break_ties` | Equal success rates choose lower cost, then lower latency, then the smaller model id. |
| `the_window_excludes_old_and_future_samples` | The boundary sample is included, the sample one millisecond older and a future sample are excluded; a zero window keeps only `now`, a negative window is clamped. |
| `classes_never_mix` | Aggregation filters by class; a strong plan candidate cannot win an edit decision and the evidence class is `edit`. |
| `reconciliation_reports_within_and_out_of_tolerance` | Within, over, and under predictions; the 20% boundary is inclusive; zero predictions avoid division by zero; an explicit tolerance changes the verdict. |
| `prediction_error_shrinks_with_samples` | No samples and a perfect record are 0; 80% over 100 samples is 400 bps. |
| `the_budget_gate_refuses_before_dispatch` | An equal budget passes; a 100 µs prediction against 99 µs is `zero.fnd.limit_exceeded` with `nothing was dispatched`. |
| `the_policy_validates_its_bounds` | Zero samples, out-of-range basis points, and a zero window are `zero.fnd.invalid_input`; the upper bounds are accepted. |
| `a_measured_choice_is_recorded_before_routing` | Seeded failures and successes switch the fallback; the recorded outcome lifts the winner to 6 samples and the log grows. |
| `the_outcome_log_dedupes_bounds_and_round_trips` | A duplicate id is refused; the bound evicts and frees the oldest id; JSONL reload restores the same order. |
| `outcomes_and_stats_expose_no_prompt_text` | The JSON keys are exactly the documented schema; a planted `prompt` line is malformed; stats and reasons have no prompt/content/message/transcript key or word. |
| `reasons_are_deterministic` | The same candidates, policy, and seed produce an identical choice, reason included, for both exploit and explore paths. |
| `an_outcome_rejects_a_blank_model_and_negative_time` | Blank model ids and negative timestamps are `zero.fnd.invalid_input` and are not stored. |

### Measured routing edge cases

- Exploration is an evidence-gathering exception, not a random override: it is
  considered only when the exploit decision keeps the fallback, and it never
  selects an unmeasured model.
- The fallback may have zero samples; an unmeasured incumbent loses to a
  measured candidate. The reverse never happens.
- `avg_latency_ms` and `avg_cost_micros` are integer floors, so a comparison of
  two very small averages can tie and fall through to the next tie-break.
- `retries` is a sum, not an average: it shows the retry volume behind the
  samples rather than a per-call rate.
- Outcomes are deduplicated by content, including `at_ms`. Replaying the exact
  same observation is idempotent; the same call at a different time is a
  separate sample.
- The JSONL store is the durable history; the in-memory bound only limits the
  aggregation input. A restart reloads the file, re-applies the bound, and keeps
  the newest outcomes.
- Within one work class, the candidate slice's order does not affect the best
  choice (the model id breaks full ties) or the exploration target (targets are
  sorted by model id).
- Reconciling a very large overspend saturates `delta` at `i64::MAX` and
  `ratio_bps` at `u32::MAX`; both are sentinels, not exact values.

## Decision records

Every turn records the model, the model version, the parameters, the router
reason, and the cost (MDL-11; T-MDL-06). The code is
`crates/zero-model/src/decision.rs`; this section is its contract.

### Schema

`TurnRecord` has exactly these fields. There is deliberately no prompt,
response, message, tool-output, or transcript field.

| Field | Type | Meaning |
|---|---|---|
| `turn_id` | `TurnId` (number) | Per-session turn number. Numeric so a sequence gap is detectable. |
| `session` | string | Session the turn belongs to. Required. |
| `at_ms` | integer | Wall-clock timestamp in milliseconds. |
| `model` | string | Exact model id the router chose. Required. |
| `model_version` | string | Exact version or snapshot id that was served. Required. |
| `provider` | string | Provider id. Required. |
| `parameters` | `ModelParameters` | See the parameter table below. |
| `class` | `WorkClass`, optional | The work class the turn was routed as. |
| `role` | string, optional | The agent role (`planner`, `coder`, …), not the message role. |
| `router_reason` | string | The deterministic reason from `RouteDecision::reason`. Required. |
| `assignment_source` | string, optional | `default`, `user_pinned`, `upgrade_requested`, `fallback`, or a router label. |
| `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens` | unsigned integer | Normalized provider usage. |
| `estimated_cost_micros` | unsigned integer | Pre-dispatch estimate. |
| `actual_cost_micros` | unsigned integer | Billed cost from `Usage::cost_micros`. |
| `escalation` | `EscalationRecord`, optional | `from_model`, `evidence_kind` (`failure`, `timeout`, `refusal`, `low_confidence`), `attempts`. |

`TurnRecord::validate` rejects a blank `session`, `model`, `model_version`,
`provider`, or `router_reason`; a blank optional `role` or
`assignment_source`; an escalation with a blank `from_model` or zero attempts;
and any invalid parameter. `TurnRecord::new(TurnRecordInit { … })` is the
validating constructor; `with_class`, `with_role`, `with_assignment_source`,
`with_usage`, and `with_escalation` add the optional fields.

`TurnRecord::from_decision(context, decision, parameters, usage, evidence)`
copies the model, provider, and router reason from the `RouteDecision`, the
token counters and actual cost from `Usage`, and the escalation from
`FailureEvidence` without its diagnostic summary. The class, role, version, and
assignment source are not carried by a `RouteDecision`, so the caller supplies
them in `DecisionContext`. The estimate is recomputed from the observed token
count because the decision does not retain its pre-dispatch forecast; a caller
that has the forecast overwrites `estimated_cost_micros`.

### Parameters

| Field | Accepted range |
|---|---|
| `temperature` | finite, `0.0..=2.0` (the union of the provider ranges this runtime speaks) |
| `top_p` | finite, `0.0..=1.0` |
| `max_output_tokens` | `1..=4_194_304` (a structural sanity bound, not a provider limit) |
| `reasoning_effort` | `none`, `minimal`, `low`, `medium`, `high` |

An unknown `reasoning_effort` label, an unknown field, or a value of the wrong
JSON type is rejected by deserialization. A NaN or infinite float, a negative
number, or a fractional integer is rejected the same way; `validate` also
rejects a non-finite or out-of-range value built in Rust. Token counts and costs
are unsigned integer micros, so a negative count or a non-finite cost is
unrepresentable in the type and a JSON line carrying one fails to deserialize.

### Append-only store

`DecisionLog::new(path)` points at one log. `append(record)`:

1. validates the record;
2. serialises it as one compact JSON object plus a newline;
3. refuses an append that would push the file past `MAX_LOG_BYTES` (64 MiB)
   with `zero.fnd.limit_exceeded`, writing nothing — rotate to a new log;
4. refuses to extend a log that is already damaged — a malformed line or a torn
   tail (`zero.fnd.corrupt`); rotate to a new log instead of appending past the
   damage;
5. refuses a second record with the same `(session, turn_id)` with
   `zero.fnd.already_exists` — append is **not** idempotent, so a duplicate turn
   is a caller bug, never a silently repeated line;
6. writes the whole line, flushes, and fsyncs before returning, and restricts
   the file to mode `0600` on Unix.

There is no update, delete, or rewrite API. The duplicate check is a safety net
within one writer; cross-process exclusion is the session lease's job (SES-06),
not this log's.

`read_all` is the lenient reader. A missing file is an empty report. One
malformed complete line is skipped and counted; a valid line whose
`(session, turn_id)` was already seen is counted as a duplicate and the first
record wins; an unterminated final line is flagged as a torn tail and is not
returned. A JSON array, non-UTF-8 bytes, or newline-terminated text lines are not
a decision log and return `zero.fnd.corrupt`. Because `TurnRecord` uses
`deny_unknown_fields`, a planted `prompt` field makes the line malformed instead
of being stored.

### Reconstruction and audit

`reconstruct(session, log)` is the strict reader:

- a malformed line, a record that fails validation, or a torn tail fails with
  `zero.fnd.corrupt`; the audit never returns a partial history;
- every valid turn of the session appears exactly once, ordered by `turn_id`
  (deduplication is by `(session, turn_id)`, first record wins);
- each turn carries its model, version, parameters, router reason, tokens, and
  cost;
- totals sum turns, the four token counters, and estimated and actual cost with
  saturation;
- a jump in the turn sequence is reported in `SessionAudit::gaps`
  (`after`, `before`, `missing`), not silently ignored. A session that starts
  mid-sequence reports no prefix gap: only the turns present in the log are
  audited.

An empty or unknown session reconstructs to an empty audit with zero totals, not
an error. `verify_turn(record, expected_model, expected_params)` checks one
record against an expectation: any difference is `zero.pol.conflict` naming the
turn and the field. `audit_line(record)` renders the deterministic summary
(model, version, provider, parameters, class, role, source, reason, tokens,
cost, escalation); it cannot leak a prompt because the record has no prompt
field.

### Ledger comparison

`compare_with_ledger(records, usage_events)` reconciles records against a usage
ledger without making `zero-model` depend on the scheduler. The caller projects
each `UsageEvent` into `LedgerEvent { session, turn_id, model, input_tokens,
output_tokens, cache_read_tokens, cache_write_tokens, cost_micros }`.

- A record with a matching `(session, turn_id)` must agree on the model, all
  four token counters, and `actual_cost_micros`. Each disagreement is a
  `Mismatch` with a `MissingEvent`, `Model`, `Tokens`, or `Cost` kind.
- A record with no matching event is reported as `MissingEvent`; it is not an
  error, because a turn can be recorded before the ledger syncs.
- Duplicate records or duplicate events for one key make the comparison
  ambiguous and return `zero.fnd.already_exists`.
- Events with no matching record are ignored, so a whole-device ledger can be
  passed. Output order is `(session, turn_id)` ascending.

### Decision record test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model decision -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`decision::tests` has 17 tests (16 on Windows; the `0600` test is Unix-only):

| Test | Evidence |
|---|---|
| `append_and_reload_round_trips_and_creates_missing_directories` | Two records reload in file order; parent directories are created; a missing log reads as empty. |
| `reconstruct_returns_every_turn_once_in_order_with_totals` | Out-of-order appends reconstruct as turns 1, 2, 3 with the other session excluded; totals and required fields are present. |
| `duplicate_turn_id_is_refused_and_a_different_session_is_allowed` | A second append for the same `(session, turn)` is `zero.fnd.already_exists`, identical or changed; another session may reuse the turn number. |
| `malformed_lines_are_skipped_and_counted` | `read_all` keeps the valid record, counts two bad lines and one duplicate; the strict audit refuses with `zero.fnd.corrupt` and an append to the damaged log is refused. |
| `a_non_jsonl_file_is_rejected` | A JSON array and text lines are `zero.fnd.corrupt`. |
| `torn_tail_is_flagged_and_reconstruction_refuses_it` | An unterminated final line is dropped and flagged; the audit refuses and so does an append. |
| `missing_fields_fail_with_a_typed_error` | Missing fields are a typed failure; blank model, session, version, and reason are `zero.fnd.invalid_input`. |
| `parameters_reject_unknown_and_out_of_range_values` | Boundary values pass; NaN, infinity, out-of-range temperature/top-p/output, unknown effort, unknown field, wrong type, negative, and fractional values fail. |
| `escalation_and_decision_fields_are_copied_without_prompt_content` | Class, role, source, reason, tokens, estimate, actual cost, and the escalation are copied; the escalation object has only `from_model`, `evidence_kind`, `attempts`; zero attempts is refused. |
| `audit_summary_and_serde_expose_no_prompt_text` | The record's JSON keys are exactly the schema; no prompt/response/content/message/transcript key exists; a planted `prompt` line is malformed and never surfaces in serde or Debug output; the audit line contains model, version, parameters, reason, and cost. |
| `sequence_gaps_are_reported_and_not_silently_ignored` | Turns 1, 2, 5, 6 report one gap (`2 → 5`, missing 2); a session that starts at 9 reports no prefix gap. |
| `empty_session_reconstructs_to_no_turns` | A missing log and another session's log both reconstruct to an empty audit with zero totals. |
| `ledger_comparison_detects_mismatches_and_missing_events` | Model, token, and cost disagreements are found; a missing event is reported but not fatal; duplicate events are `zero.fnd.already_exists`. |
| `verify_turn_checks_model_and_parameters` | A matching record passes; a different model or parameter set is `zero.pol.conflict`; a blank expected model is `zero.fnd.invalid_input`. |
| `the_log_is_bounded` | A log at `MAX_LOG_BYTES` refuses the next append with `zero.fnd.limit_exceeded` and the file is unchanged. |
| `the_log_is_owner_only_on_unix` | A new and a previously `0644` file are both `0600` after append. |

`audit_totals_saturate_instead_of_overflowing` also covers the saturating sum
used by `reconstruct`.

### Decision record edge cases

- Turn numbers are per session. Two sessions legitimately both contain turn 1,
  so the store and the audit key on `(session, turn_id)`; deduplication is not
  global by turn number alone.
- A resumed session may start at turn 9. The audit reports gaps only between
  recorded turns; an absent prefix is not evidence that turns 0–8 were lost.
- The strict audit refuses the whole reconstruction when any line is bad, even a
  line belonging to another session. That is deliberate: a damaged log cannot
  prove completeness for any session.
- `append` reads the log to enforce the duplicate rule, so appending is O(n) in
  the log size. The 64 MiB bound and one log per session keep that bounded;
  callers that append thousands of turns should rotate per session.
- A concurrent writer can still race the duplicate check on platforms without
  atomic append; the session lease is the exclusion mechanism.

## Classifier test evidence

Run:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-model classify -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-model --all-targets -j 1 -- -D warnings
```

`classify::tests` covers, with 11 tests:

| Test | Evidence |
|---|---|
| `every_class_is_reachable_and_carries_its_floor` | One fixture per class, each with its floor and a reason. |
| `security_and_destructive_outrank_plan_review_and_edit` | Secrets beat plan/edit; irreversible beats review/test; network auth and shell-destructive keywords raise. |
| `explicit_asks_beat_keywords_and_keywords_beat_the_default` | Ask precedence, keyword fallback, read-only and edit defaults. |
| `keywords_match_whole_words_not_substrings` | `latest` does not match `test`. |
| `security_keywords_and_network_auth_raise_to_security` | CVE keyword and auth-over-network; plain network research stays `plan`. |
| `meets_reports_every_missing_capability_and_unknown_is_zero` | `meets` output, unknown capability = 0, exact missing tuple. |
| `security_and_destructive_refuse_a_downgrade_even_when_asked` | `zero.pol.denied`, class and capability named, refusal recorded, no prompt text. |
| `non_security_classes_downgrade_only_within_policy` | Edit refuses below-floor without a request, accepts a recorded grade-2 request, ignores a request above the floor. |
| `the_cheapest_model_above_the_floor_is_selected` | Cheapest eligible wins, below-floor skipped, ties by name, empty candidates report `zero.fnd.unavailable`. |
| `reasons_are_deterministic` | Two runs produce identical reasons and the same selection. |
| `grades_are_clamped_and_ordered` | 0–5 clamping, ordering, absent capability = 0. |

## Known heuristic limits

- Classification is lexical. It understands the flags the caller sets and a
  fixed English keyword table; it does not parse intent, and a paraphrase with
  no keyword and no flag falls to the read-only or edit default.
- `touches_shell` alone is `edit`, because builder tasks run commands. A
  genuinely dangerous shell command must set `irreversible`; the keyword
  backstop only catches the listed literals.
- When several asks are set the higher-priority ask wins; the reasons record
  the winner but not the conflict.
- `cheapness` is the sum of declared grades, not price. A pool entry should
  declare every capability so the sum reflects the whole model; a sparse entry
  can look cheaper on axes its class does not require.
