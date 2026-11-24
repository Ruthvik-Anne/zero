# Configuration

One schema, six layers. The code lives in `zero_types::config`; the matrix test
covers every ordered pair of layers and the untrusted-project cases.

## Resolution order

Lowest to highest. The highest layer that supplies a key wins.

| # | Layer | Source | Trust |
|---|---|---|---|
| 0 | `defaults` | Built into the binary | trusted |
| 1 | `user` | Per-user config directory | trusted |
| 2 | `trusted_project` | `.zero/config.toml` in a trusted project | trusted only after explicit trust |
| 3 | `environment` | Environment variables | trusted |
| 4 | `cli` | Flags on this invocation | trusted |
| 5 | `session` | Values set for this session | trusted |

**Untrusted project config is inert.** If a project is not trusted, its layer is
dropped before resolution: it cannot override a default, and it cannot introduce
a key. This is tested for every other layer, not just defaults.

## Rules

- Resolution is deterministic: a key's winning layer is recorded (`source`) for
  display and audit.
- An empty key is a typed `zero.fnd.config_invalid` error.
- Within one layer the last write wins; this is explicit rather than accidental.
- `features.md` FND-05 and POL-06 define the trust requirement; `architecture.md`
  §10 defines the boundary.
