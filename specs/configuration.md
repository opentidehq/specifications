---
spec: configuration
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Configuration and overrides

## Summary

OpenTide merges bundled package configuration with optional client overrides from `.opentide/configurations/`. Deep merge applies at the TOML key level; later layers override earlier ones for scalar and replaced subtrees.

## Requirements

- Bundled configuration MUST include `paths.toml` (or equivalent `global` alias).
- Client overrides MUST live only under `.opentide/configurations/` in the discovered workspace.
- Merge order MUST be: bundled package → bundled platforms → client workspace → parent instance (if applicable).
- Vocabulary files MUST NOT be overridden by clients; extensions use `schema.toml` only.
- Files under `.opentide/schemas/` MUST NOT be treated as configuration overrides.
- Platform configurations MUST be keyed by `platform.identifier`, `tide.identifier`, or filename stem.

## Definition

### Merge layers

| Layer | Source | Notes |
|-------|--------|-------|
| 1. Bundled | `opentide.data.configurations/` | `paths.toml`, `deployment.toml`, `schema.toml`, etc. |
| 2. Bundled platforms | `configurations/platforms/*.toml` | Merged into `platforms` / `systems` |
| 3. Client workspace | `.opentide/configurations/` | Deep-merged on top |
| 4. Parent instance | `../.opentide/configurations/` | When workspace is nested |

An additional implementation-only layer applies during opentide's own test suite (selected by `OPENTIDE_TIDE_WORKSPACE`); it is not part of a normal client workspace and authors can ignore it.

If bundled config lacks `global`, `paths` is aliased to `global`. If `platforms` is absent, `systems` is used as fallback.

### Overridable configuration files

| File | May override? | Purpose |
|------|---------------|---------|
| `paths.toml` | Yes | Workspace directory paths |
| `deployment.toml` | Yes | Rule lifecycle statuses and promotion |
| `schema.toml` | Yes | Template defaults, vocabulary extensions |
| `visibility.toml` | Yes | Visibility configuration |
| `documentation.toml` | Yes | Documentation generation settings |
| `platforms/*.toml` | Yes | Per-platform connection and behavior |
| Vocabulary `.vocab.toml` | **No** | Canonical in `specifications/vocabularies/` |
| `.opentide/schemas/*` | **No** | Generated artifacts |

### Configuration discovery

- Top-level `.toml` files in a configuration directory map to keys by filename (without `.toml`).
- Subdirectories (e.g. `platforms/`) map to nested dicts; each file becomes an entry keyed by platform identifier.

### Path resolution

Path values in merged configuration MUST resolve to absolute paths, including legacy aliases (the `tide` and `core` path groups map onto their modern equivalents).

## Relationships

- [workspace.md](workspace.md) — default paths from `paths.toml`
- [deployment.md](deployment.md) — `deployment.toml` semantics
- [specs/vocabularies/format.md](vocabularies/format.md) — vocabulary extension via `schema.toml`
- [platforms.md](platforms.md) — platform TOML under `platforms/`

## Defaults & overrides

Package defaults ship in the PyPI wheel (`get_data_root()`). Clients deep-merge overrides from `.opentide/configurations/`. Scalar values replace; nested tables merge recursively.

## Examples

Platform override pattern: `.opentide/configurations/platforms/sentinel.toml` with `[platform] enabled = true`.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `core/files.py` |
