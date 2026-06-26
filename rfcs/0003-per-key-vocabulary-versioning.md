# RFC 0003: Per-key vocabulary versioning and schema pins

- **RFC:** 0003
- **Title:** Per-key vocabulary versioning and schema pins
- **Status:** proposed
- **Created:** 2026-06-26
- **Supersedes:** file-level vocabulary `version` semantics proposed in [RFC 0002](0002-vocabulary-versioning.md) and [PR #2](https://github.com/OpenTideHQ/specifications/pull/2)

## Summary

This RFC replaces file-level vocabulary versioning with **per-key lifecycle metadata** on each `[[keys]]` entry. Vocabulary contract identifiers (`field::major.minor`) denote resolved enum sets derived from key filters, not whole-file stamps. Object schema revisions pin explicit vocabulary contracts via per-family TOML manifests under `schemas/pins/`.

## Motivation

[RFC 0002](0002-vocabulary-versioning.md) introduces versioned vocabulary identifiers and schema pins — the right direction — but its § Version source still assumes each vocabulary **file** carries a top-level `version`. [PR #2](https://github.com/OpenTideHQ/specifications/pull/2) implements that file-level approach.

File-level versioning cannot answer: *what enum did `threat::1.0` allow for `killchain` when it was authored?* Adding a key to `killchain.vocab.toml` would bump the whole file, yet existing schema revisions must keep their original allowed values.

Per-key metadata decouples three layers:

| Layer | What it versions | Example |
|-------|------------------|---------|
| **Vocabulary keys** | Individual enum entry lifecycle | `Reconnaissance` at `version = "1.0"`; `NewStage` at `version = "1.1"` |
| **Vocabulary contract** | Resolved enum set for a field at `field::M.m` | `killchain::1.0` = keys with `version <= 1.0` and not removed |
| **Object schema** | Which vocabulary contracts a revision consumes | `threat::2.1` pins `killchain::1.1`, `severity::1.0`, … |

## Detailed design

### Per-key lifecycle (not file version)

Canonical vocabulary content remains in `vocabularies/*.vocab.toml`. Files MUST declare `name` and `field` only — **no top-level `version`**.

Each `[[keys]]` entry MUST include:

| Property | Required | Description |
|----------|----------|-------------|
| `name` / `id` | yes (per keying mode) | Entry identity |
| `version` | yes | Contract line when this key enters the vocabulary (`major.minor`) |
| `removed` | no | Contract line when this key leaves (major bump) |

Example:

```toml
name = "Unified Kill Chain"
field = "killchain"

[[keys]]
name = "Reconnaissance"
version = "1.0"

[[keys]]
name = "NewStage"
version = "1.1"
# removed = "2.0"  # optional; excludes key from pins below 2.0
```

#### Bump rules (per key)

| Change type | Key metadata | Contract bump |
|-------------|--------------|---------------|
| Add new key | set `version` to introducing minor line | new minor contract available |
| Remove key | set `removed` at next major | major contract line |
| Rename key | `removed` on old + new key at major | major |
| Description/icon-only edit | no change | none |

#### Resolver

`resolve(field, pin)` where `pin` is `field::M.m`:

- Include key iff `version <= pin` (cumulative minor semantics) AND (`removed` absent OR `removed > pin`).

Identifier form stays `killchain::1.1` (field + contract revision), but contract revision is **derived from key sets**, not a file stamp.

### Schema pin manifests

Pin tables live in **one TOML file per object family**, with a **section per schema revision**:

- `schemas/pins/threat.toml`
- `schemas/pins/objective.toml`
- `schemas/pins/rule.toml`

```toml
# schemas/pins/threat.toml

["threat::1.0"]
"metadata.tlp" = "tlp::1.0"
"criticality" = "criticality::1.0"
"threat.severity" = "severity::1.0"
"threat.killchain" = "killchain::1.0"
"threat.att&ck" = "att&ck::1.0"

["threat::2.1"]
"metadata.tlp" = "tlp::1.0"
"criticality" = "criticality::1.0"
"threat.severity" = "severity::1.0"
"threat.killchain" = "killchain::1.1"   # only pin that moved
"threat.att&ck" = "att&ck::1.0"
```

**Conventions:**

- Section header = full `metadata.schema` identifier (quoted because of `::`).
- Keys = dot-paths to vocab-constrained fields (same paths used in metaschema / validation walk).
- Values = versioned vocabulary contract identifiers (`field::M.m`).
- A section MAY declare `extends = "threat::1.0"` and list overrides only; if omitted, every pin is explicit.

Object spec markdown files SHOULD link to the pin file anchor (e.g. `schemas/pins/threat.toml#threat::1.0`) as the machine-readable source of truth.

### Versioned `tide.vocab`

| `tide.vocab` value | Behavior |
|--------------------|----------|
| `"severity"` (legacy) | WARN + resolve via active schema pin for field path |
| `"severity::1.0"` | Explicit pin (authoring) |
| `true` | Infer field name → lookup schema pin |
| `["att&ck::1.0", "custom"]` | Union (existing list semantics + versions) |

When building JSON Schema for `threat::2.1`, unresolved `tide.vocab: true` on `threat.killchain` MUST resolve to pin table entry `killchain::1.1`, not latest keys.

### Worked example

1. `killchain.vocab.toml` gains `NewStage` with `version = "1.1"`.
2. `threat::1.0` pin stays `killchain::1.0` → enum excludes `NewStage`.
3. New spec `threat-2.1.md` + new `["threat::2.1"]` section in `schemas/pins/threat.toml` sets `"threat.killchain" = "killchain::1.1"`.
4. Object with `metadata.schema: threat::1.0` using `NewStage` → **validation error**.
5. Object with `metadata.schema: threat::2.1` using `NewStage` → **valid**.
6. `opentide generate schemas` emits two JSON Schemas with different `killchain` enums.

### Migration

One-time backfill: `version = "1.0"` on all existing `[[keys]]` entries. All current object schemas pin at `::1.0`. Behavior is unchanged until keys or pins move forward.

### Required spec updates

1. `schemas/vocabulary.schema.json` — require `version` on each key; optional `removed`; no top-level file `version`.
2. `specs/vocabularies/format.md` — per-key lifecycle and bump rules.
3. `specs/metaschema-keywords.md` — versioned `tide.vocab` and pin resolution.
4. `schemas/pins/{threat,objective,rule}.toml` — initial `::1.0` pin sections.
5. `scripts/validate.py` — per-key version checks and pin file parsing.

## Drawbacks

- More metadata per key than a single file stamp.
- Pin manifests must be kept in sync with object schema revisions.
- Tooling work spans `specifications` and `opentide`.

## Alternatives

- **File-level `version` (PR #2)** — rejected; cannot express per-schema enum determinism.
- **Immutable vocabulary snapshots per schema** — rejected; duplicates canonical TOML and complicates STIX-driven vocabs.

## Unresolved questions

- Contract bump policy for bulk STIX imports (`att&ck`, `actors`).
- Sunset policy for unversioned `tide.vocab` references.
- Whether pin sections should support `extends` in v1 or require explicit tables.

## References

- [RFC 0002](0002-vocabulary-versioning.md) — identifier format and schema pins (file-level version superseded by this RFC)
- [specs/vocabularies/format.md](../specs/vocabularies/format.md)
- [specs/metaschema-keywords.md](../specs/metaschema-keywords.md)
- [PR #2](https://github.com/OpenTideHQ/specifications/pull/2) — superseded approach
