# RFC 0001: Authority model and change process

- **RFC:** 0001
- **Title:** Authority model and change process
- **Status:** accepted
- **Created:** 2026-06-25

## Summary

This RFC establishes the normative authority chain for OpenTide: markdown specs in the `specifications` repository are canonical; opentide Pydantic models implement them; JSON Schema is a generated artifact for IDE validation. It also defines the Issue → RFC → spec → implementation change process.

## Motivation

OpenTide previously mixed architecture docs, Pydantic models, and generated JSON Schema without a single normative source. Authors, agents, and implementers need a clear precedence order and a lightweight governance path for evolving object schemas, vocabularies, and workspace conventions.

## Detailed design

### Authority chain

```
specifications/specs/*.md          (normative prose + field tables)
specifications/vocabularies/*.toml (canonical enum data)
        ↓ implements
opentide Pydantic models + vocabulary bundle
        ↓ generates
.opentide/schemas/*.schema.json    (artifact — not authoritative)
```

| Layer | Role | May authors edit directly? |
|-------|------|----------------------------|
| Spec markdown | Defines requirements and field semantics | Yes (via RFC) |
| Vocabulary TOML | Canonical allowed values | Yes (via RFC) |
| Pydantic models | Runtime validation implementation | No — opentide PR after spec |
| JSON Schema | IDE/router validation | No — `opentide generate schemas` |

### Two version fields

Every Tide object carries:

| Field | Example | Meaning |
|-------|---------|---------|
| `metadata.schema` | `rule::1.0` | Structural schema revision — selects Pydantic model and JSON Schema artifact |
| `metadata.version` | `1.2.0` | Business semver for instance content — git is authoritative history |

`metadata.version` MUST NOT be used to select a JSON Schema file.

### Schema identifier conventions

| Layer | Format | Example |
|-------|--------|---------|
| Schema identifier | `{family}::{major}.{minor}` | `rule::1.0` |
| Spec file | `specs/objects/{family}-{major}.{minor}.md` | `rule-1.0.md` |
| Schema artifact | `.opentide/schemas/{family}.{major}.{minor}.schema.json` | `rule.1.0.schema.json` |
| Template artifact | `.opentide/templates/{family}.{major}.{minor}.template.yaml` | `rule.1.0.template.yaml` |
| IDE router | `.opentide/schemas/opentide.schema.json` | routes by `metadata.schema` |

### Per-spec versioning (no framework version)

- There is no `specifications v1.0`.
- Each spec file has independent `version:` frontmatter.
- Breaking object changes create a new file (`rule-1.1.md`); the prior file remains with `status: deprecated`.

### Change process

1. **Issue** — `spec-change.yml` template captures problem, affected specs, change type, acceptance criteria.
2. **RFC** — Non-trivial or breaking work gets `rfcs/NNNN-*.md` (use `publish-rfc` skill).
3. **Spec merge** — Update `specs/`, `fixtures/`, `SPECS.md`, `CHANGELOG.md`.
4. **Implementation** — Separate opentide PR aligns models, generation, and tests.
5. **Website** (future) — `website` repo rebuilds from spec markdown at build time; out of scope for `specifications`.

### Multi-version coexistence

When `rule::1.1` ships:

1. New Pydantic model with `__schema_identifier__ = "rule::1.1"`.
2. Schema registry registers both `rule::1.0` and `rule::1.1`.
3. Migration chain `rule::1.0` → `rule::1.1` (opentide concern).
4. `opentide generate schemas` emits both artifacts; router adds a branch per identifier.
5. Objects opt in via `metadata.schema`; older objects remain on `rule::1.0` until migrated.

### Vocabulary authority

- Canonical `.vocab.toml` files live in `specifications/vocabularies/`.
- opentide copies at build to `data/vocabulary/`.
- Clients MUST NOT override vocabulary files; extensions use `schema.toml` `[[vocabulary.*]]` only.

### CI scope (specifications repo)

- Validate vocabulary TOML against `schemas/vocabulary.schema.json`
- Verify fixture paths referenced in specs exist
- Breaking PRs MUST reference an accepted RFC
- No site build, no JSON Schema generation in this repo

## Drawbacks

- Dual-repo coordination adds latency between spec acceptance and implementation.
- Field tables in specs must be kept in sync with Pydantic models manually until tooling exists.

## Alternatives

- **JSON Schema as source of truth** — Rejected: poor authoring ergonomics, hard to diff intent.
- **Pydantic as source of truth** — Rejected: couples normative definitions to Python implementation.
- **Single monorepo** — Deferred: separate `specifications` enables agent-friendly, language-neutral specs.

## Unresolved questions

- Automated drift detection between spec field tables and Pydantic models
- Bulk migrate CLI (`opentide migrate objects`) — deferred in opentide

## References

- [GOVERNANCE.md](../GOVERNANCE.md)
- [AGENTS.md](../AGENTS.md)
- opentide `docs/architecture/SCHEMA_REVISION.md` (bootstrap source)
