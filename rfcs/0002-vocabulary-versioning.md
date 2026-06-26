# RFC 0002: Vocabulary identifier versioning and schema pins

- **RFC:** 0002
- **Title:** Vocabulary identifier versioning and schema pins
- **Status:** proposed
- **Created:** 2026-06-26

## Summary

This RFC introduces versioned vocabulary identifiers in the form `field::major.minor`, adds schema-level vocabulary pinning through `tide.vocab`, and defines bump rules when vocabulary entries change. The goal is to let object schema revisions pin deterministic enum sets while keeping additive vocabulary evolution possible without forcing breaking schema migration.

## Motivation

Vocabulary files in `vocabularies/*.vocab.toml` are canonical today but effectively unversioned. As a result, object schemas can change behavior when enum sets drift over time, even if `metadata.schema` remains unchanged (for example, `threat::1.0` may validate differently depending on when validation runs).

OpenTide already version-controls object schemas (`metadata.schema` like `rule::1.0`). Vocabulary resolution should provide equivalent determinism:

- Schema `X::M.N` resolves against explicit vocabulary revisions.
- Additive vocabulary changes can roll out through minor revisions.
- Removal/rename changes are treated as breaking and require coordinated schema planning.

## Detailed design

### Identifier format

- A vocabulary identifier MUST use `{field}::{major}.{minor}`.
- `field` MUST equal the constrained field path (existing `field` semantics remain).
- `major` and `minor` MUST be non-negative integers.
- The unversioned identifier (`field` only) MAY remain as an authoring convenience alias during migration, but implementations MUST normalize to an explicit version for validation and schema generation.

Examples:

- `tlp::1.0`
- `detection.methodology::2.3`
- `chaining_relations::1.1`

### Version source and canonical data

- Canonical vocabulary content remains in `vocabularies/*.vocab.toml`.
- Each canonical vocabulary file will carry an explicit version value (follow-up in SPEC-V3/SPEC-V5).
- Implementations MUST treat `(field, version)` as the lookup key, not filename alone.

> **Note (2026-06-26):** File-level vocabulary `version` proposed here and in [PR #2](https://github.com/OpenTideHQ/specifications/pull/2) is **superseded** by per-key lifecycle metadata in [RFC 0003](0003-per-key-vocabulary-versioning.md). Identifier format, schema pins, and bump semantics in this RFC remain directionally valid; only the version *granularity* moves from file to `[[keys]]` entries.

### Schema pinning (`tide.vocab`)

- `tide.vocab` SHOULD accept explicit versioned identifiers (string or list entries).
- When `tide.vocab` is `true`, default field-name inference MAY continue, but generation/validation MUST resolve it to a concrete version pinned by the active object schema revision.
- Object schema revisions (`metadata.schema`, e.g. `threat::1.0`) SHOULD maintain a mapping of field -> vocabulary identifier(s) so validation is deterministic across time.

### Bump rules

Vocabulary version increments are defined by effective enum semantics for the constrained field:

| Change type | Vocabulary bump | Schema consideration |
|-------------|-----------------|----------------------|
| Add new key (backward-compatible expansion) | **minor** (`1.0 -> 1.1`) | Existing schema revision MAY remain pinned to older minor; opting into new values is explicit |
| Remove key | **major** (`1.x -> 2.0`) | Any schema revision permitting removed value requires migration/deprecation plan |
| Rename key (effective remove + add) | **major** (`1.x -> 2.0`) | Treat as breaking for producers/validators; new schema revision likely required |
| Reassign key meaning incompatibly | **major** (`1.x -> 2.0`) | Treat as semantic break; schema notes and migration guidance required |
| Metadata-only clarifications (description/icon) | no bump or patch policy (deferred) | No schema change required unless validation semantics change |

Notes:

- This RFC does not introduce a patch segment in identifiers; if patch-level tracking is later needed, it can be specified separately.
- A major vocabulary bump does not automatically force an object schema major bump, but it MUST trigger explicit schema impact review and documented pin decisions.

### Required spec updates after RFC acceptance

The following documents should be updated as follow-up normative edits:

1. `specs/vocabularies/format.md`
   - Define versioned vocabulary identifier grammar: `field::major.minor`.
   - Add required top-level `version` semantics for vocabulary files.
   - Clarify bump policy table (add = minor; remove/rename = major).
   - Document compatibility/alias behavior for temporary unversioned references.

2. `specs/metaschema-keywords.md`
   - Expand `tide.vocab` definition to include version-pinned identifiers and lists.
   - Specify resolver behavior when `tide.vocab = true` (field inference + schema pin lookup).
   - Define failure behavior when a pinned vocabulary revision is unavailable.
   - Add examples showing object-schema pin tables and resolved enum output.

### Implementation sequencing (tracks)

- SPEC-V3: add vocabulary `version` to `schemas/vocabulary.schema.json` and validator checks.
- SPEC-V4: encode per-object-schema vocabulary pin sets in object specs/catalog docs.
- SPEC-V5: populate canonical vocabulary TOML files with initial explicit versions.

## Drawbacks

- Additional coordination overhead between vocabulary updates and object schema governance.
- Short-term migration complexity while unversioned references coexist with explicit pins.
- Tooling work is required across both `specifications` and `opentide` repositories.

## Alternatives

- **Keep vocabularies unversioned** — rejected; leads to non-deterministic validation across time.
- **Version only object schemas, not vocabularies** — rejected; cannot express enum evolution independently.
- **Encode versions in filenames only** — rejected for now; identifier-based pinning is clearer for metaschema and schema mapping.

## Unresolved questions

- Whether a patch segment is needed for non-semantic metadata edits.
- Where the schema-to-vocabulary pin table should be represented canonically (`specs/objects/*` only vs shared catalog index).
- Migration sunset policy for unversioned `tide.vocab` references.

## References

- [GOVERNANCE.md](../GOVERNANCE.md)
- [rfcs/0001-authority-model.md](0001-authority-model.md)
- [specs/vocabularies/format.md](../specs/vocabularies/format.md)
- [specs/metaschema-keywords.md](../specs/metaschema-keywords.md)
