---
spec: metadata
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Metadata

## Summary

Shared metadata block present on all Tide objects (threat, objective, rule). Provides identity, schema routing, versioning, provenance, and classification.

## Requirements

- Every core object MUST include a `metadata` object.
- `metadata.schema` MUST be a registered schema identifier; unknown identifiers are invalid.
- `metadata.uuid` MUST be a UUIDv4 string.
- `metadata.version` MUST be present (semver string or integer).
- `metadata.created` and `metadata.modified` MUST be ISO 8601 date or datetime strings (coerced to string on load).
- `metadata.tlp` MUST be a valid Traffic Light Protocol value from the `tlp` vocabulary.
- `metadata.author`, `metadata.contributors`, and `metadata.organisation` MAY be omitted.

## Definition

### `metadata` (ObjectMetadata)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uuid` | string (UUIDv4) | yes | Globally unique object identifier |
| `schema` | string | yes | Schema identifier, e.g. `rule::1.0` (alias: `schema_id` in Pydantic) |
| `version` | string \| integer | yes | Business version of this instance |
| `created` | string | yes | Creation date |
| `modified` | string | yes | Last modification date |
| `tlp` | string | yes | Traffic Light Protocol classification |
| `author` | string | no | Primary author |
| `contributors` | list[string] | no | Additional contributors |
| `organisation` | Organisation | no | Owning organisation |

### `organisation` (Organisation)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uuid` | string | yes | Organisation UUID |
| `name` | string | yes | Organisation display name |

### `references` (ObjectReferences)

Optional on threat, objective, and rule objects.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public` | map[integer, string] | no | Public reference IDs to URLs (YAML int keys coerced on load) |
| `internal` | map[string, string] | no | Internal reference keys to URLs |
| `reports` | list[string] | no | Report links |

## Relationships

- [versioning.md](versioning.md) — `metadata.schema` and `metadata.version` semantics
- [specs/vocabularies/catalog.md](vocabularies/catalog.md) — `tlp` vocabulary
- Object specs — embed `metadata` as required top-level block

## Defaults & overrides

No client overrides for metadata structure. Template generation MAY pre-fill dates and placeholder UUIDs via opentide `generate templates`.

## Examples

- Valid metadata on a rule: [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml)
- Invalid UUID: [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `models/metadata.py` |
