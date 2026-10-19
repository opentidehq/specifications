---
spec: metadata
version: "1.2"
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
- `metadata.pap`, when present, MUST be a `pap` vocabulary `name` (`white`, `green`, `amber`, `red`).
- `metadata.author`, `metadata.contributors`, and `metadata.organisation` MAY be omitted.
- `metadata.reviewed`, when present, MUST be an ISO 8601 date or datetime string (coerced to string on load). A date-only value denotes 00:00:00Z on that date. The field is defined only for `metadata.schema: rule::1.1`. `threat::1.0`, `objective::1.0`, and `rule::1.0` MUST reject it.

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
| `pap` | string | no | Permissible Actions Protocol classification. Omitted means no PAP tag on share. |
| `author` | string | no | Primary author |
| `contributors` | list[string] | no | Additional contributors |
| `organisation` | Organisation | no | Owning organisation |
| `reviewed` | string | no | Last human review of a detection rule. Defined only for `rule::1.1`. Omitted means no recorded review. Staleness is defined in [rule-1.1.md](objects/rule-1.1.md#review-staleness). |

### `organisation` (Organisation)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `uuid` | string | yes | Organisation UUID. Sharing uses it as the default publishing organisation. |
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
- [specs/vocabularies/catalog.md](vocabularies/catalog.md) — `tlp` and `pap` vocabularies
- [sharing/misp-1.0.md](sharing/misp-1.0.md) — consumes `metadata.tlp`, optional `metadata.pap`, and `metadata.organisation.uuid` as the publishing organisation unless the `[[misp]]` block overrides it
- Object specs — embed `metadata` as required top-level block
- [objects/rule-1.1.md](objects/rule-1.1.md) — optional `metadata.reviewed` and the unreviewed-rule predicate

## Defaults & overrides

No client overrides for metadata structure. Template generation MAY pre-fill dates and placeholder UUIDs via opentide `generate templates`.

## Examples

```yaml
metadata:
  uuid: 00000000-0000-4000-8003-000000000001   # UUIDv4, unique across the repo
  schema: rule::1.0                             # registered schema identifier
  version: 1                                    # instance content version
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: clear                                    # from the `tlp` vocabulary
```

- Valid metadata on a rule: [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml)
- Invalid UUID: [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.2 | 2026-09-30 | Optional `metadata.reviewed` on `rule::1.1` only ([RFC 0008](../rfcs/0008-rule-reviewed-date.md)). |
| 1.1 | 2026-09-28 | Optional `metadata.pap` for sharing ([RFC 0005](../rfcs/0005-sharing-system.md)). Sharing uses `organisation.uuid` as the default publishing organisation. |
| 1.0 | 2026-06-25 | Initial spec from opentide `models/metadata.py` |
