---
spec: sharing-misp
version: "1.0"
schema_id: sharing::misp::1.0
status: normative
supersedes: null
---

# MISP connector

## Summary

`sharing::misp::1.0` publishes one Tide object as one MISP Event. Each MISP instance is one `[[misp]]` block in `sharing.toml`. The Event carries exactly one instance of the upstream `opentide` MISP object, and its `opentide-object` attribute holds the source document verbatim. Exposure is the block's `max_tlp` ceiling and the MISP distribution that the object's `metadata.tlp` permits. The connector does not filter fields out of the document.

This first revision keeps the block small: where to connect, what to select, and how high TLP may go. Distribution width, sharing groups, file export, and Event title decoration are not configurable in 1.0.

The pinned template is [schemas/misp/opentide.definition.json](../../schemas/misp/opentide.definition.json), copied from `MISP/misp-objects` `objects/opentide/definition.json`. Refresh direction is **upstream MISP → this repository**, the reverse of vocabulary sync. A refresh that changes the pinned relation set is a revision of this spec.

## Requirements

- Each MISP instance MUST be one `[[misp]]` entry in `sharing.toml`.
- A `[[misp]]` block MUST set `name`, `url`, and `api_key`. Every other key has a default.
- A key not listed in this spec MUST be rejected as a configuration error before any instance is contacted.
- The publishing organisation MUST be resolved from the object's `metadata.organisation.uuid` unless the block sets `organisation_uuid`, and MUST be verified against the API key's organisation before any write.
- The connector MUST emit exactly one `opentide` object per Event and zero Event-level attributes.
- The `opentide-object` value MUST be the verbatim UTF-8 YAML bytes of the source document. Comments, key order, indentation, and blank lines MUST be preserved. The connector MUST NOT re-serialise, encode, truncate, split, or wrap that body.
- No configuration value, API key, authorization header, or `${ENV_VAR}` substitution result MAY be injected into the document, object, envelope, tag set, share report, share state, or CLI output.
- The connector MUST NOT create, modify, enable, delete, or upload a galaxy or cluster.
- `pull` is not supported.

## Definition

### Capability

| Capability | MISP 1.0 |
|------------|----------|
| Integration key | `misp` (`[[misp]]`) |
| `schema` | `sharing::misp::1.0` |
| `push` | yes |
| `preview` | yes |
| `status` | yes (local state; MAY view the remote) |
| `retract` | yes (unpublish; optional delete) |
| `pull` | no |

### `[[misp]]` block

```toml
[[misp]]
name = "misp-internal"
enabled = true
url = "https://misp.internal.example.org"
api_key = "${MISP_INTERNAL_API_KEY}"
max_tlp = "amber"
object_types = ["threat", "objective", "rule"]
rule_statuses = ["PRODUCTION"]

[[misp]]
name = "misp-isac"
enabled = true
url = "https://misp.isac.example.net"
api_key = "${MISP_ISAC_API_KEY}"
max_tlp = "green"
object_types = ["rule"]
publish = true
organisation_uuid = "00000000-0000-4000-8aaa-000000000002"
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `name` | string | yes | — | Block identifier ([sharing.md](../sharing.md)) |
| `enabled` | bool | no | `false` | |
| `url` | string (URL) | yes | — | Instance origin. Trailing slash ignored. |
| `api_key` | string | yes | — | MUST be a `${ENV_VAR}` reference in committed config. An unset or empty variable excludes the block before any request. A literal key SHOULD raise a validation warning and MUST NOT be printed. |
| `max_tlp` | string | no | `amber` | Highest `metadata.tlp` this block shares |
| `object_types` | list[string] | no | all three | |
| `rule_statuses` | list[string] | no | `["PRODUCTION"]` | |
| `organisation_uuid` | string (UUID) | no | from the object | Override for the publishing organisation. Canonical 36-character UUID. |
| `publish` | bool | no | `false` | Call publish after each create or update |
| `verify_ssl` | bool | no | `true` | |

Requests use an implementation default timeout, which SHOULD be 30 seconds.

#### Not configurable in 1.0

These keys are rejected like any other unknown key. They name behaviour this revision fixes rather than exposes; a later revision MAY add them.

| Key | Fixed 1.0 behaviour |
|-----|---------------------|
| `distribution`, `sharing_group_id`, `sharing_group_uuid` | Distribution derived from `metadata.tlp` (below). No sharing groups. |
| `mode`, `directory` | API only. `preview` is the offline path. |
| `analysis` | `completed` |
| `info_prefix` | Event `info` is the object `name` |
| `extra_tags` | Closed tag set |
| `timeout_seconds`, `client_cert`, `client_key` | Implementation default timeout; no mutual TLS |
| `require_validation` | Always validates ([sharing.md](../sharing.md)) |
| `connector`, `schema`, `identifier` | The array key is the connector; `name` is the identifier |
| `event_mode`, `threat_level_source`, `threat_level_id`, `verify_event_org`, `tag_namespace`, `include_*` | One Event per object; derived threat level; organisation in the lookup key; no tag namespace; no payload filtering |

### Publishing organisation

The publishing organisation is half of the Event lookup key. opentide already records an owning organisation on each object as `metadata.organisation.uuid` ([metadata.md](../metadata.md)), so the connector consumes that value first:

| Order | Source | When used |
|-------|--------|-----------|
| 1 | `[[misp]].organisation_uuid` | Set on the block. Overrides every object for that block. |
| 2 | Object `metadata.organisation.uuid` | Block value absent |
| 3 | Organisation of the authenticated API key | Neither is set. The report carries note `organisation_from_api_key`. |

MISP records the API key's organisation as the Event creator, whatever the payload says. Before any create or update, the connector MUST read that organisation with `GET /users/view/me` and compare it case-insensitively to the resolved value:

| Result | Outcome |
|--------|---------|
| Match | Continue |
| Mismatch, value from the block | Fail the block with `organisation_uuid_mismatch`; write nothing to it |
| Mismatch, value from the object | Fail that object with `organisation_uuid_mismatch`; other objects continue |
| Read failure | Fail the block with `organisation_uuid_unverified` |

A mismatch is never written through, because an Event created under another organisation would not match the lookup key on the next run and would duplicate. An object whose `metadata.organisation` belongs to someone else can be republished by setting `organisation_uuid` on the block to the publisher's own organisation.

`preview` makes no request. It resolves the organisation from steps 1 and 2, and notes `organisation_unverified` on every record.

### Distribution

1.0 derives distribution from the object's TLP only:

| Object `metadata.tlp` | MISP `distribution` |
|-----------------------|---------------------|
| `clear` | `1` (this community) |
| `green` | `1` (this community) |
| `amber` | `0` (your organisation) |
| `amber+strict` | `0` (your organisation) |
| `red` | `0` (your organisation), only when `max_tlp = "red"` and `--allow-tlp-red` is passed |

`sharing_group_id` is always `0`. Wider distribution (connected or all communities) and sharing groups are out of scope for 1.0.

### HTTP subset

Minimum server: a MISP release that ships `opentide` template version 5 (`uuid` `892fd46a-f69e-455c-8c4f-843a4b8f4295`).

Every request MUST send the API key as `Authorization: <key>`. The key MUST NOT appear in query strings. On `401` or `403`, the block MUST fail with authentication failed and MUST NOT dump response bodies.

| Operation | Request | Use |
|-----------|---------|-----|
| Server identity | `GET /servers/getVersion` | Connectivity probe |
| Authenticated organisation | `GET /users/view/me` | Organisation check. Compare `Organisation.uuid` case-insensitively. |
| Find events | `POST /events/restSearch` | Body includes `"returnFormat": "json"`, `"object_name": "opentide"`, `"value": "<metadata.uuid>"`, and a page size. Page with `page` and `limit` until a page returns fewer than `limit` hits. |
| View event | `GET /events/view/<uuid-or-id>` | Read a candidate, including `Orgc` and objects |
| Add event | `POST /events/add` | Create, including the nested object and tags |
| Edit event | `POST /events/edit/<id>` | Update after lookup |
| Publish | `POST /events/publish/<id>` | When `publish` resolves true |
| Unpublish | `POST /events/unpublish/<id>` | Retract default |
| Delete event | `DELETE /events/<id>` | Retract `--delete` |
| Galaxy clusters | Read-only galaxy cluster search | Resolve `threat-actor` and `mitre-attack-pattern` |

`restSearch` is not assumed to constrain creator organisation and object attribute in one predicate. The connector MUST keep a hit only when both halves of the lookup key match, and MUST exclude every other hit from the match count. A foreign organisation's Event is an informational note, not a match and not an error.

PyMISP is the recommended opentide library. The spec is HTTP/JSON. Any client that speaks this subset conforms.

A galaxy lookup that fails for transport, timeout, or authorization fails the affected object with `galaxy_lookup_failed`. It MUST NOT degrade into a guessed value.

### Tags

Emission order: TLP, PAP, `threat-actor` clusters, then `mitre-attack-pattern` clusters. Ascending code point order within each group. Each distinct tag string at most once.

| Source | Cardinality | Value |
|--------|-------------|-------|
| `tlp` vocabulary `misp` for `metadata.tlp` | exactly 1 | copied character-for-character |
| `pap` vocabulary `misp` for `metadata.pap` | 0 or 1 | copied character-for-character |
| `threat-actor` galaxy cluster | 0..n | `misp-galaxy:threat-actor="<cluster value as returned>"` |
| `mitre-attack-pattern` galaxy cluster | 0..n | `misp-galaxy:mitre-attack-pattern="<cluster value as returned>"` |

A missing or unmapped `metadata.tlp` fails the object with `unmapped_tlp`. An unmapped `metadata.pap` fails it with `unmapped_pap`. An absent `metadata.pap` emits no PAP tag.

Cluster values MUST be the `value` string the instance returns. The connector MUST NOT derive a cluster value from an OpenTide vocabulary field.

| Identifier source | Galaxy | First key that yields exactly one match |
|-------------------|--------|------------------------------------------|
| `threat.att&ck[]`, objective `attack[]`, rule `techniques[]` | `mitre-attack-pattern` | `meta.external_id` contains the technique id, case-insensitive after trimming |
| `threat.actors[].name` scope `att&ck::` | `threat-actor` | (a) `meta.external_id` contains the id; else (b) `meta.refs` URL final path segment equals the id; else (c) `meta.synonyms` contains the id |
| `threat.actors[].name` scope `misp::` | `threat-actor` | cluster `uuid` equals the scoped identifier, canonical form, case-insensitive |

| Condition | Behaviour |
|-----------|-----------|
| Actor name has no scope, or a scope other than `att&ck::` or `misp::` | Omit the tag, note `actor_unscoped`. Bare strings MUST NOT be coerced. |
| No cluster matches | Omit the tag, note `cluster_not_found`, emit the Event |
| More than one cluster matches | Omit the tag, note `cluster_ambiguous` listing every matched cluster UUID |
| Lookup fails for transport, timeout, or authorization | Fail the object with `galaxy_lookup_failed`; leave the remote Event unmodified |

A sub-technique emits its own cluster tag only. The parent is emitted only when the object lists the parent identifier separately.

`preview` makes no lookup. It omits cluster tags with note `cluster_not_resolved` and still emits the Event.

Golden fixtures MUST assert galaxy tag *shape* (`misp-galaxy:<galaxy>="<non-empty>"`) rather than one instance's cluster value. Cluster strings are not stable across galaxy versions.

### Event envelope

The connector sets exactly these Event fields:

| Field | Source |
|-------|--------|
| `info` | Object top-level `name`, truncated to 255 characters |
| `date` | UTC calendar date of `metadata.created` (`YYYY-MM-DD`), on create and update. Never the run date. |
| `distribution` | The TLP-derived value above |
| `sharing_group_id` | `0` |
| `threat_level_id` | The table below |
| `analysis` | `2` (completed) |
| `published` | `false` on every create and update payload. Publishing is a separate call. |

`uuid`, `timestamp`, `orgc_id`, `org_id`, `Orgc`, `Org`, `event_creator_email`, `EventReport`, and `CryptographicKey` are server-owned and MUST NOT be set on create. The Event `uuid` is assigned by the instance and is sent only to address an existing Event on update.

An object whose top-level `name` is absent or empty after trimming, or whose `metadata.created` is absent or not a valid `YYYY-MM-DD` date, is `failed` with the field named. No remote Event is created or modified.

`threat_level_id` (`1` High, `2` Medium, `3` Low, `4` Undefined) is derived, never configured. Threat uses top-level `criticality`. Rule uses top-level `severity`. Objective has no source and is `4`.

| OpenTide scale | Source values | `threat_level_id` |
|----------------|---------------|-------------------|
| `criticality::1.0` | `Emergency`, `Severe`, `High` | `1` |
| `criticality::1.0` | `Medium` | `2` |
| `criticality::1.0` | `Low`, `Baseline - Minor`, `Baseline - Negligible` | `3` |
| `severity::1.0` | `National cyber emergency`, `Highly significant incident`, `Significant incident` | `1` |
| `severity::1.0` | `Substantial incident`, `Moderate incident` | `2` |
| `severity::1.0` | `Localised incident` | `3` |
| `alert_severity::1.0` | `Critical`, `High` | `1` |
| `alert_severity::1.0` | `Medium` | `2` |
| `alert_severity::1.0` | `Low`, `Informational` | `3` |
| — | every objective; absent or unmatched source | `4` |

Match the full vocabulary `name`, case-sensitive first, then case-insensitive equality. Never substring. A rule `severity` is matched against both `severity::1.0` and `alert_severity::1.0` rows. `Low` and `Medium` resolve identically on every scale that contains them.

### `opentide` object

Pinned template identity:

| Property | Value |
|----------|-------|
| Name | `opentide` |
| `uuid` | `892fd46a-f69e-455c-8c4f-843a4b8f4295` |
| `version` | `5` |
| `meta-category` | `misc` |
| Required relations | `name`, `opentide-object`, `opentide-type`, `uuid`, `version`, `schema` |
| Optional repeatable relations | `opentide-relation`, `misp-event-relation` |

`opentide-type` MUST be one of the template `values_list` entries: `threat`, `objective`, `rule`. Those strings are the OpenTide family names.

| Relation | Cardinality | Source | `disable_correlation` |
|----------|-------------|--------|------------------------|
| `name` | exactly 1 | Object top-level `name`, verbatim | `false` |
| `uuid` | exactly 1 | `metadata.uuid`, verbatim. Never the Event UUID | `false` |
| `version` | exactly 1 | `metadata.version` as a decimal digit string, no leading zeroes. The template `sane_default` of `1` MUST NOT replace a real value | `true` |
| `opentide-type` | exactly 1 | Family name: `threat`, `objective`, or `rule` | `true` |
| `schema` | exactly 1 | `metadata.schema`, verbatim (`rule::1.0` and siblings) | `true` |
| `opentide-object` | exactly 1 | Verbatim source document | `false` |
| `opentide-relation` | 0..n | Parent object UUIDs below | `false` |
| `misp-event-relation` | 0 | Not emitted. MISP Event UUIDs are server-assigned and are not OpenTide identity | — |

Every emitted attribute MUST set `type` to `text`, `category` to `Other`, `to_ids` to `false`, and `distribution` to `5` (inherit the Event). The object itself MUST set `distribution` to `5`, so a stored object cannot outreach its Event.

`disable_correlation` MUST follow the table. Correlation of `uuid` and `opentide-relation` text MAY surface related events on an instance that correlates `text`. This spec does not require that UI behaviour. The authoritative link is the attribute value.

A missing template fails the object with `template_missing`. A missing required relation on the instance template fails it with `template_relation_missing`, naming each absent relation. A template version other than `5`, while all six required relations exist and `opentide-type` accepts the family name, is an informational note. The connector still emits the pinned relation set.

Updates touch the seven envelope fields, the tag set, and the one `opentide` object. Remote objects or Event-level attributes the connector did not emit stay, with an informational note. The remote Event `uuid` and creator organisation are never rewritten.

#### Relations

`opentide-relation` points from child to parent:

| Family | Source | Emitted |
|--------|--------|---------|
| `threat` | — | zero relations |
| `objective` | `objective.threats[]` | one per distinct UUID |
| `rule` | top-level `detection_model` | zero or one |

Values are 36-character lowercase canonical UUIDs of Tide objects, never MISP Event or object UUIDs, at most one attribute per distinct UUID, ordered ascending. A non-canonical UUID fails the object. An absent, null, or empty source emits zero relations. A relation UUID whose object was not shared to that block is still emitted, with an informational note.

No `extends_uuid` is set and no MISP event extension is created.

### Identity

```
lookup key = (Event.Orgc.uuid == resolved publishing organisation)
           ∧ (opentide object uuid attribute == Tide metadata.uuid)
```

`Orgc.uuid` is compared as a canonical UUID, case-insensitively. The `uuid` attribute is compared as an exact case-sensitive string. An Event satisfying only one half is not a match.

| Lookup result | Stored content hash | Outcome | Action |
|---------------|---------------------|---------|--------|
| No match | any | `created` | Create without an Event `uuid`; store the UUID the instance returns |
| Exactly one | absent or different | `updated` | Update; store the new hash |
| Exactly one | equal | `unchanged` | No create, update, or publish request |
| More than one | any | `failed` / `ambiguous_remote_event` | Report every matched Event UUID; write nothing |
| Object UUID matches, organisation differs | any | not a match | Leave it untouched; informational note |
| Transport or auth failure | any | `failed` / `remote_lookup_failed` | Leave state unchanged |
| Update rejected | any | `failed` / `remote_update_rejected` | Never fall back to create |

The content hash covers the emitted object document only, computed locally before any request.

If the instance rejects `opentide-object` for length, fail that object with `attribute_too_large` and write nothing. The connector MUST NOT split the document across attributes.

### Payload

The emitted document is one YAML document whose root is a mapping. It passes `uuid-format` and `schema` checks against its own `metadata.schema` whenever the source object does.

Nothing in the document is removed for any block, TLP value, or flag. Withholding content is done by raising `metadata.tlp`, lowering the block's `max_tlp`, or leaving the object out of the block's selection.

`preview` and `push` produce a byte-identical `opentide-object` value and the same outcome class for the same object and block, apart from the notes that only a live instance can settle (organisation, clusters).

### Retract

| Mode | MISP action |
|------|-------------|
| default | `unpublish` if published; leave the event |
| `--delete` | delete the event. Implementations SHOULD require `--yes` or an equivalent confirm flag. The share-state row MUST be dropped. |

Retract operates on records present in state or on the remote, not on objects that were never pushed.

### Preflight reasons

These are preflight (exit `1`) for this connector, before the exit rules in [sharing.md](../sharing.md): an unknown key in a `[[misp]]` block, a missing `name`, `url`, or `api_key`, an unset `api_key` variable, a malformed `organisation_uuid`, and `organisation_uuid_mismatch` on every selected block.

### Validation check `sharing-config`

`opentide validate` SHOULD offer `sharing-config` (off by default, on for `opentide share push`). It checks `sharing.toml` and every `[[misp]]` block in the merged result:

| Condition | Checker code |
|-----------|--------------|
| `name`, `url`, or `api_key` missing | `missing_field` |
| `name` repeated in one layer, or used by two integrations | `duplicate_name` |
| `name` outside the allowed characters | `name_invalid` |
| A key not defined by this spec, or a top-level key that is not an array of tables | `unknown_key` |
| `max_tlp` not a `tlp` name | `max_tlp_unknown` |
| `organisation_uuid` not a canonical UUID | `organisation_uuid_invalid` |
| `object_types` entry not a family | `object_type_unknown` |
| A `sharing/` configuration directory exists | `sharing_directory` |

## Relationships

- [sharing.md](../sharing.md) — `sharing.toml`, CLI, exit statuses, share state
- [metadata.md](../metadata.md) — `metadata.tlp`, optional `metadata.pap`, `metadata.organisation.uuid`
- [vocabularies/tlp.vocab.toml](../../vocabularies/tlp.vocab.toml), [vocabularies/pap.vocab.toml](../../vocabularies/pap.vocab.toml) — tag strings
- [schemas/misp/opentide.definition.json](../../schemas/misp/opentide.definition.json) — pinned template version 5

## Defaults & overrides

A block needs `name`, `url`, and `api_key`. It ships disabled, shares `amber` and below, selects all three families and `PRODUCTION` rules, takes its organisation from each object, and does not publish.

## Examples

- Two instances: [fixtures/sharing/valid/sharing.toml](../../fixtures/sharing/valid/sharing.toml)
- Golden Events for the committed object fixtures: [rule](../../fixtures/sharing/valid/rule-event.json), [objective](../../fixtures/sharing/valid/objective-event.json), [threat](../../fixtures/sharing/valid/threat-event.json)
- Invalid key not configurable in 1.0: [fixtures/sharing/invalid/unknown-distribution.toml](../../fixtures/sharing/invalid/unknown-distribution.toml). Every invalid fixture and its checker code is listed in [validation.md](../validation.md).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-28 | Initial connector spec from accepted [RFC 0005](../../rfcs/0005-sharing-system.md). Pins upstream `opentide` template version 5. Minimal `[[misp]]` block; organisation from `metadata.organisation.uuid`, overridable per block; distribution derived from TLP. |
