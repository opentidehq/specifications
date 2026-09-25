---
spec: sharing-misp
version: "1.0"
schema_id: sharing::misp::1.0
status: normative
supersedes: null
---

# MISP connector

## Summary

`sharing::misp::1.0` publishes one Tide object as one MISP Event. The Event carries exactly one instance of the upstream `opentide` MISP object. The `opentide-object` attribute holds the source document verbatim. Exposure is the object's `metadata.tlp`, the MISP distribution that value permits, and the target's sharing group. The connector does not filter fields out of the document.

The pinned template is [schemas/misp/opentide.definition.json](../../schemas/misp/opentide.definition.json), copied from `MISP/misp-objects` `objects/opentide/definition.json`. Refresh direction is **upstream MISP → this repository**, the reverse of vocabulary sync. A refresh that changes the pinned relation set is a revision of this spec.

## Requirements

- A target with `connector = "misp"` MUST set `schema = "sharing::misp::1.0"`.
- `[targets.<id>.misp].organisation_uuid` MUST be present and a canonical 36-character UUID.
- The connector MUST emit exactly one `opentide` object per Event and zero Event-level attributes.
- The `opentide-object` value MUST be the verbatim UTF-8 YAML bytes of the source document. Comments, key order, indentation, and blank lines MUST be preserved. The connector MUST NOT re-serialise, encode, truncate, split, or wrap that body.
- No workspace configuration value, API key, authorization header, or `${ENV_VAR}` substitution result MAY be injected into the document, object, envelope, tag set, share report, share state, or CLI output.
- The connector MUST NOT create, modify, enable, delete, or upload a galaxy or cluster.
- `pull` is not supported.

## Definition

### Capability

| Capability | MISP 1.0 |
|------------|----------|
| `identifier` | `misp` |
| `schema` | `sharing::misp::1.0` |
| `push` | yes |
| `preview` | yes |
| `status` | yes (local state; MAY view the remote) |
| `retract` | yes (unpublish; optional delete) |
| `pull` | no |

### Target tables

Targets live in `sharing.toml` ([sharing.md](../sharing.md)). A second MISP instance is a second `[targets.<id>]` table in that same file.

```toml
[targets.misp-internal]
enabled = false
identifier = "misp-internal"
name = "Internal MISP"
connector = "misp"
schema = "sharing::misp::1.0"
require_validation = true
description = "Internal MISP instance"

[targets.misp-internal.connection]
url = "https://misp.internal.example.org"
api_key = "${MISP_INTERNAL_API_KEY}"
verify_ssl = true
timeout_seconds = 30

[targets.misp-internal.misp]
organisation_uuid = "00000000-0000-4000-8aaa-000000000001"
mode = "api"
publish = false
distribution = "this-community"
sharing_group_id = 0
sharing_group_uuid = ""
analysis = "completed"
info_prefix = "[OpenTide] "
extra_tags = []

[targets.misp-internal.misp.file]
directory = ".opentide/exports/sharing/misp-internal"

[targets.misp-isac]
enabled = false
identifier = "misp-isac"
connector = "misp"
schema = "sharing::misp::1.0"
max_tlp = "green"

[targets.misp-isac.connection]
url = "https://misp.isac.example.net"
api_key = "${MISP_ISAC_API_KEY}"

[targets.misp-isac.misp]
organisation_uuid = "00000000-0000-4000-8aaa-000000000002"
mode = "api"
distribution = "sharing-group"
sharing_group_uuid = "00000000-0000-4000-8bbb-000000000001"
sharing_group_id = 0
publish = true
```

#### `[targets.<id>.connection]`

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `url` | string (URL) | yes when `mode = "api"` | — | Origin only. Trailing slash ignored. |
| `api_key` | string | yes when `mode = "api"` | — | MUST use `${ENV_VAR}` in committed config. An unset or empty variable excludes that target before any request. Literal keys SHOULD warn and MUST NOT be printed. |
| `verify_ssl` | bool | no | `true` | |
| `timeout_seconds` | number | no | `30` | Per-request timeout |
| `client_cert` / `client_key` | string | no | — | Mutual TLS. Values MUST support `${ENV_VAR}`. |

#### `[targets.<id>.misp]`

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `organisation_uuid` | string (UUID) | yes | — | Publishing organisation. Half of the lookup key. |
| `mode` | string | no | `api` | `api` or `file` |
| `publish` | bool | no | `false` | Call publish after upsert |
| `distribution` | string | no | per TLP row | Clamped to the allowed set below |
| `sharing_group_id` | integer | no | `0` | Required non-zero for `sharing-group` in file mode |
| `sharing_group_uuid` | string | no | `""` | Preferred in api mode |
| `analysis` | string | no | `completed` | `initial`, `ongoing`, `completed` |
| `info_prefix` | string | no | `""` | At most 32 characters, prepended verbatim |
| `extra_tags` | list[string] | no | `[]` | At most 10 entries of 1–255 characters |

`mode = "file"` writes one JSON document per event under `[targets.<id>.misp.file].directory`, default `.opentide/exports/sharing/<target id>/`. The directory is created if missing. Filenames SHOULD be the object UUID, because the Event UUID does not exist yet. File mode applies the TLP ceiling, the `allow_tlp_red` gate, and the distribution rules. It makes no HTTP request.

In `mode = "api"`, before any create or update, the connector MUST read the organisation UUID of the authenticated API key and compare it case-insensitively to `organisation_uuid`. A mismatch fails that target with `organisation_uuid_mismatch` and writes nothing. A read failure fails that target with `organisation_uuid_unverified`. Other targets continue. In file mode the declared UUID is written as the intended creator organisation and is not verified.

#### Removed keys

Supplying any of these is an error naming the key and the target identifier, raised before any target is contacted:

| Key | Replaced by |
|-----|-------------|
| `event_mode` | One Event per Tide object |
| `threat_level_source` | The threat-level table in this spec |
| `threat_level_id` on the target | Derived per object |
| a per-target PAP option | Object `metadata.pap` |
| `verify_event_org` | Organisation half of the lookup key |
| `tag_namespace` | No `opentide:*` tag namespace |
| `include_queries`, `include_internal_references`, `include_tenant_identifiers`, `include_platform_blocks`, `include_object_yaml` | TLP, distribution, and sharing group |

#### Distribution

| Config value | MISP `distribution` |
|--------------|---------------------|
| `your-organization` | `0` |
| `this-community` | `1` |
| `connected-communities` | `2` |
| `all-communities` | `3` |
| `sharing-group` | `4` |

`sharing-group` is a membership list, not a point on the 0–3 width scale. Resolution is set membership. If `distribution` is omitted, use the row default. If it is set and in the allowed set, use it. If it is set and not in the allowed set, use the row default. Do not fail the object solely for this clamp.

| Object `metadata.tlp` | Allowed `distribution` values | Default when omitted |
|-----------------------|-------------------------------|----------------------|
| `clear` | `your-organization`, `this-community`, `connected-communities`, `all-communities`, `sharing-group` | `all-communities` |
| `green` | `your-organization`, `this-community`, `connected-communities`, `sharing-group` | `this-community` |
| `amber` | `your-organization`, `sharing-group` | `sharing-group` if a group is configured, else `your-organization` |
| `amber+strict` | `your-organization` | `your-organization` |
| `red` | `your-organization` | Not shared unless `allow_tlp_red` resolves true and `--allow-tlp-red` is passed; then `your-organization` |

If `distribution = "sharing-group"`, fail that target before any event is written when:

- `api`: neither `sharing_group_uuid` nor a non-zero `sharing_group_id` is set.
- `file`: `sharing_group_id` is `0`. A UUID alone is not enough.

| Mode | Sharing-group identifier |
|------|--------------------------|
| `api` | `sharing_group_uuid` is preferred. When set, resolve it on each run against `GET /sharing_groups/index` by exact UUID match. UUID wins if both are set. If the UUID is empty, use a non-zero `sharing_group_id`. If the UUID is set and not found, fail the target (`sharing_group_unresolved`). |
| `file` | MUST NOT contact the instance. A non-zero `sharing_group_id` is required. The UUID MAY be copied into export metadata and MUST NOT be treated as resolved. |

`sharing_group_id` MUST be `0` whenever the resolved distribution is not `sharing-group`.

An `analysis` value outside the three names, or an `info_prefix` longer than 32 characters, fails that target before any Event is written. An `extra_tags` entry in the `opentide` namespace, or equal to a `misp` tag string of the `tlp` or `pap` vocabularies, is a configuration error. The closed tag set below is provable only while `extra_tags` is absent or empty.

### HTTP subset

Minimum server: a MISP release that ships `opentide` template version 5 (`uuid` `892fd46a-f69e-455c-8c4f-843a4b8f4295`).

Every request MUST send the API key as `Authorization: <key>`. The key MUST NOT appear in query strings. On `401` or `403`, the target MUST fail with authentication failed and MUST NOT dump response bodies.

| Operation | Request | Use |
|-----------|---------|-----|
| Server identity | `GET /servers/getVersion` | Connectivity probe |
| Authenticated organisation | `GET /users/view/me` | `organisation_uuid` pre-flight. Compare `Organisation.uuid` (or equivalent org UUID on the user) case-insensitively. |
| Find events | `POST /events/restSearch` | Body includes `"returnFormat": "json"`, `"object_name": "opentide"`, `"value": "<metadata.uuid>"`, and a page size. Page with `page` and `limit` until a page returns fewer than `limit` hits. |
| View event | `GET /events/view/<uuid-or-id>` | Read a candidate, including `Orgc` and objects |
| Add event | `POST /events/add` | Create, including the nested object and tags |
| Edit event | `POST /events/edit/<id>` | Update after lookup |
| Publish | `POST /events/publish/<id>` | When `publish` resolves true |
| Unpublish | `POST /events/unpublish/<id>` | Retract default |
| Delete event | `DELETE /events/<id>` | Retract `--delete` |
| Sharing groups | `GET /sharing_groups/index` | Resolve UUID to numeric id (`mode = api` only) |
| Galaxy clusters | Read-only galaxy cluster search | Resolve `threat-actor` and `mitre-attack-pattern` |

`restSearch` is not assumed to constrain creator organisation and object attribute in one predicate. The connector MUST keep a hit only when both halves of the lookup key match, and MUST exclude every other hit from the match count. A foreign organisation's Event is an informational note, not a match and not an error.

PyMISP is the recommended opentide library. The spec is HTTP/JSON. Any client that speaks this subset conforms.

Galaxy or sharing-group lookups that fail for transport, timeout, or authorization fail the affected object with `galaxy_lookup_failed` or the target with `sharing_group_unresolved`. They MUST NOT degrade into a guessed value.

### Tags

Emission order: TLP, PAP, `threat-actor` clusters, `mitre-attack-pattern` clusters, then `extra_tags`. Ascending code point order within each group. Each distinct tag string at most once.

| Source | Cardinality | Value |
|--------|-------------|-------|
| `tlp` vocabulary `misp` for `metadata.tlp` | exactly 1 | copied character-for-character |
| `pap` vocabulary `misp` for `metadata.pap` | 0 or 1 | copied character-for-character |
| `threat-actor` galaxy cluster | 0..n | `misp-galaxy:threat-actor="<cluster value as returned>"` |
| `mitre-attack-pattern` galaxy cluster | 0..n | `misp-galaxy:mitre-attack-pattern="<cluster value as returned>"` |
| `extra_tags` | 0..10 | Free-form constants on the target |

A missing or unmapped `metadata.tlp` fails the object with `unmapped_tlp`. An unmapped `metadata.pap` fails it with `unmapped_pap`. An absent `metadata.pap` emits no PAP tag. There is no per-target PAP default.

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

File mode and `preview` omit cluster tags that would require a lookup, with the same notes, and still emit the Event.

Golden fixtures MUST assert galaxy tag *shape* (`misp-galaxy:<galaxy>="<non-empty>"`) rather than one instance's cluster value. Cluster strings are not stable across galaxy versions.

### Event envelope

The connector sets exactly these Event fields:

| Field | Source |
|-------|--------|
| `info` | `info_prefix` concatenated with the object top-level `name`, no separator inserted, truncated to 255 characters |
| `date` | UTC calendar date of `metadata.created` (`YYYY-MM-DD`), on create and update. Never the run date. |
| `distribution` | The TLP-narrowed value |
| `sharing_group_id` | Resolved numeric group when distribution is `4`; otherwise `0` |
| `threat_level_id` | The table below |
| `analysis` | `initial`→`0`, `ongoing`→`1`, `completed`→`2` |
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

`opentide-type` MUST be one of the template `values_list` entries: `threat`, `objective`, `rule`. Those strings are the OpenTide family names. This spec does not emit the earlier draft's `tvm`, `dom`, or `mdr` tokens; template version 5 rejects them.

| Relation | Cardinality | Source | `disable_correlation` |
|----------|-------------|--------|------------------------|
| `name` | exactly 1 | Object top-level `name`, verbatim | `false` |
| `uuid` | exactly 1 | `metadata.uuid`, verbatim. Never the Event UUID | `false` |
| `version` | exactly 1 | `metadata.version` as a decimal digit string, no leading zeroes. The template `sane_default` of `1` MUST NOT replace a real value | `true` |
| `opentide-type` | exactly 1 | Family name: `threat`, `objective`, or `rule` | `true` |
| `schema` | exactly 1 | `metadata.schema`, verbatim (`rule::1.0` and siblings) | `true` |
| `opentide-object` | exactly 1 | Verbatim source document | `false` |
| `opentide-relation` | 0..n | Parent object UUIDs below | `false` |
| `misp-event-relation` | 0 | Not emitted. MISP Event UUIDs are server-assigned and are not OpenTide identity | `false` when present on a remote object the connector did not write |

Every emitted attribute MUST set `type` to `text`, `category` to `Other`, `to_ids` to `false`, and `distribution` to `5` (inherit the Event). The object itself MUST set `distribution` to `5`. Inheritance is MISP distribution value 5, not an omitted field, so a stored object cannot outreach its Event if the server honours the attribute.

`disable_correlation` MUST follow the table. It is taken from the pinned template where the template sets it, and `false` where the template omits it. Correlation of `uuid` and `opentide-relation` text MAY surface related events on an instance that correlates `text`. This spec does not require that UI behaviour. The authoritative link is the attribute value.

A missing template fails the object with `template_missing`. A missing required relation on the instance template fails it with `template_relation_missing`, naming each absent relation. A template version other than `5`, while all six required relations exist and `opentide-type` accepts the family name, is an informational note. The connector still emits the pinned relation set.

Updates touch the seven envelope fields, the tag set, and the one `opentide` object. Remote objects or Event-level attributes the connector did not emit stay, with an informational note. The remote Event `uuid` and creator organisation are never rewritten.

#### Relations

`opentide-relation` points from child to parent:

| Family | Source | Emitted |
|--------|--------|---------|
| `threat` | — | zero relations |
| `objective` | `objective.threats[]` | one per distinct UUID |
| `rule` | top-level `detection_model` | zero or one |

Values are 36-character lowercase canonical UUIDs of Tide objects, never MISP Event or object UUIDs, at most one attribute per distinct UUID, ordered ascending. A non-canonical UUID fails the object. An absent, null, or empty source emits zero relations. A relation UUID whose object was not shared to that target is still emitted, with an informational note.

No `extends_uuid` is set and no MISP event extension is created.

### Identity

```
lookup key = (Event.Orgc.uuid == target organisation_uuid)
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

If the instance rejects `opentide-object` for length, fail that object with `attribute_too_large` and write nothing. The connector MUST NOT split the document across attributes. This spec does not set a byte cap of its own; the instance's rejection is the limit.

### Payload

The emitted document is one YAML document whose root is a mapping. It passes `uuid-format` and `schema` checks against its own `metadata.schema` whenever the source object does. Workspace `id-uniqueness` and cross-object reference checks are outside a single detached document.

`require_validation` (default `true`) runs those checks before payload construction. An object that raises `error` is `failed` / `validation_error`. Warnings continue with a note. With `require_validation = false`, construction proceeds and each unvalidated object UUID is noted.

Nothing in the document is removed for any target, TLP value, configuration key, or flag. Withholding content is done by raising `metadata.tlp`, narrowing distribution or the sharing group, or leaving the object out of the selection.

`preview` and `push` produce a byte-identical `opentide-object` value and the same outcome class for the same object, target, and resolved policy.

### Retract

| Mode | MISP action |
|------|-------------|
| default | `unpublish` if published; leave the event |
| `--delete` | delete the event. Implementations SHOULD require `--yes` or an equivalent confirm flag. The share-state row MUST be dropped. |

Retract operates on records present in state or on the remote, not on objects that were never pushed. It still respects the resolved TLP ceiling.

### Preflight reasons

These are preflight (exit `1`) for this connector, before the exit rules in [sharing.md](../sharing.md): `sharing_group_unresolved` before any Event is written, file-mode `sharing-group` with `sharing_group_id = 0`, and `organisation_uuid_mismatch` on every selected target.

### Validation check `sharing-config`

`opentide validate` SHOULD offer `sharing-config` (off by default, on for `opentide share push`):

- The sharing file is one `sharing.toml`. A `sharing/targets/` directory is an error (`sharing_targets_directory`).
- Every target is a named `[targets.<id>]` table. `identifier`, when set, equals `<id>`.
- `connector` and `schema` are known.
- `mode = "api"` implies a resolvable `url` and a non-empty `api_key` environment variable.
- `organisation_uuid` is a canonical UUID on every `misp` target.
- Sharing-group rules in this spec hold.
- `max_tlp` is a `tlp` name, and target policy is not weaker than global policy.
- `analysis`, `info_prefix`, and `extra_tags` respect their bounds.
- No removed key is present.

## Relationships

- [sharing.md](../sharing.md) — CLI, single-file configuration, exit statuses, share state
- [metadata.md](../metadata.md) — `metadata.tlp`, optional `metadata.pap`
- [vocabularies/tlp.vocab.toml](../../vocabularies/tlp.vocab.toml), [vocabularies/pap.vocab.toml](../../vocabularies/pap.vocab.toml) — tag strings
- [schemas/misp/opentide.definition.json](../../schemas/misp/opentide.definition.json) — pinned template version 5

## Defaults & overrides

Bundled targets are absent or `enabled = false`. Distribution and threat level are derived per object. `publish` defaults to false. `mode` defaults to `api`.

## Examples

- One file, two targets: [fixtures/sharing/valid/sharing.toml](../../fixtures/sharing/valid/sharing.toml)
- Golden Event for the committed rule fixture: [fixtures/sharing/valid/rule-event.json](../../fixtures/sharing/valid/rule-event.json)
- Invalid removed key: [fixtures/sharing/invalid/removed-event-mode.toml](../../fixtures/sharing/invalid/removed-event-mode.toml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-25 | Initial connector spec from accepted [RFC 0005](../../rfcs/0005-sharing-system.md). Pins upstream `opentide` template version 5 (`threat` / `objective` / `rule`, required `schema`). Targets are tables in `sharing.toml`. |
