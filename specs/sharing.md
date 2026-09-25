---
spec: sharing
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Sharing

## Summary

Sharing publishes Tide objects (threat, objective, rule) to external intelligence platforms. It is a sibling of deployment, not a detection platform. `opentide share` reads one workspace file, `sharing.toml`, selects objects, applies TLP policy, and hands each selected object to a connector target named in that file. The first connector is MISP ([sharing/misp-1.0.md](sharing/misp-1.0.md)).

## Requirements

- Sharing configuration MUST be a single file, `sharing.toml`. Implementations MUST NOT load per-target files from `sharing/targets/` or any other subdirectory as sharing targets.
- Every target MUST be a named table `[targets.<identifier>]` inside that file. The table key is the target identifier.
- `opentide share` with no subcommand MUST mean `push`.
- Implementations MUST provide `push`, `preview`, `status`, `retract`, and `targets`.
- MISP MUST NOT be added to the [platforms](platforms.md) capability matrix and MUST NOT appear as `configurations.misp` on `rule::1.0`.
- Bundled defaults MUST ship with `[sharing]` equivalent `enabled = false` and no enabled target.
- A target MUST NOT set a looser `max_tlp` or `allow_tlp_red` than the value resolved on `sharing.toml`. A looser value is a configuration error raised before any target is contacted.
- Scope filters and target selection that match nothing MUST fail with `scope_no_match`.
- Secrets MUST NOT appear in logs, reports, preview payloads, or share state. API keys, authorization header values, and values substituted from `${ENV_VAR}` MUST be replaced with a fixed redaction marker. Target URLs and organisation UUIDs are not credentials and MUST be emitted unredacted.
- Connectors without `pull` MUST NOT advertise import.

## Definition

### Sharing is not deployment

| Concern | Command | Config | Destination |
|---------|---------|--------|-------------|
| Detection runtime | `opentide deploy` | `deployment.toml`, `platforms/*.toml` | SIEM / EDR |
| Intelligence publication | `opentide share` | `sharing.toml` | CTI platforms (MISP first) |

Connectors register by connector id (`misp`). A workspace MAY define multiple targets of the same connector (for example `misp-internal` and `misp-isac`). Each target has its own URL, credentials, publishing organisation, sharing group, and TLP ceiling. Nothing in one target changes the resolved configuration of another.

Platform files stay one file per bundled product because those identifiers are fixed by the package. Sharing targets are workspace-authored destinations, so they belong in the same file an operator reviews, diffs, and overrides.

### Configuration file

`sharing.toml` maps to config key `sharing`, following [configuration.md](configuration.md): the file body is the `sharing` table. Client overrides live at `.opentide/configurations/sharing.toml` and deep-merge onto the bundled file. A client MAY override one target key without restating every other target.

```toml
enabled = false
default_targets = []
max_tlp = "amber"
allow_tlp_red = false

[selection]
object_types = ["threat", "objective", "rule"]
rule_statuses = ["PRODUCTION"]

[targets.misp-internal]
enabled = false
identifier = "misp-internal"
name = "Internal MISP"
connector = "misp"
schema = "sharing::misp::1.0"
require_validation = true
description = "Internal MISP instance"
```

Connector-specific tables (`[targets.<id>.connection]`, `[targets.<id>.misp]`) are defined by the connector spec. An array-of-tables `[[targets]]` MUST NOT be used: index-based merge cannot address one target. A table key that is not 1–64 characters of lowercase letters, digits, hyphen, and underscore is a configuration error. `[targets.<id>].identifier`, when set, MUST equal `<id>`.

Files under `.opentide/configurations/sharing/` MUST NOT be read as configuration. Placing a target in a subfolder is not an override.

| Field | Type | Required | Default | Semantics |
|-------|------|----------|---------|-----------|
| `enabled` | bool | no | `false` | Master switch. `push`, `publish`, and `retract` MUST refuse remote mutation when false. `preview` and `status` MAY still run. |
| `default_targets` | list[string] | no | `[]` | Identifiers used when `--target` is omitted. Empty means every target with `enabled = true`. |
| `max_tlp` | string | no | `amber` | A `tlp` vocabulary `name`. Objects whose `metadata.tlp` exceeds this ceiling are `skipped_tlp`. Order: `clear` < `green` < `amber` < `amber+strict` < `red`. |
| `allow_tlp_red` | bool | no | `false` | TLP:RED MUST NOT be shared unless this resolves to `true` and the operator passes `--allow-tlp-red`. |
| `selection.object_types` | list[string] | no | all three families | Restrict families. |
| `selection.rule_statuses` | list[string] | no | `["PRODUCTION"]` | Names from merged `deployment.toml`. Threats and objectives ignore this key. |

`max_tlp` and `allow_tlp_red` are the only policy keys resolved both globally and per target. Comparison order is `clear` < `green` < `amber` < `amber+strict` < `red`. A lower `max_tlp` shares fewer objects and is stricter. A target MAY lower `max_tlp` or set `allow_tlp_red = false`. A target MUST NOT raise `max_tlp` or set `allow_tlp_red = true` when the global value is `false`. CLI flags follow strictest-wins, except `--allow-tlp-red`, which may widen a value only where `allow_tlp_red` already resolves to `true` for that target.

`require_validation` is per target, default `true`, not a global key.

### Common target fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | no | `false` | Participate in share runs |
| `identifier` | string | no | table key | MUST match the table key when present |
| `name` | string | no | identifier | Display name |
| `connector` | string | yes | — | Connector id |
| `schema` | string | yes for MISP | — | Connector schema id, e.g. `sharing::misp::1.0` |
| `require_validation` | bool | no | `true` | When true, push MUST run default [validation](validation.md) checks and MUST NOT share objects that raise errors. Warnings do not block. |
| `description` | string | no | `""` | Human notes |
| `max_tlp` | string | no | global | Stricter ceiling only |
| `allow_tlp_red` | bool | no | global | May only tighten |

An unrecognised table is a warning and does not prevent the target from loading, except `connector`, which MUST be recognised or the target is skipped with an error. An unrecognised key inside a known table is a warning, unless it names a removed option published by the connector spec, which is an error. The loader MUST reject removed keys before contacting any target.

### CLI

| Command | Purpose |
|---------|---------|
| `opentide share` / `opentide share push` | Publish in-scope objects to selected targets |
| `opentide share preview` | Build payloads and apply policy; write nothing remote (`push --dry-run`) |
| `opentide share status` | Local share state versus object versions; no remote mutation |
| `opentide share retract` | Unpublish, or delete with `--delete` |
| `opentide share targets` | List targets, connector, enabled flag, and redacted connection |

| Flag | Effect |
|------|--------|
| `--target <id>` | Repeatable. Unknown id is an error. A disabled target is an error and MUST NOT be re-enabled. |
| `--uuid <uuid>` | Repeatable. Narrow to objects. |
| `--type <family>` | Repeatable. `threat`, `objective`, `rule`. |
| `--file <path>` | Repeatable. Narrow to YAML files. |
| `--dry-run` | On `push`: same as `preview`. |
| `--allow-tlp-red` | Required in addition to resolved `allow_tlp_red = true` to share TLP:RED. |
| `--publish` / `--no-publish` | Override target `publish` for this run. |
| `--workers` | Optional parallelism across HTTP upserts. MUST NOT change any object's outcome. |

An unmatched `--target`, an unmatched `default_targets` entry, and an empty resolved target set are `scope_no_match`.

Implementations MUST choose exactly one exit status, in this order:

1. Preflight (validation, policy misconfiguration, connector preflight failures listed by the connector spec, `scope_no_match`) → `1`.
2. Else if at least one object action succeeded (`created`, `updated`, `unchanged`, `retracted`) and at least one object or target `failed` → `3`.
3. Else if no object `failed` → `0`. Policy skips (`skipped_tlp`, `skipped_status`) are not `failed`. An all-skip run is `0`.
4. Else, if every `failed` is authentication or connectivity → `2`; otherwise → `1`.

| Code | Meaning |
|------|---------|
| `0` | Preflight passed and no object `failed`. |
| `1` | Preflight error, or total failure that is not solely auth/connectivity. |
| `2` | No successful object action, and every `failed` is authentication or connectivity. |
| `3` | Partial success: at least one success and at least one failure. |

Stdout SHOULD be a share report (human table by default; `--json` MAY be offered). The report MUST carry exactly one record per pair of object `metadata.uuid` and target identifier, each with exactly one action (`created`, `updated`, `unchanged`, `skipped_tlp`, `skipped_status`, `retracted`, `failed`), the remote identifier where one exists, and a reason on every `skipped_*` and `failed`. Informational notes MAY be attached without changing the action.

### Workspace paths

| Path | Purpose | Client-edited? |
|------|---------|----------------|
| `.opentide/configurations/sharing.toml` | The sharing file: global policy and every target | Yes |
| `.opentide/sharing/state.json` | Last successful share mapping | No — generated |
| `.opentide/exports/sharing/<target id>/` | Preview and file-mode output | No — generated |

`state.json` holds at most one entry per pair of object UUID and target identifier:

| Field | Description |
|-------|-------------|
| `object_uuid` | Tide `metadata.uuid` |
| `object_schema` | `metadata.schema` |
| `object_version` | `metadata.version` at last successful share |
| `content_hash` | Hash of the emitted object document for that target |
| `target_id` | Sharing target identifier |
| `connector` | Connector id |
| `organisation_uuid` | Publishing organisation observed for the matched remote record |
| `remote_event_uuid` | Remote identifier assigned by the destination |
| `remote_event_id` | Remote numeric id, or explicit null when not observed |
| `published` | Whether the remote record was published |
| `shared_at` | ISO-8601 UTC timestamp |

State is a regenerable cache. The connector's remote lookup wins on disagreement. Deleting `state.json` changes no outcome except replacing `unchanged` with `updated`. Implementations SHOULD gitignore `state.json`.

### Connector contract

A connector spec MUST declare `identifier`, `schema`, and whether `push`, `preview`, `status`, `retract`, and `pull` are supported. It MUST publish its own removed-keys table. Future connectors (OpenCTI, TAXII) get their own `sharing::<id>::1.0` specs and add named targets to the same `sharing.toml`.

## Relationships

- [sharing/misp-1.0.md](sharing/misp-1.0.md) — MISP connector `sharing::misp::1.0`
- [configuration.md](configuration.md) — merge order; `sharing.toml` is overridable
- [workspace.md](workspace.md) — generated sharing paths
- [validation.md](validation.md) — `sharing-config` check and `require_validation`
- [metadata.md](metadata.md) — `metadata.tlp`, optional `metadata.pap`
- [platforms.md](platforms.md) — deployment targets; MISP is not in this matrix
- [RFC 0005](../rfcs/0005-sharing-system.md) — accepted proposal

## Defaults & overrides

Bundled `sharing.toml` ships disabled, with `max_tlp = "amber"`, `allow_tlp_red = false`, and `selection.rule_statuses = ["PRODUCTION"]`. Clients enable sharing and declare targets only in `.opentide/configurations/sharing.toml`.

## Examples

Two MISP instances in one file: [fixtures/sharing/valid/sharing.toml](../fixtures/sharing/valid/sharing.toml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-25 | Initial spec from accepted [RFC 0005](../rfcs/0005-sharing-system.md). Targets are named tables in `sharing.toml`, not files under `sharing/targets/`. |
