---
spec: sharing
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Sharing

## Summary

Sharing publishes Tide objects (threat, objective, rule) to external intelligence platforms. It is a sibling of deployment, not a detection platform. `opentide share` reads one workspace file, `sharing.toml`. Each integration is a top-level array of tables named after its connector — `[[misp]]` today, `[[opencti]]` when that connector is specified. Every block is one destination and carries its own selection and TLP ceiling. The first connector is MISP ([sharing/misp-1.0.md](sharing/misp-1.0.md)).

## Requirements

- Sharing configuration MUST be a single file, `sharing.toml`. Implementations MUST NOT load sharing configuration from `sharing/` or any other subdirectory.
- Each integration MUST be a top-level array of tables whose key is the connector id (`[[misp]]`). One array entry is one destination.
- The top level of `sharing.toml` MUST hold only arrays of tables. Any other top-level key, including a `[sharing]` or `[targets.<id>]` table, MUST be a configuration error.
- Every block MUST carry a `name`. Names MUST be unique across every integration block in the file.
- Selection and the TLP ceiling MUST be resolved per block. There is no global selection or global ceiling.
- A block MUST NOT share an object whose `metadata.tlp` exceeds its `max_tlp`. TLP:RED MUST NOT be shared unless the block sets `max_tlp = "red"` **and** the operator passes `--allow-tlp-red`.
- Bundled defaults MUST ship with no enabled block.
- `opentide share` with no subcommand MUST mean `push`. Implementations MUST provide `push`, `preview`, `status`, `retract`, and `targets`.
- MISP MUST NOT be added to the [platforms](platforms.md) capability matrix and MUST NOT appear as `configurations.misp` on `rule::1.0`.
- Scope filters and target selection that match nothing MUST fail with `scope_no_match`.
- Secrets MUST NOT appear in logs, reports, preview payloads, or share state. API keys, authorization header values, and values substituted from `${ENV_VAR}` MUST be replaced with a fixed redaction marker. URLs and organisation UUIDs are not credentials and MUST be emitted unredacted.
- Connectors without `pull` MUST NOT advertise import.

## Definition

### Sharing is not deployment

| Concern | Command | Config | Destination |
|---------|---------|--------|-------------|
| Detection runtime | `opentide deploy` | `deployment.toml`, `platforms/*.toml` | SIEM / EDR |
| Intelligence publication | `opentide share` | `sharing.toml` | CTI platforms (MISP first) |

### `sharing.toml`

The file has no global keys. Its top level holds only integration arrays.

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
rule_statuses = ["PRODUCTION"]

# A later connector spec adds its own array, for example:
# [[opencti]]
# name = "opencti-sector"
```

A two-instance MISP setup is two `[[misp]]` entries. A MISP instance plus an OpenCTI instance is one `[[misp]]` entry and one `[[opencti]]` entry. Nothing in one block changes another.

#### Keys every integration block carries

| Field | Type | Required | Default | Semantics |
|-------|------|----------|---------|-----------|
| `name` | string | yes | — | Identifier used by `--target`, the share report, state, and preview paths. 1–64 characters of lowercase letters, digits, hyphen, and underscore. |
| `enabled` | bool | no | `false` | Participate in share runs. |
| `max_tlp` | string | no | `amber` | A `tlp` vocabulary `name`. Objects above this ceiling are `skipped_tlp`. Order: `clear` < `green` < `amber` < `amber+strict` < `red`. |
| `object_types` | list[string] | no | `["threat", "objective", "rule"]` | Families this block shares. |
| `rule_statuses` | list[string] | no | `["PRODUCTION"]` | Rule statuses this block shares. Values MUST be names from merged `deployment.toml`. Threats and objectives ignore this key. |

The connector spec defines every other key in its block. Within a known integration, an unrecognised key MUST be a configuration error naming the key and the block `name`, raised before any destination is contacted. A top-level array whose key names no known connector is a warning, and that array is skipped, so a workspace can declare `[[opencti]]` before its CLI supports it.

#### Merge

`sharing.toml` follows the [configuration](configuration.md) merge order: bundled package, then client `.opentide/configurations/sharing.toml`, then parent instance. Integration arrays merge **by `name`**, not by position and not by replacing the array. A later layer's entry with the same integration key and `name` overrides the earlier entry key by key; keys it does not restate are kept, and a list value replaces the earlier list. An entry with a new `name` is appended after the existing entries. A duplicate `name` inside one layer is a configuration error naming every block involved. A `name` used by two different integrations is a configuration error.

Required keys and value checks apply to the merged result, so a layer MAY restate only `name` and the keys it changes.

A client can therefore enable a bundled block with a two-line override:

```toml
[[misp]]
name = "misp-internal"
enabled = true
```

### CLI

| Command | Purpose |
|---------|---------|
| `opentide share` / `opentide share push` | Publish in-scope objects to selected blocks |
| `opentide share preview` | Build payloads and apply selection and TLP; write nothing remote (`push --dry-run`) |
| `opentide share status` | Local share state versus object versions; no remote mutation |
| `opentide share retract` | Unpublish, or delete with `--delete` |
| `opentide share targets` | List blocks: integration, `name`, `enabled`, `max_tlp`, and URL. Never the API key. |

| Flag | Effect |
|------|--------|
| `--target <name>` | Repeatable. Restrict to named blocks. Unknown name is an error. A disabled block is an error and MUST NOT be re-enabled. Omitted means every enabled block across all integrations. |
| `--uuid <uuid>` | Repeatable. Narrow to objects. |
| `--type <family>` | Repeatable. `threat`, `objective`, `rule`. Intersected with each block's `object_types`. |
| `--file <path>` | Repeatable. Narrow to YAML files. |
| `--dry-run` | On `push`: same as `preview`. |
| `--allow-tlp-red` | Required, together with a block `max_tlp = "red"`, to share TLP:RED to that block. |
| `--publish` / `--no-publish` | Override the block's `publish` for this run. |
| `--workers` | Optional parallelism across HTTP upserts. MUST NOT change any object's outcome. |

CLI filters narrow a block's selection. They never widen it. An unmatched `--target` and an empty resolved block set are `scope_no_match`.

Implementations MUST choose exactly one exit status, in this order:

1. Preflight (validation, configuration errors, connector preflight failures listed by the connector spec, `scope_no_match`) → `1`.
2. Else if at least one object action succeeded (`created`, `updated`, `unchanged`, `retracted`) and at least one object or block `failed` → `3`.
3. Else if no object `failed` → `0`. Policy skips (`skipped_tlp`, `skipped_status`, `skipped_type`) are not `failed`. An all-skip run is `0`.
4. Else, if every `failed` is authentication or connectivity → `2`; otherwise → `1`.

| Code | Meaning |
|------|---------|
| `0` | Preflight passed and no object `failed`. |
| `1` | Preflight error, or total failure that is not solely auth/connectivity. |
| `2` | No successful object action, and every `failed` is authentication or connectivity. |
| `3` | Partial success: at least one success and at least one failure. |

Stdout SHOULD be a share report (human table by default; `--json` MAY be offered). The report MUST carry exactly one record per pair of object `metadata.uuid` and block `name`, each with exactly one action (`created`, `updated`, `unchanged`, `skipped_tlp`, `skipped_status`, `skipped_type`, `retracted`, `failed`), the remote identifier where one exists, and a reason on every `skipped_*` and `failed`. Informational notes MAY be attached without changing the action.

Every in-scope object MUST pass the default [validation](validation.md) checks before it is shared. An object that raises `error` is `failed` / `validation_error`. Warnings do not block.

### Workspace paths

| Path | Purpose | Client-edited? |
|------|---------|----------------|
| `.opentide/configurations/sharing.toml` | Every integration block | Yes |
| `.opentide/sharing/state.json` | Last successful share mapping | No — generated |
| `.opentide/exports/sharing/<name>/` | `preview` output | No — generated |

`state.json` holds at most one entry per pair of object UUID and block `name`:

| Field | Description |
|-------|-------------|
| `object_uuid` | Tide `metadata.uuid` |
| `object_schema` | `metadata.schema` |
| `object_version` | `metadata.version` at last successful share |
| `content_hash` | Hash of the emitted object document |
| `integration` | Connector id (`misp`) |
| `target` | Block `name` |
| `organisation_uuid` | Publishing organisation observed for the matched remote record |
| `remote_event_uuid` | Remote identifier assigned by the destination |
| `remote_event_id` | Remote numeric id, or explicit null when not observed |
| `published` | Whether the remote record was published |
| `shared_at` | ISO-8601 UTC timestamp |

State is a regenerable cache. The connector's remote lookup wins on disagreement. Deleting `state.json` changes no outcome except replacing `unchanged` with `updated`. Implementations SHOULD gitignore `state.json`.

### Connector contract

A connector spec MUST declare its integration key (the top-level array name), its `schema` id, the block keys it adds, and whether `push`, `preview`, `status`, `retract`, and `pull` are supported. Future connectors (OpenCTI, TAXII) get their own `sharing::<id>::1.0` specs and their own top-level array in `sharing.toml`.

## Relationships

- [sharing/misp-1.0.md](sharing/misp-1.0.md) — MISP connector `sharing::misp::1.0`, block `[[misp]]`
- [configuration.md](configuration.md) — merge order; `sharing.toml` is overridable
- [workspace.md](workspace.md) — generated sharing paths
- [validation.md](validation.md) — `sharing-config` check
- [metadata.md](metadata.md) — `metadata.tlp`, optional `metadata.pap`, `metadata.organisation`
- [platforms.md](platforms.md) — deployment targets; MISP is not in this matrix
- [RFC 0005](../rfcs/0005-sharing-system.md) — accepted proposal

## Defaults & overrides

Bundled `sharing.toml` ships with no enabled block. A block that omits `max_tlp`, `object_types`, or `rule_statuses` shares `amber` and below, all three families, and `PRODUCTION` rules only. Clients declare and enable blocks only in `.opentide/configurations/sharing.toml`.

## Examples

- Two MISP instances with different selections: [fixtures/sharing/valid/sharing.toml](../fixtures/sharing/valid/sharing.toml)
- Merge by `name`: [override.toml](../fixtures/sharing/valid/override.toml) applied to that file yields [merged.toml](../fixtures/sharing/valid/merged.toml)
- The `[targets.<id>]` layout from RFC drafts, rejected: [fixtures/sharing/invalid/legacy-targets-table.toml](../fixtures/sharing/invalid/legacy-targets-table.toml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-28 | Initial spec from accepted [RFC 0005](../rfcs/0005-sharing-system.md). Integration blocks are top-level arrays (`[[misp]]`) with per-block selection and `max_tlp`, merged by `name`. |
