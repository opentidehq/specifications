---
spec: visibility
version: "1.0"
schema_id: visibility::1.0
status: normative
supersedes: null
---

# Visibility

## Summary

`visibility.toml` describes what a workspace can see: the assets that produce logs, the log sources that hold them, and the external detectors that already cover parts of the environment. Objective signals name log sources (`signals[].data.logsources`).

A log source's `name` **is its dataset**: the KQL table for Sentinel and Defender for Endpoint, the sourcetype for Splunk, the index pattern for Elastic. A log source may list the dataset's columns, keyed by column name, and the query checks treat them like the columns of a table they ship.

## Requirements

### File

- The file MUST be `.opentide/configurations/visibility.toml` ([configuration.md](configuration.md)). Its top level MUST hold only `assets`, `logsources` and `detectors`, each an array of tables. `logsources` MUST be present.
- An implementation MUST accept a file that starts with a UTF-8 byte-order mark.

### Log sources

- A log source MUST set `name`, `description` and `system`, and MAY set `tenants`, `assets`, `references` and `columns`. Any other key MUST fail validation.
- `name` MUST NOT be empty or whitespace-only. Names MUST be unique per `system`; the same name MAY appear under two systems (`DeviceEvents` under `sentinel` and `defender_for_endpoint`).
- The opentide 0.20.0 keys `tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views` and `ecs` MUST fail validation with a message that names `opentide migrate visibility` ([Migration](#migration-from-opentide-0200)).

### Columns

- `columns` MUST be a table keyed by column name, as the platform spells it. Each value MUST be a table with `type`, from the system's type set ([Column types](#column-types)), and MAY set `description`. Any other key MUST fail validation.
- `columns` on a system with no type set MUST fail validation.
- Columns on a name with `*` apply to every dataset the name matches.

### Query checks

These requirements apply to every query check an implementation runs offline (`validate`, `validate query`, `lint`, the language server, the MCP server). Each MUST read the same `visibility.toml`, and an editor MUST re-read it when it changes.

- **What is declared.** `sentinel`, `defender_for_endpoint`: each `name` is a declared KQL table (or workspace function). `splunk`: a declared sourcetype. `elastic`: a declared index pattern or data stream. Other systems declare nothing. Splunk indexes and macros and Elastic data views are not declarable.
- **Opt-in.** Checking is opt-in per system: a system with at least one log source is checked against its names; a system with none MUST be checked as if nothing were declared.
- **Matching.** A name matches exactly, or as a glob where `*` matches any run of characters. KQL and Elastic names are case-sensitive; Splunk names are not.
- **KQL source names.** Every name a KQL query reads from (a pipeline's first source, a `union` leg, a `join` or `lookup` right side) that is not a `let` binding, a query parameter, or a function the engine knows MUST be resolved as below. Under opt-in, a name is checked whatever its case. Without opt-in, a name that starts with a lowercase letter is checked only when it ends in `_CL`.

| The name is | Opted in | Report |
|---|---|---|
| declared | yes | nothing |
| known to the implementation's catalog, not declared | yes | `kql_table_not_declared`, warning |
| known to the implementation's catalog | no | nothing |
| unknown to the catalog, not declared | either | `kql_unknown_table`, at the platform profile's severity: warning under `sentinel`, error under `defender_for_endpoint` |

- **Splunk and Elastic.** Under opt-in, a sourcetype that is not declared is `spl_dataset_not_declared`, and an index pattern that is not declared is `elastic_dataset_not_declared`, both warnings. Neither has an unknown-dataset error.
- **Declared columns, KQL.** An implementation MUST check column references against declared columns as it does for a documented table of its catalog: a near miss is `kql_unknown_column`, and an operator the declared type does not support is `kql_type_mismatch`. Hover MUST show a declared column's type and description; completion MUST offer the declared columns. On a table the catalog also knows, declared columns extend the catalog's, and a declared column with a catalog column's name replaces its type and description. A declared table without `columns` is known by name only.
- **Declared columns, Elastic.** Declared columns are fields the index pattern maps: an implementation MUST NOT report `ecs_unknown_field` for them and MUST use their declared type for `ecs_type_mismatch`.
- **Declared columns, Splunk.** Offered in hover and completion where the implementation has them; not checked.
- **Quick fix.** A fix that declares an undeclared name MUST append a new log source with `name` set to it, the system, and an empty `description` for the author to fill. It MUST NOT edit another log source.

### Signal references

- A signal's `data.logsources` entry MUST name a log source of the workspace: `<name>`, `<system>::<name>`, or `<system>::<tenant>::<name>`. A bare name that two systems declare refers to both.

## Definition

### `[[logsources]]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | The dataset: the KQL table for `sentinel` and `defender_for_endpoint`, the sourcetype for `splunk`, the index pattern or data stream for `elastic`; for other systems, a name. `*` matches any run of characters. Unique per `system`. Signals reference it. |
| `description` | string | yes | What the log source records. |
| `system` | string | yes | Platform identifier ([platforms/index.md](platforms/index.md)). |
| `tenants` | list[string] | no | Tenants of `system` that hold the logs. |
| `assets` | list[string] | no | Names of the `[[assets]]` that produce the logs. |
| `references` | list[string] | no | Reference links. |
| `columns` | table | no | The dataset's columns, keyed by column name as-is. |

### `[logsources.columns]` values

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | Column type, from the system's type set. |
| `description` | string | no | What the column holds. |

### Column types

| `system` | Types |
|----------|-------|
| `sentinel`, `defender_for_endpoint` | KQL scalar types: `bool`, `datetime`, `decimal`, `dynamic`, `guid`, `int`, `long`, `real`, `string`, `timespan` |
| `splunk` | `string`, `number`, `boolean` |
| `elastic` | Elasticsearch field types: `binary`, `boolean`, `byte`, `constant_keyword`, `date`, `date_nanos`, `double`, `flattened`, `float`, `geo_point`, `half_float`, `integer`, `ip`, `keyword`, `long`, `match_only_text`, `nested`, `object`, `scaled_float`, `short`, `text`, `unsigned_long`, `version`, `wildcard` |
| any other | none: `columns` is not allowed |

### `[[assets]]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Asset name, referenced by log sources and detectors. |
| `description` | string | yes | What the asset is. |
| `criticality` | string | yes | Criticality vocabulary value. |
| `surface` | list[string] | no | Threat surface vocabulary values the asset exposes. |
| `custom_details` | table | no | Free-form keys with string, boolean or number values. |

### `[[detectors]]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Detector name. |
| `description` | string | yes | What the detector covers. |
| `assets` | list[string] | no | Names of the assets the detector monitors. |
| `references` | list[string] | no | Reference links. |

A log source or detector that names an asset `[[assets]]` does not declare MUST be reported.

### Migration from opentide 0.20.0

opentide 0.20.0 let a log source list datasets under plural keys (`tables = ["A", "B"]`). An implementation SHOULD offer `opentide migrate visibility` (a dry run by default, `--apply` to write):

- Each name in `tables`, `sourcetypes` or `indices` becomes its own log source with that `name`, copying `description`, `system`, `tenants`, `assets` and `references`. `indexes`, `macros`, `data_views` and `ecs` are dropped, and the migration lists what it dropped.
- A log source with none of the plural keys is left unchanged.
- In objective files, a signal `data.logsources` reference to a migrated log source's old name becomes the names it was split into, all of them, in order. A log source that held only dropped keys is split into none, and references to it are removed.

## Relationships

- [configuration.md](configuration.md): `visibility.toml` is a configuration file; package defaults and workspace overrides merge as described there. Arrays replace.
- [workspace.md](workspace.md): `visibility.1.0.schema.json` is the generated schema for this file.
- [objective-1.0.md](objects/objective-1.0.md), [objective-1.1.md](objects/objective-1.1.md): `signals[].data.logsources` names log sources.
- [platforms/index.md](platforms/index.md): platform identifiers for `system`.

## Defaults & overrides

The package default declares no log source. A workspace that declares none for a system is checked exactly as before this spec's query-check requirements: no `*_not_declared` warning is raised for that system.

## Examples

```toml
[[assets]]
name = "Contoso identity provider"
description = "Production identity provider"
criticality = "High"

[[logsources]]
name = "Contoso_Audit_CL"
description = "Administrative audit events from the Contoso connector"
system = "sentinel"
tenants = ["Production"]
assets = ["Contoso identity provider"]

[logsources.columns]
TimeGenerated = { type = "datetime" }
Actor_s = { type = "string", description = "UPN of the account that made the change" }
ResultCode_d = { type = "real" }

[[logsources]]
name = "WinEventLog:Security"          # splunk: name is the sourcetype
description = "Domain controller security log"
system = "splunk"

[logsources.columns]
EventCode = { type = "number" }

[[logsources]]
name = "logs-endpoint.events.*"        # elastic: name is the index pattern
description = "Endpoint telemetry"
system = "elastic"

[logsources.columns]
"process.name" = { type = "keyword" }
```

A signal names them:

```yaml
data:
  availability: Complete
  requirements: Contoso connector enabled
  logsources:
    - Contoso_Audit_CL
    - splunk::WinEventLog:Security
```

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-03 | First normative spec ([RFC 0013](../rfcs/0013-visibility-logsource-is-a-dataset.md), [#63](https://github.com/opentidehq/specifications/issues/63)). A log source's `name` is its dataset; optional `columns` keyed by column name; query-check semantics. The opentide 0.20.0 plural keys and `ecs` fail validation, with a migration. `schema_id` stays `visibility::1.0`. Corrected before any implementation released the 2026-11-02 draft of this spec (singular dataset keys, `[[logsources.columns]]`). |
