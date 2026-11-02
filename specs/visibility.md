---
spec: visibility
version: "1.0"
schema_id: visibility::1.0
status: normative
supersedes: null
---

# Visibility

## Summary

`visibility.toml` describes what a workspace can see: the assets that produce logs, the log sources that hold them, and the external detectors that already cover parts of the environment. Objective signals name log sources (`signals[].data.logsources`), and the query checks use the datasets the log sources declare to know a workspace's own tables, indexes and index patterns, and the columns they hold.

A log source is **one dataset**: one table, one Splunk index or sourcetype, one Elastic index pattern or data view. It may list that dataset's columns, with their type and description, and the query checks treat them like the columns of a table they ship.

## Requirements

### File

- The file MUST be `.opentide/configurations/visibility.toml` ([configuration.md](configuration.md)). Its top level MUST hold only `assets`, `logsources` and `detectors`, each an array of tables.
- `logsources` MUST be present. `assets` and `detectors` MAY be omitted.
- An implementation MUST accept a file that starts with a UTF-8 byte-order mark.

### Log sources

- A log source MUST set `system` to a platform identifier ([platforms/index.md](platforms/index.md)).
- A log source MUST declare **at most one dataset**, with the keys its `system` takes ([Datasets](#datasets)). A dataset key that does not fit the log source's `system`, a second dataset on the same entry, or an empty or whitespace-only dataset name MUST fail validation.
- `name` MAY be omitted. It then defaults to the dataset (the `table`, `macro`, `data_view` or `index` value; for a Splunk `index` with a `sourcetype`, `<index>:<sourcetype>`). A log source with neither a `name` nor a dataset MUST fail validation.
- Log source names MUST be unique per `system`. The same name MAY appear under two systems (`DeviceEvents` under `sentinel` and `defender_for_endpoint`).
- A dataset MUST be declared at most once per `system`.
- The plural dataset keys `tables`, `indexes`, `sourcetypes`, `macros`, `indices` and `data_views` are not part of `visibility::1.0`. A log source that sets one MUST fail validation, with a message that names the singular key and the migration ([Migration](#migration-from-the-plural-keys)).

### Columns

- A log source MAY list its dataset's columns in `columns`. A log source with `columns` MUST declare a dataset, and that dataset MUST NOT contain `*`.
- Each column MUST set `name` and `type`. `name` is the column name as the platform spells it, kept as written; it MUST NOT be empty. `type` MUST be one of the types of the log source's system ([Column types](#column-types)). `description` is optional.
- Column names MUST be unique within a log source.

### Query checks

These requirements apply to every query check an implementation runs offline (`validate`, `validate query`, `lint`, the language server, the MCP server). Each MUST read the same `visibility.toml`, and an editor MUST re-read it when it changes.

- **Opt-in.** Checking a query against declared datasets is opt-in per system and dataset kind (KQL table; Splunk index, sourcetype, macro; Elastic index, data view). A system and kind with no declared dataset MUST be checked as if `visibility.toml` declared nothing.
- **Matching.** A declared name matches a query's name exactly, or as a glob where `*` matches any run of characters. KQL and Elastic names are case-sensitive; Splunk names are not.
- **KQL source names.** Every name a KQL query reads from (a pipeline's first source, a `union` leg, a `join` or `lookup` right side) that is not a `let` binding, a query parameter, or a function the engine knows MUST be resolved as below, whatever its case. Without opt-in, an implementation MAY leave unchecked a name that starts with a lowercase letter and does not end in `_CL`, as it may be a workspace function; with opt-in, a workspace function MUST be declared as a table.

| The name is | KQL tables opted in | Report |
|---|---|---|
| declared | either | nothing |
| known to the implementation's catalog, not declared | yes | `kql_table_not_declared`, warning |
| known to the implementation's catalog | no | nothing |
| unknown to the catalog, not declared | either | `kql_unknown_table`, with the severity of the platform profile: warning under `sentinel`, error under `defender_for_endpoint`. With opt-in its help names the declaration. |

  Splunk (`spl_dataset_not_declared`) and Elastic (`elastic_dataset_not_declared`) follow the same table for their kinds; neither has an unknown-dataset error.

- **Declared columns.** For a declared KQL table with `columns`, an implementation MUST check column references against them as it does for a documented table of its own catalog: a near miss of a declared column is `kql_unknown_column`, and an operator the declared type does not support is `kql_type_mismatch`. Hover MUST show a declared column's type and description, and completion MUST offer the declared columns.
- **Declared columns on a known table.** When a declared KQL table is also in the implementation's catalog, its declared columns extend the catalog's. A declared column with the name of a catalog column replaces that column's type and description.
- A declared table **without** `columns` is known by name only: its columns are not checked.
- For Elastic, declared columns are fields the index pattern maps: an implementation MUST NOT report `ecs_unknown_field` for them, and MUST use their declared type for `ecs_type_mismatch`. For Splunk, declared columns are offered in hover and completion and are not checked.
- A fix that declares a name MUST add a new log source for it. It MUST NOT add the name to an existing log source.

### Signal references

- A signal's `data.logsources` entry MUST name a log source of the workspace: `<name>`, `<system>::<name>`, or `<system>::<tenant>::<name>`. A bare name that two systems declare refers to both.

## Definition

### `[[logsources]]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | no | Log source name, unique per `system`. Default: the dataset. Signals reference it. |
| `description` | string | no | What the log source records. |
| `system` | string | yes | Platform identifier of the system that holds the logs. |
| `table` | string | no | `sentinel`, `defender_for_endpoint`: the KQL table or workspace function. |
| `index` | string | no | `splunk`: the index, as `index=` names it. `elastic`: the index pattern or data stream, as a rule's `index` names it. |
| `sourcetype` | string | no | `splunk`: the sourcetype, as `sourcetype=` names it. |
| `macro` | string | no | `splunk`: a macro that searches the logs, without backticks. |
| `data_view` | string | no | `elastic`: the data view id, as `data_view_id` names it. |
| `ecs` | bool | no | `elastic`: the `index` follows the Elastic Common Schema. |
| `columns` | list[Column] | no | The dataset's columns. |
| `tenants` | list[string] | no | Tenants of `system` that hold the logs. |
| `assets` | list[string] | no | Names of the `[[assets]]` that produce the logs. |
| `references` | list[string] | no | Reference links. |

### Datasets

| `system` | One dataset is | Keys |
|----------|----------------|------|
| `sentinel`, `defender_for_endpoint` | a table | `table` |
| `splunk` | an index, a sourcetype, or both together; or a macro | `index` and/or `sourcetype`, or `macro` alone |
| `elastic` | an index pattern or a data view | `index` (with optional `ecs`), or `data_view` |
| any other | none | — |

A Splunk `index` with a `sourcetype` is one dataset, the sourcetype within that index; each name is matched as its own kind. `*` is allowed in any dataset name.

### `[[logsources.columns]]` (Column)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Column name, as-is. |
| `type` | string | yes | Column type, from the system's type set. |
| `description` | string | no | What the column holds. |

### Column types

| `system` | Types |
|----------|-------|
| `sentinel`, `defender_for_endpoint` | KQL scalar types: `bool`, `datetime`, `decimal`, `dynamic`, `guid`, `int`, `long`, `real`, `string`, `timespan` |
| `splunk` | `string`, `number`, `boolean` |
| `elastic` | Elasticsearch field types: `binary`, `boolean`, `byte`, `constant_keyword`, `date`, `date_nanos`, `double`, `flattened`, `float`, `geo_point`, `half_float`, `integer`, `ip`, `keyword`, `long`, `match_only_text`, `nested`, `object`, `scaled_float`, `short`, `text`, `unsigned_long`, `version`, `wildcard` |

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

### Migration from the plural keys

opentide 0.20.0 shipped plural dataset lists on one log source (`tables = ["A", "B"]`). They grouped datasets arbitrarily and had no place for columns; `visibility::1.0` is corrected in place to one dataset per log source. An implementation SHOULD offer a mechanical migration:

- Each name in a plural list becomes its own log source with the singular key, copying the entry's `system`, `description`, `tenants`, `assets` and `references`. Splunk `indexes` and `sourcetypes` become separate log sources; Elastic `ecs` is copied to each `index`.
- A log source that held a single dataset keeps its `name`. One that held several is replaced by log sources named after their datasets.
- A signal `data.logsources` reference to a log source that was split SHOULD be replaced by the names of the log sources it was split into.

## Relationships

- [configuration.md](configuration.md): `visibility.toml` is a configuration file; package defaults and workspace overrides merge as described there. Arrays replace.
- [workspace.md](workspace.md): `visibility.1.0.schema.json` is the generated schema for this file.
- [objective-1.0.md](objects/objective-1.0.md), [objective-1.1.md](objects/objective-1.1.md): `signals[].data.logsources` names log sources.
- [platforms/index.md](platforms/index.md): platform identifiers for `system`.

## Defaults & overrides

The package default declares no dataset. A workspace that declares none is checked exactly as before this spec's query-check requirements: no `*_not_declared` warning is ever raised.

## Examples

```toml
[[assets]]
name = "Contoso identity provider"
description = "Production identity provider"
criticality = "High"

[[logsources]]
name = "Contoso audit log"
description = "Administrative audit events from the Contoso connector"
system = "sentinel"
table = "Contoso_Audit_CL"
tenants = ["Production"]
assets = ["Contoso identity provider"]

[[logsources.columns]]
name = "TimeGenerated"
type = "datetime"

[[logsources.columns]]
name = "Actor_s"
type = "string"
description = "UPN of the account that made the change"

[[logsources.columns]]
name = "ResultCode_d"
type = "real"

# A built-in table, declared by name only; `name` defaults to "SigninLogs".
[[logsources]]
system = "sentinel"
table = "SigninLogs"

[[logsources]]
name = "Windows security events"
system = "splunk"
index = "wineventlog"
sourcetype = "WinEventLog:Security"

[[logsources.columns]]
name = "EventCode"
type = "number"

[[logsources]]
name = "Endpoint telemetry"
system = "elastic"
index = "logs-endpoint.events.*"
ecs = true
```

A signal names them:

```yaml
data:
  availability: Complete
  requirements: Contoso connector enabled
  logsources:
    - Contoso audit log
    - SigninLogs
```

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-02 | First normative spec ([RFC 0013](../rfcs/0013-visibility-one-dataset-per-logsource.md), [#63](https://github.com/opentidehq/specifications/issues/63)). Corrects the plural dataset lists opentide 0.20.0 shipped: one dataset per log source, optional `columns`, query-check semantics. `schema_id` stays `visibility::1.0`. |
