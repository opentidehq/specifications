# RFC 0013: A log source is a dataset, with its columns

- **RFC:** 0013
- **Title:** A log source is a dataset, with its columns
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-02
- **Revised:** 2026-11-03, after maintainer review of [#64](https://github.com/opentidehq/specifications/pull/64)
- **Issue:** [opentidehq/specifications#63](https://github.com/opentidehq/specifications/issues/63)
- **Implementation:** [opentidehq/opentide#718](https://github.com/opentidehq/opentide/issues/718), [opentidehq/language-server#146](https://github.com/opentidehq/language-server/issues/146), release [opentidehq/opentide#722](https://github.com/opentidehq/opentide/issues/722)

## Summary

`visibility.toml` gets its first normative spec, [visibility.md](../specs/visibility.md). A `[[logsources]]` entry's `name` is its dataset: the KQL table for Sentinel and Defender for Endpoint, the sourcetype for Splunk, the index pattern for Elastic. It may list the dataset's columns as a table keyed by column name, each with a `type` and optional `description`. The query checks use declared columns the way they use the columns of the tables they ship.

This corrects `visibility::1.0` in place. It does not open `visibility::1.1`.

## Motivation

opentide 0.20.0 ([opentide#695](https://github.com/opentidehq/opentide/issues/695)) let a log source list datasets: `tables = ["A", "B", "C"]`. No spec described the file, so the shape was never reviewed against what a log source is. Used on a 199-rule production Sentinel catalogue, it fails in two ways:

1. **The grouping is arbitrary.** Declaring the 56 tables the rules read meant inventing groups ("Custom tables", "Cloud provider connectors"). Signals reference log sources by name, so those invented groups become what a signal says it depends on.
2. **A dataset cannot say what it holds.** A declared table is known by name only. Its columns are never checked, hovered or completed, though the workspace knows them exactly.

A log source is one dataset in every system opentide supports. Its name should be that dataset, and its entry is the natural place for its columns.

## Detailed design

See [visibility.md](../specs/visibility.md). In short:

- Keys: `name` (the dataset), `description`, `system`, `tenants`, `assets`, `references`, `columns`. Nothing else. `name` is unique per `system`.
- `columns` is a table keyed by column name as-is; each value has `type` from the system's type set (KQL scalar types, Elasticsearch field types, Splunk `string`/`number`/`boolean`) and optional `description`. Other systems take no columns.
- Query checks are opt-in per system. Splunk declares sourcetypes only and Elastic index patterns only; Splunk indexes and macros and Elastic data views are not declarable. An undeclared name the implementation does not know keeps `kql_unknown_table` at its profile's severity (0.20.0 downgraded it to the `kql_table_not_declared` warning once any table was declared, so a Defender typo stopped failing validation), and under opt-in a KQL name is checked whatever its case.
- The 0.20.0 keys (`tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views`, `ecs`) fail validation. No migration command is provided: opentide is pre-1.0, and a workspace rewrites the file (one log source per table, sourcetype or index pattern) by hand or with an agent.

## Why in place, not `visibility::1.1`

The plural lists shipped in opentide 0.20.0 on 2026-11-02 and are corrected in 0.20.1. They were a defect of an unspecified format, not a reviewed revision that users adopted. Keeping both shapes would carry the arbitrary grouping forward indefinitely. The cost is that a 0.20.0 file with plural lists fails validation in 0.20.1; the failure says what replaces the key. opentide is pre-1.0, so there is no migration command: the file and the signals that reference it are rewritten by hand or by an agent.

## Alternatives considered

- **Singular dataset keys per system** (`table`, `index`, `sourcetype`, `macro`, `data_view`, plus `ecs`, a defaulted `name`, and Splunk index-and-sourcetype pairs). The 2026-11-02 draft of this RFC. Rejected in maintainer review as over-engineered: `name` already is the dataset, and a second key restating it adds per-system key rules, defaulting and uniqueness checks for no gain.
- **Keep the lists and add `[logsources.columns.<table>]`.** Columns keyed by table inside a group would work mechanically, but keeps the meaningless grouping as the thing signals reference.
- **A separate `[[datasets]]` array, with log sources referencing datasets.** Two levels for what is one thing in every supported system.
- **Columns only for KQL.** Elastic and Splunk datasets have fields too; the same entry shape covers them, with each system's type set.

## Unresolved questions

- Importing columns from a platform (`opentide` reading a Sentinel workspace's table schema) is out of scope.
