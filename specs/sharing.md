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
- Every block MUST set `max_tlp`. There is no default ceiling. A block MUST NOT share an object whose `metadata.tlp` exceeds that value, including TLP:RED when the ceiling is below `red`.
- Bundled defaults MUST ship with no enabled block.
- `opentide share` with no subcommand MUST mean `push`. Implementations MUST provide `push`, `preview`, `status`, `retract`, and `targets`.
- MISP MUST NOT be added to the [platforms](platforms/index.md) capability matrix and MUST NOT appear as `configurations.misp` on `rule::1.0`.
- Scope filters and target selection that match nothing MUST fail with `scope_no_match`. A `--changed` run whose diff is empty, and a `--changed` run with no enabled block, MUST exit 0 instead.
- Secrets MUST NOT appear in logs, reports, preview payloads, or share state. API keys, authorization header values, and values substituted from `${ENV_VAR}` MUST be replaced with a fixed redaction marker. URLs and organisation UUIDs are not credentials and MUST be emitted unredacted.
- `opentide setup` and `opentide setup ci` MUST offer a sharing stage. The stage defaults off. When selected, it MUST run only on a push to the default branch, and its command MUST be `opentide share push --changed`. The generated pipeline MUST NOT run `opentide share` on a pull request or a merge request.
- Connectors without `pull` MUST NOT advertise import.

## Definition

### Sharing is not deployment

| Concern | Command | Config | Destination |
|---------|---------|--------|-------------|
| Detection runtime | `opentide deploy` | `deployment.toml`, `platforms/*.toml` | SIEM / EDR |
| Intelligence publication | `opentide share` | `sharing.toml` | CTI platforms (MISP first) |

### Surfaces

Four surfaces share `sharing.toml` and `.opentide/states/sharing.jsonl`.

| Surface | Operator entry | Remote write |
|---------|----------------|--------------|
| Configuration | `sharing.toml` | None |
| CLI | `opentide share` | `push` and `retract` write. `preview`, `status`, and `targets` do not. |
| CI stage | `share` in the pipeline written by setup | `push --changed` on a production release, and only when the stage was selected |
| Setup | `opentide setup`, `opentide setup ci` | None. Setup writes the pipeline. It does not write `sharing.toml` and it does not ask for API keys. |

**Production release.** A push to the repository default branch. This is the event `opentide deploy --plan PRODUCTION` already uses.

**Sharing stage.** The optional pipeline unit named `share`. It is absent unless setup selects it. Block `enabled` and the sharing stage are separate switches: an enabled block does not add the stage, and a selected stage with no enabled block exits 0.

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
| `name` | string | yes | — | Identifier used by `--target`, the share report, and the state ledger. 1–64 characters of lowercase letters, digits, hyphen, and underscore. |
| `enabled` | bool | no | `false` | Participate in share runs. |
| `max_tlp` | string | yes | — | A `tlp` vocabulary `name`. Objects above this ceiling are `skipped_tlp`. Order: `clear` < `green` < `amber` < `amber+strict` < `red`. |
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
| `opentide share preview` | Build payloads and apply selection and TLP; print the share report. Write nothing, locally or remotely (`push --dry-run`) |
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
| `--publish` / `--no-publish` | Override the block's `publish` for this run. |
| `--workers` | Optional parallelism across HTTP upserts. MUST NOT change any object's outcome. |
| `--changed` | On `push`: share only the object files in the production diff. See [Continuous integration](#continuous-integration). |

CLI filters narrow a block's selection. They never widen it. An unmatched `--target` and an empty resolved block set are `scope_no_match`. A `--changed` run with an empty diff, or with no enabled block, exits 0.

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

### Setup

Setup decides whether the pipeline contains the sharing stage. It does not publish.

| Entry | Selection | Default |
|-------|-----------|---------|
| `opentide setup` wizard, once a CI platform is chosen | Checkbox under "CI workflow features": "Sharing on the default branch" | Off |
| `opentide setup --ci <github\|gitlab\|azure>` | `--sharing` / `--no-sharing` | `--no-sharing` |
| `opentide setup ci <github\|gitlab\|azure>` | `--sharing` / `--no-sharing` | `--no-sharing` |

The wizard MUST show that checkbox only after a CI platform is selected. "Configure later" MUST NOT ask and MUST NOT write a pipeline. `--sharing` without a CI platform MUST NOT write a pipeline and MUST warn that the flag was ignored, as `--no-staging` does today.

The wizard and the flags are one choice. A later run that does not select the stage MUST omit it when it rewrites the pipeline. Setup MUST NOT prompt for a URL, an API key, or a block `name`.

### Continuous integration

When the sharing stage is selected, `opentide setup` and `opentide setup ci` MUST add it to the workflow file that platform already uses:

| File | Platform | Unit |
|------|----------|------|
| `.github/workflows/opentide.yml` | GitHub Actions | Job `share` |
| `.gitlab-ci.yml` | GitLab CI | Stage `share`, job `share` |
| `azure-pipelines.yml` | Azure Pipelines | Stage `Share`, job `share` |

When the stage is not selected, those files MUST NOT contain `opentide share` and MUST NOT contain that stage or job.

| Platform | Run when | Do not run when |
|----------|----------|-----------------|
| GitHub Actions | `github.event_name` is `push`, and the ref is `refs/heads/<default branch>` | `pull_request` |
| GitLab CI | `CI_COMMIT_BRANCH` equals `CI_DEFAULT_BRANCH`, and `CI_PIPELINE_SOURCE` is not `merge_request_event` | a merge request pipeline |
| Azure Pipelines | `Build.SourceBranch` is `refs/heads/<default branch>`, and `Build.Reason` is not `PullRequest` | pull request validation |

The command MUST be `opentide share push --changed`. The generated files MUST NOT contain any other `opentide share` command.

The stage starts after generate has succeeded. It depends only on generate. Deploy jobs MUST keep their current dependencies. Adding the stage MUST NOT make deploy wait for share, and MUST NOT make share wait for deploy. The checkout MUST include the history the production diff needs. API keys come from the CI secret store. The generated file MUST NOT embed them.

`--changed` uses the commit range `opentide deploy --plan PRODUCTION` uses:

| Platform | Range |
|----------|-------|
| GitHub Actions | First parent of `HEAD` through `GITHUB_SHA` |
| Azure Pipelines | First parent of `HEAD` through `BUILD_SOURCEVERSION` |
| GitLab CI | `CI_COMMIT_BEFORE_SHA` through `CI_COMMIT_SHA` |

A repository's first commit has no parent. That diff is empty and the run exits 0. A parent that is not in the checkout is a preflight error and MUST NOT be reported as an empty diff.

The paths in that range are `.yaml` and `.yml` files whose parent directory is the configured threat, objective, or rule directory (`paths.objects.threat`, `paths.objects.objective`, `paths.objects.rule`). A file in a subdirectory of those folders is out of scope. Added paths, modified paths, and the destination of a rename are in scope. Deleted paths are not. Deleting an object file MUST NOT retract it.

An edit that does not touch those files, including an edit that only changes `sharing.toml`, is not in the diff. Sharing every other in-scope object is `opentide share push` without `--changed`.

`opentide share push --changed` during a pull request or merge request MUST fail preflight and MUST NOT contact the destination. `--changed` outside GitHub Actions (`GITHUB_ACTIONS`), GitLab CI (`CI` set, and not the other two), and Azure Pipelines (`TF_BUILD`) MUST fail preflight. Platform detection checks Azure, then GitHub, then GitLab.

`preview` is unchanged and is not part of this job. It remains the local dry run.

### Workspace paths

| Path | Purpose | Client-edited? |
|------|---------|----------------|
| `.opentide/configurations/sharing.toml` | Every integration block | Yes |
| `.opentide/states/sharing.jsonl` | Current synchronization ledger | No — generated |

There is no sharing export directory. `preview` prints the share report and writes no file.

`.opentide/states/` is the directory for generated synchronization ledgers. Sharing has exactly one, `sharing.jsonl`. A later subsystem (deployment, another sync) gets its own file there. Sharing itself does not grow more files when a new connector or a new sync state is added: both are further lines in this file.

The file is UTF-8 JSON Lines: one JSON object per line, no wrapping array. It is the **current** state of what was shared, not a history. A writer MUST keep at most one line per triple of `object_uuid`, `integration`, and `target`, rewriting the file to replace the previous line for that triple. A reader that finds a duplicate triple (a crash between write and replace) MUST keep the last line and ignore the earlier ones. A missing or empty file means no local state. Lines an implementation does not understand MUST be preserved when it rewrites the file, so a newer `state` value survives an older CLI.

| Field | Description |
|-------|-------------|
| `state` | Synchronization state. `synced` after a successful create or update. `retracted` after a successful unpublish; the remote record still exists. Further values MAY be added later. |
| `object_uuid` | Tide `metadata.uuid` |
| `object_schema` | `metadata.schema` |
| `object_version` | `metadata.version` at last successful share |
| `content_hash` | SHA-256 of the verbatim UTF-8 bytes of the emitted object document, lowercase hex |
| `integration` | Connector id (`misp`, later `opencti`) |
| `target` | Block `name` |
| `organisation_uuid` | Publishing organisation observed for the matched remote record |
| `remote_event_uuid` | Remote identifier assigned by the destination |
| `remote_event_id` | Remote numeric id, or explicit null when not observed |
| `published` | Whether the remote record is published |
| `shared_at` | ISO-8601 UTC timestamp of the write |

A skip or a failure MUST NOT add, change, or remove a line. `unchanged` leaves the line as it is. `retract --delete` removes the line. A lookup that finds no remote record discards the line.

The ledger is a regenerable cache. The connector's remote lookup wins on disagreement. Deleting the file changes no outcome except replacing `unchanged` with `updated`. Implementations SHOULD gitignore it.

```jsonl
{"state":"synced","object_uuid":"00000000-0000-4000-8003-000000000001","object_schema":"rule::1.0","object_version":1,"content_hash":"<hash>","integration":"misp","target":"misp-internal","organisation_uuid":"00000000-0000-4000-8aaa-000000000001","remote_event_uuid":"<uuid assigned by MISP>","remote_event_id":42,"published":false,"shared_at":"2026-09-28T11:00:00Z"}
```

### Connector contract

A connector spec MUST declare its integration key (the top-level array name), its `schema` id, the block keys it adds, and whether `push`, `preview`, `status`, `retract`, and `pull` are supported. Future connectors (OpenCTI, TAXII) get their own `sharing::<id>::1.0` specs and their own top-level array in `sharing.toml`.

## Relationships

- [sharing/misp-1.0.md](sharing/misp-1.0.md) — MISP connector `sharing::misp::1.0`, block `[[misp]]`
- [configuration.md](configuration.md) — merge order; `sharing.toml` is overridable
- [workspace.md](workspace.md) — generated sharing paths
- [validation.md](validation.md) — `sharing-config` check
- [metadata.md](metadata.md) — `metadata.tlp`, optional `metadata.pap`, `metadata.organisation`
- [platforms/index.md](platforms/index.md) — deployment targets; MISP is not in this matrix
- [RFC 0005](../rfcs/0005-sharing-system.md) — accepted proposal
- [RFC 0006](../rfcs/0006-sharing-ci.md) — production-merge sharing job

## Defaults & overrides

Bundled `sharing.toml` ships with no enabled block. A block MUST set `max_tlp`. A block that omits `object_types` or `rule_statuses` shares all three families and `PRODUCTION` rules only. Clients declare and enable blocks only in `.opentide/configurations/sharing.toml`.

## Examples

- Two MISP instances with different selections: [fixtures/sharing/valid/sharing.toml](../fixtures/sharing/valid/sharing.toml)
- Merge by `name`: [override.toml](../fixtures/sharing/valid/override.toml) applied to that file yields [merged.toml](../fixtures/sharing/valid/merged.toml)
- The `[targets.<id>]` layout from RFC drafts, rejected: [fixtures/sharing/invalid/legacy-targets-table.toml](../fixtures/sharing/invalid/legacy-targets-table.toml)

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-28 | [RFC 0006](../rfcs/0006-sharing-ci.md). Optional sharing stage, default off, runs `opentide share push --changed` only on a push to the default branch. |
| 1.0 | 2026-09-28 | Initial spec from accepted [RFC 0005](../rfcs/0005-sharing-system.md). Integration blocks are top-level arrays (`[[misp]]`) with per-block selection and a required `max_tlp`, merged by `name`. Share state is `.opentide/states/sharing.jsonl`. `preview` writes no files. |
