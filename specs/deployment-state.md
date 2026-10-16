---
spec: deployment-state
version: "1.0"
schema_id: deployment.state::1.0
status: normative
supersedes: null
---

# Deployment state

## Summary

Microsoft Defender for Endpoint, SentinelOne, and CrowdStrike give every rule OpenTide creates an id of their own. The next deploy has to update, disable, or delete the remote rule by that id, and the id is per tenant. OpenTide keeps it in one committed JSON file per rule, `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`). It never stores it on the rule.

A platform block that still carries `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>` is invalid, and deploy refuses the rule. `opentide deploy migrate-state` moves the ids of an existing catalogue into shards once. Losing a shard, or never committing it, loses the only handle on the remote rule: the next deploy creates a second live rule beside the first. Every requirement below exists to prevent that.

This spec is the normative text of accepted [RFC 0010](../rfcs/0010-deployment-external-ids.md).

## Requirements

- Defender for Endpoint, SentinelOne, and CrowdStrike vendor identifiers MUST be stored only in `.opentide/states/deployment/<uuid>.json`. A platform block MUST NOT contain `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>`.
- `<uuid>` MUST be the lowercase canonical form of the rule's `metadata.uuid`, and `object_uuid` MUST equal the filename stem exactly.
- Tenant keys MUST be non-empty and MUST equal the configured tenant `name` with surrounding whitespace removed. A stored key with leading or trailing whitespace is invalid.
- External identifiers MUST be JSON strings. Defender and SentinelOne identifiers MUST match `0|[1-9][0-9]*`. CrowdStrike identifiers MUST contain a non-whitespace character and are otherwise stored verbatim.
- Writers MUST preserve unknown root keys, change only the addressed platform-and-tenant binding, sort keys at every level, use two-space JSON indentation, and write one trailing newline.
- Writers MUST remove an empty platform map and MUST delete a shard that holds no binding. A successful delete MUST remove the tenant binding, then an empty platform map, then the file when no binding remains. Readers MAY treat an empty `platforms` object and an empty platform map as no bindings.
- `.opentide/states/deployment/` MUST be committed. Implementations MUST NOT gitignore it, and MUST NOT gitignore the whole `.opentide/states/` directory.
- Whether deployment state is ignored MUST be evaluated with the repository's complete Git ignore semantics, including nested `.gitignore` files, parent-directory patterns, wildcards, negations, `.git/info/exclude`, and `core.excludesFile`. Implementations MUST NOT decide it by searching `.gitignore` text. A fail-safe false positive (reporting ignored when Git would not) is acceptable.
- Deploy MUST refuse a rule that carries a legacy external-id key on any platform block, on every deploy path, before any platform client is built and before any HTTP call (`external_id_in_rule`).
- Deploy MUST NOT create a remote rule for a state-backed platform unless the returned binding can be retained: not when deployment state is ignored (`deployment_state_ignored`), and not when the run cannot persist state (`deployment_state_unpersisted`).
- `DELETION` and `DISABLEMENT` without a binding MUST NOT call the vendor and MUST report `external_id_missing` at warning level.
- Deploy MUST NOT rediscover an id by listing remote rules or matching titles. The shard is the only record of what OpenTide created.
- A generated CI job MUST NOT create a state-backed remote rule unless that job publishes the returned binding to the default branch. The generated production job does so under [CI requirements 1–7](#continuous-integration); every other generated job MUST refuse the create before the vendor call (`deployment_state_unpersisted`).
- Generated production CI MUST meet [CI requirements 1–7](#continuous-integration).
- Status and reporting interfaces MUST read vendor identifiers from deployment state only. They MUST NOT reconstruct them from rule YAML. An unreadable shard MUST be surfaced with its `deployment_state_*` code.

## Definition

### Platforms and identity

A **state-backed platform** is one whose deployer addresses the remote rule by an id the vendor assigns at create time. Only state-backed platforms have entries in a shard.

| Platform | How deploy addresses the remote rule | Deployment state |
|----------|--------------------------------------|------------------|
| `defender_for_endpoint` | Graph detection-rule `id` returned on create | **Shard** |
| `sentinel_one` | STAR rule id returned on create | **Shard** |
| `crowdstrike` | Correlation rule id returned on create (`resources[0].id`) | **Shard** |
| `sentinel` | Analytics rule id is `metadata.uuid` | None |
| `splunk` | The saved search; no vendor-assigned id | None |
| `harfanglab` | Sigma id and YARA meta `id` are `metadata.uuid` | None |
| `carbon_black_cloud` | IOC id is `metadata.uuid`; the report is matched by title | None |
| `elastic` ([RFC 0007](../rfcs/0007-elastic-security-platform.md)) | Kibana `rule_id` is `metadata.uuid` | None. Elastic never stores external ids; Kibana's internal `id` is not recorded |

A later platform that needs a vendor-assigned id joins this table and the shard's platform set through a spec change. It MUST NOT gain an id field on its rule block.

### Paths

| Path | What it is | Committed? |
|------|------------|------------|
| `.opentide/states/deployment/<uuid>.json` | Vendor ids for one rule, per platform and tenant. An authoritative record. | **Yes.** MUST NOT be gitignored |
| `.opentide/states/sharing.jsonl` | Sharing cache ([sharing.md](sharing.md#workspace-paths)). Unchanged. | No. SHOULD be gitignored |
| `.opentide/inflight/<uuid>.json` | Preview overlay ([workspace.md](workspace.md#inflight-preview-shards)). Unchanged by this spec. | Unchanged |

One file per rule that has at least one binding. A rule never deployed to a state-backed platform has no file. Deploying a rule to Sentinel, Splunk, HarfangLab, Carbon Black Cloud, or Elastic MUST NOT create one.

A shard whose `object_uuid` is no longer in the object registry (an **orphan shard**) is retained. It is the handle for a remote rule that may still exist after its YAML was removed. No command deletes orphan shards automatically.

### Shard format

The file is UTF-8 JSON holding one object.

| Field | Required | Meaning |
|-------|----------|---------|
| `schema` | yes | The string `deployment.state::1.0`. |
| `object_uuid` | yes | `metadata.uuid` of the rule, lowercase canonical (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, hex digits `0-9a-f`). MUST equal the filename stem exactly. |
| `platforms` | yes | Map of state-backed platform identifier to a map of tenant key to external id. |

Inside `platforms`:

| Platform key | External id |
|--------------|-------------|
| `defender_for_endpoint` | Canonical decimal integer as a string: no sign, no leading zero (`"12345"`, `"0"`). |
| `sentinel_one` | Canonical decimal integer as a string. |
| `crowdstrike` | The create-response id, verbatim, as a string. MUST contain a non-whitespace character. It is not parsed as an integer. |

A platform key outside this table fails `deployment_state_platform`. A tenant key that is empty, or that has leading or trailing whitespace, fails `deployment_state_shape`. A non-string id, or an id that breaks its platform's pattern, fails `deployment_state_shape`. There is one binding per platform-and-tenant pair.

Root keys other than `schema`, `object_uuid`, and `platforms` are allowed. A writer MUST preserve them, so a newer field survives an older CLI.

The JSON Schema [schemas/deployment.state.1.0.schema.json](../schemas/deployment.state.1.0.schema.json) is a checker artifact for the file content. It cannot see the filename, so filename equality and the case rule below are checked by the reader, not by the schema.

### Canonical form

Writers MUST emit exactly this form. Readers MUST reject the violations named here.

| Rule | Writers | Readers |
|------|---------|---------|
| Filename stem and `object_uuid` are the lowercase canonical uuid, and equal | MUST | Reject with `deployment_state_uuid_mismatch` |
| Two shard files whose names differ only by case, or that canonicalise to the same uuid | MUST NOT produce | Reject with `deployment_state_uuid_mismatch`, fail closed: no create for that rule |
| Tenant keys non-empty and equal to their own whitespace-stripped form | MUST | Reject with `deployment_state_shape` |
| Keys sorted at every level, two-space indent, one trailing newline, UTF-8 | MUST | MAY accept other whitespace and key order |
| No empty platform map; no file with no binding | MUST | MAY treat empty maps as no bindings |

Lookup canonicalises before it reads: the shard for a rule is the file named by the lowercase canonical `metadata.uuid`, and the tenant key is the configured tenant `name` with surrounding whitespace removed. Before treating a rule's shard as absent, a reader MUST look for a file whose name matches the canonical name case-insensitively, and MUST fail closed if one exists.

### Writes

The writers are `opentide deploy` and `opentide deploy migrate-state` (and the CI replay in [requirement 5](#continuous-integration)). A hand edit is possible; the next write overwrites only the binding it addresses.

A writer MUST read the file, change one binding, and write the rest back unchanged. Create writes the binding only after the vendor returned an id. A failed create writes nothing. A successful delete removes the binding, then an empty platform map, then the file. Writes SHOULD be durable (written to a temporary file in the same directory, flushed, and renamed over the target).

### Deploy decisions

For `defender_for_endpoint`, `sentinel_one`, and `crowdstrike`, per rule and per tenant the deployment plan selected, deploy MUST decide in this order. "Create" means a strategy other than `DELETION` or `DISABLEMENT` with no binding. `DISABLEMENT` with a binding is an update that sets the vendor's disabled state. It keeps the binding.

| # | Situation | Code | Level | Result |
|---|-----------|------|-------|--------|
| 1 | A legacy key (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) at the root of **any** platform block of the rule | `external_id_in_rule` | error | The rule is refused on every path, before any client is built. No HTTP, no shard write. |
| 2 | The rule's shard is unreadable, names an unsupported platform, or fails the canonical-form rules | the shard's `deployment_state_*` code | error | The rule is refused for every state-backed platform. No HTTP. |
| 3 | Binding present | — | — | Update, disable, or delete. A delete removes the binding (then an empty platform map, then the file). |
| 3a | Binding present and deployment state ignored | `deployment_state_ignored` | warning | Proceed as row 3. |
| 4 | No binding, strategy `DELETION` or `DISABLEMENT` | `external_id_missing` | **warning** | No HTTP. Nothing is known to exist on that tenant. If a remote copy exists it MUST be removed by hand. |
| 5 | No binding, create, deployment state ignored | `deployment_state_ignored` | error | No HTTP. |
| 6 | No binding, create, the run cannot persist state | `deployment_state_unpersisted` | error | Refused before any HTTP call. |
| 7 | No binding, create, otherwise | — | — | Create, then write the binding. |
| 7a | The binding write fails after the vendor created the rule, or the binding removal fails after a successful delete | `deployment_state_write_failed` | error | The error MUST include the platform, tenant, and id. The remote rule MUST NOT be rolled back. |

Row 1 applies whatever platform is being deployed, including Sentinel, Splunk, HarfangLab, Carbon Black Cloud, and Elastic blocks, and on every path that can reach a vendor: `opentide deploy`, `deploy --dry-run`, a plan narrowed by `--platform`, `--skip-unconfigured`, `opentide validate query --live`, and direct deployer or MCP calls. Deploy MUST NOT read a legacy key as a binding. There is no dual read.

A dry run MUST NOT call the vendor and MUST NOT write a shard.

#### The run cannot persist state

A run **cannot persist state** when both hold:

- it runs in CI: Azure Pipelines (`TF_BUILD`), GitHub Actions (`GITHUB_ACTIONS`), or GitLab CI (`CI`), detected in that order; and
- its deployment plan (`opentide deploy --plan`, or `DEPLOYMENT_PLAN`) is anything other than `PRODUCTION` (`STAGING`, `FULL`, `ALWAYS`, `MANUAL`, `DEBUG`, …).

Only the generated production job commits shards ([CI](#continuous-integration)). A staging or pull-request run that created a remote rule would leave its id on the runner, and every rerun, and the production run after merge on an `ALWAYS` tenant, would create another copy.

A local run (no CI detected) may create; the operator commits the shard. `opentide deploy --persist-state-externally` lifts the `deployment_state_unpersisted` refusal for an operator who persists `.opentide/states/deployment/` by other means. Generated CI MUST NOT pass it. It does not lift `deployment_state_ignored`.

Updates, disablements, and deletes that have a binding are always allowed. Only creates are refused.

### Migration

`opentide deploy migrate-state` moves legacy ids from rule YAML into shards. It does not call a vendor API and does not deploy.

Legacy keys are read at the root of each platform block only, never inside `query`, `exclusions`, `alert`, or another nested key:

| Key | Shape |
|-----|-------|
| `rule_id::<tenant>` | scalar, integer or string (the line deploy used to write) |
| `rule_id` | map of tenant name to integer (Defender) |
| `rule_id_bundle` | map of tenant name to integer or string |

The command MUST:

1. **Refuse an ignored destination.** If deployment state is ignored, exit 1 with `deployment_state_ignored` and edit no rule. The message names the ignore source and the replacement: ignore `.opentide/states/sharing.jsonl` only. The command does not edit `.gitignore`.
2. **Scan every rule file**: every `.yaml` and `.yml` file under the configured rule directory, recursively, including subfolders deploy itself skips.
3. **Collect bindings** from the keys above on every platform block.
4. **Store state-backed bindings first.** For `defender_for_endpoint`, `sentinel_one`, and `crowdstrike`, copy each valid binding into the shard and make that write durable before the YAML changes. A crash between the two leaves both copies; they agree, and the next run strips the YAML.
5. **Drop every other platform's keys loudly.** For every other platform, including Sentinel, Splunk, HarfangLab, Carbon Black Cloud, and Elastic, remove the legacy key without storing it and emit `external_id_unused` (warning) with platform, tenant, value, and source file. Those deployers never read the value.
6. **Edit YAML surgically.** Delete the external-id lines and the `rule_id` / `rule_id_bundle` mapping blocks without rewriting the rest. Comments, key order, and unrelated whitespace stay. The edited document MUST parse to the original minus those keys, or the rule is left untouched.
7. **Leave a failing rule untouched.** On `external_id_shape`, `external_id_conflict`, `yaml_parse`, or `invalid_uuid`, that rule's YAML and shard are not modified. Other rules still migrate.

Value rules: integers become canonical decimal strings (`12345` and `"12345"` are the same id). A Defender or SentinelOne string with a sign or leading zero fails `external_id_shape` rather than being rewritten to a different integer. CrowdStrike strings are copied verbatim. A value that is not a string or integer, a `rule_id` / `rule_id_bundle` that is not a mapping, an empty tenant name, or an empty id fails `external_id_shape`. The same tenant bound twice on one platform, or bound to a different id than the shard already holds, fails `external_id_conflict`.

A migration is complete when the default branch contains, in one commit, every rule with its legacy keys removed, every new or changed shard, and a `.gitignore` that does not ignore `.opentide/states/deployment/`.

### Git policy

| Path | Policy |
|------|--------|
| `.opentide/states/deployment/` | MUST be committed. MUST NOT be gitignored. |
| `.opentide/states/sharing.jsonl` | SHOULD be gitignored. Regenerable cache. |
| `.opentide/states/` | MUST NOT be gitignored as a whole. |
| `.opentide/inflight/` | Unchanged until [specifications#31](https://github.com/OpenTideHQ/specifications/issues/31). |

`opentide setup` MUST write `.opentide/states/sharing.jsonl`, not `.opentide/states/`, as the ignore line for a new repository. Setup does not rewrite an existing `.gitignore`; `migrate-state` and the create guard are what stop an old ignore from hiding shards.

### Continuous integration

These requirements apply to the production deploy job that `opentide setup` and `opentide setup ci` generate for GitHub Actions, GitLab CI, and Azure Pipelines. That job runs `opentide deploy --plan PRODUCTION` on the default branch and is the only generated job that commits deployment state.

1. **Serialise production jobs.** GitHub Actions MUST set job-level `concurrency: {group: opentide-production-<branch>, cancel-in-progress: false}`. GitLab CI MUST set `resource_group: opentide-production`. Azure Pipelines MUST use the strongest serialisation available from YAML (`lockBehavior: sequential` on the production stage) and the generated file MUST state that Azure serialises the job only when an Exclusive Lock check is configured on the protected resource the stage uses. Without that check Azure cannot serialise from YAML; requirements 2 and 5 then bound the damage.
2. **Overlay the default-branch state before deploying.** Before the dry run and the deploy, the job MUST fetch the default branch and replace `.opentide/states/deployment/` in the working tree with the tip's copy. It MUST remove the directory first, so deletions on the tip hold, and MUST leave it absent when the tip has none. The tip descends from the triggering commit, so it already holds that commit's state plus every later production write-back.
3. **Write back whenever the deploy started**, including after a partial failure, a cancellation, or a timeout:
   - GitHub Actions: `if: ${{ always() && steps.deploy.outcome != 'skipped' }}`.
   - Azure Pipelines: `condition: and(always(), eq(variables['OPENTIDE_DEPLOY_STARTED'], 'true'))`, with the deploy step setting that variable before it runs.
   - GitLab CI: the write-back MUST run whenever the deploy started, including when it failed. It SHOULD run from `after_script`, gated on a marker the deploy step writes, so that it also runs for a cancelled or timed-out job where the GitLab instance and runner run `after_script` in those cases. Where the generated job cannot run it on cancellation or timeout (for example a combined script block), the generated file MUST say so in a comment; requirement 7 then keeps the ids in the job log.
4. **Stage state independently of rule files.** The job MUST stage every change under `.opentide/states/deployment/` unconditionally. It MUST commit a rule file the deploy changed (a promotion rewrites `status`) only if `opentide validate --strict` passes on exactly those files. The file list MUST be read NUL-delimited (`git diff -z --name-only`, read with `read -r -d ''` in bash), and `opentide validate --file` MUST fail when any given `--file` target matches no object. A rule file that fails validation is left out and the job fails after the state is pushed; it MUST NOT cost a shard. The commit message carries `[skip ci]`.
5. **Replay on conflict.** When the push is rejected because the default branch moved, the job rebases. If the rebase conflicts, the job MUST abort it, reset to the new tip, and replay this run's state delta per platform and tenant onto the tip's shards (`opentide deploy replay-state <state-commit>`), never by copying whole shard files. Bindings this run did not touch, and shards others deleted, keep the tip's value. When the same binding changed on both sides, the replay MUST keep this run's binding, report `deployment_state_conflict` with both values, publish the resulting state, and fail the job so an operator can remove the duplicate remote rule.
6. **Recover on every terminal failure.** Once the state commit exists, every terminal failure of the write-back (push retries exhausted, fetch failure, replay failure) MUST print the deployment-state diff of that commit and make a best-effort push of the commit to `refs/opentide/deployment-state/<commit>` (for example from a shell `trap` on `EXIT`), then fail the job. One ref per commit, so a later failure does not overwrite an earlier one.
7. **Ids in the log.** Every binding deploy records MUST be logged as `external_id_recorded` (platform, tenant, id, rule uuid) at `WARNING`, so it is visible at the default console level and the CI log holds every id even when the write-back never ran. `external_id_recorded` is a log record, not a diagnostic: it does not set `DEPLOYMENT_WARNING_RAISED` or change the exit code.

Staging, pull-request, and merge-request deploy jobs do not commit state. [Row 6](#deploy-decisions) refuses their creates.

### Other surfaces

| Surface | Requirement |
|---------|-------------|
| `opentide validate` | Reports `external_id_in_rule` from the schema check and suppresses the generic unknown-key error for the same field. Full-workspace validation validates every `*.json` file under `.opentide/states/deployment/`, orphan shards included. A missing shard is not an error. See [validation.md](validation.md). |
| MCP `deploy_rule` | Resets the deployment outcome flags before it runs. Reports `status: failed` with the error when the deployment outcome failed. |
| Status and reporting (CLI, MCP, exports) | Read ids from deployment state only, never from YAML. An unreadable shard is reported with its code. |

### Diagnostics

The complete catalogue. `yaml_parse` and `invalid_uuid` are the existing generic codes, used by migration.

| Code | Level | Raised by | Meaning and required behaviour |
|------|-------|-----------|--------------------------------|
| `external_id_in_rule` | error | validate, deploy | A legacy key at the root of any platform block. The rule is refused on every path before any client is built or HTTP call made. |
| `external_id_missing` | warning | deploy | `DELETION` or `DISABLEMENT` with no binding for the tenant. No HTTP. Sets `DEPLOYMENT_WARNING_RAISED`; does not fail the run. The message states that nothing is known to exist on that tenant and that a remote copy, if any, must be removed by hand. |
| `external_id_shape` | error | migrate-state | Invalid tenant or id shape on a legacy key. That rule and its shard are untouched. |
| `external_id_conflict` | error | migrate-state | The same tenant bound twice, or bound to a different id than the shard holds. That rule is untouched. |
| `external_id_unused` | warning | migrate-state | A legacy key removed from a platform that is not state-backed, and not stored. Carries platform, tenant, value, and file. |
| `deployment_state_ignored` | error before a create; warning for an update or delete with a usable binding; error in migrate-state | deploy, migrate-state | Git ignores `.opentide/states/deployment/`. |
| `deployment_state_unpersisted` | error | deploy | A create in a run that cannot persist state. Refused before any HTTP call. |
| `deployment_state_write_failed` | error | deploy | The vendor created or deleted the rule but the shard could not be updated. Includes the id. No rollback. |
| `deployment_state_uuid_mismatch` | error | validate, deploy, migrate-state | Filename and `object_uuid` disagree or are not lowercase canonical, or two shard files canonicalise to the same uuid. Fail closed: no create for that rule. |
| `deployment_state_platform` | error | validate, deploy, migrate-state | The shard names a platform that is not state-backed. |
| `deployment_state_shape` | error | validate, deploy, migrate-state | The shard is unreadable or violates `deployment.state::1.0`. |
| `deployment_state_conflict` | CI replay diagnostic | production write-back | The same binding changed concurrently. This run's binding is kept, both values are printed, the state is published, and the job fails. |
| `yaml_parse` | error | migrate-state | The rule file is not parseable YAML. That rule is untouched. |
| `invalid_uuid` | error | migrate-state | The rule has no valid `metadata.uuid`, so no shard can be named. That rule is untouched. |

### Exit semantics

| Command | Exit 0 | Exit 1 |
|---------|--------|--------|
| `opentide deploy` | Every selected rule deployed, or reported warnings only (`external_id_missing`, `deployment_state_ignored` on an update or delete). | Any selected rule reported an error-level code above. Deploy continues with independent rules first. |
| `opentide deploy migrate-state` | Successful migration, a clean idempotent run (no legacy keys, shards in place), or `external_id_unused` warnings only. | Any rule failed, or deployment state is ignored. |
| Production write-back | Everything committed and pushed, or nothing to commit. | Rule files left out, `deployment_state_conflict`, or a terminal failure of [requirement 6](#continuous-integration). |

## Relationships

- [RFC 0010](../rfcs/0010-deployment-external-ids.md) — accepted proposal
- [platforms/index.md](platforms/index.md) — platform blocks carry no external ids
- [platforms/defender-for-endpoint-1.0.md](platforms/defender-for-endpoint-1.0.md), [platforms/sentinel-one-1.0.md](platforms/sentinel-one-1.0.md), [platforms/crowdstrike-1.0.md](platforms/crowdstrike-1.0.md) — state-backed deploy tables
- [deployment.md](deployment.md) — status strategies
- [validation.md](validation.md) — `external_id_in_rule` and shard validation
- [workspace.md](workspace.md) — `.opentide/states/deployment/` and the production write-back
- [sharing.md](sharing.md) — the other occupant of `.opentide/states/`
- [RFC 0007](../rfcs/0007-elastic-security-platform.md) — Elastic identity by `metadata.uuid`

## Defaults & overrides

| Setting | Default | Override |
|---------|---------|----------|
| Shard directory | `.opentide/states/deployment/` | None |
| Create in CI under a plan other than `PRODUCTION` | Refused (`deployment_state_unpersisted`) | `opentide deploy --persist-state-externally` |
| Setup ignore line | `.opentide/states/sharing.jsonl` | Client `.gitignore`, which MUST NOT ignore `.opentide/states/deployment/` |
| Orphan shards | Retained | Removed by hand |

There is no configuration key for this spec.

## Examples

A rule bound on all three state-backed platforms, `.opentide/states/deployment/00000000-0000-4000-8003-000000000010.json`:

```json
{
  "object_uuid": "00000000-0000-4000-8003-000000000010",
  "platforms": {
    "crowdstrike": {
      "falcon-prod": "c5e1b2a0e4c84f0a9d3b7e6a1c8f0d22"
    },
    "defender_for_endpoint": {
      "contoso": "12345",
      "fabrikam": "67890"
    },
    "sentinel_one": {
      "s1-prod": "4242"
    }
  },
  "schema": "deployment.state::1.0"
}
```

A rule `migrate-state` must fix. Validate and deploy refuse it with `external_id_in_rule`:

```yaml
configurations:
  defender_for_endpoint:
    rule_id::Contoso: 12345
    enabled: true
    schema: platform::defender_for_endpoint::1.0
```

After migration the `rule_id::Contoso` line is gone, the rest of the file is byte-identical, and the shard holds `"defender_for_endpoint": {"Contoso": "12345"}`.

Fixtures: [fixtures/deployment/valid/](../fixtures/deployment/valid/) and [fixtures/deployment/invalid/](../fixtures/deployment/invalid/), checked by `scripts/deployment_state_fixtures.py`.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-10-16 | Initial normative deployment-state contract from accepted [RFC 0010](../rfcs/0010-deployment-external-ids.md). |
