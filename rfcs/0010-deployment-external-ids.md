# RFC 0010: Deployment external ids

- **RFC:** 0010
- **Title:** Deployment external ids
- **Author:** Behemoth Security
- **Status:** accepted
- **Created:** 2026-09-30
- **Revised:** 2026-10-16 — renumbered to 0010; resolved CI persistence, staging creates, migration scope, deploy guards, canonical shard form, exit codes, and error semantics
- **Accepted:** 2026-10-16 — normative text in [specs/deployment-state.md](../specs/deployment-state.md) and the affected platform, workspace, deployment, validation, and sharing specs
- **Issue:** [#30](https://github.com/opentidehq/specifications/issues/30)
- **PR:** [#32](https://github.com/opentidehq/specifications/pull/32)
- **Implementation issue:** [opentide#396](https://github.com/opentidehq/opentide/issues/396)
- **Implementation PR:** [opentide#555](https://github.com/opentidehq/opentide/pull/555)
- **Deferred:** inflight moves to `.opentide/states/inflight/` in [#31](https://github.com/opentidehq/specifications/issues/31). This RFC does not move it.

## Summary

Vendor-assigned rule ids leave the rule file and move to `.opentide/states/deployment/<metadata.uuid>.json` (`deployment.state::1.0`). Each shard is the map from that rule to the external id of each tenant, for the platforms that assign an id opentide does not choose: Microsoft Defender for Endpoint, SentinelOne, and CrowdStrike. Deploy reads and writes the shard. It no longer splices `rule_id::<tenant>:` into the rule YAML.

`rule_id`, `rule_id_bundle`, and every `rule_id::<tenant>` key come off every platform block, including the HarfangLab and Carbon Black fields deploy never reads. Platform schema ids stay `platform::<identifier>::1.0`; only the spec documents' versions advance. `rule::1.0` stays `rule::1.0`. A rule that still contains those keys is invalid, and deploy refuses it before any client is built.

**Catalogues that already have those keys must migrate, and the migration has to land in git, or the next deploy creates a second live rule.** Defender, SentinelOne, and CrowdStrike do not address the remote rule by `metadata.uuid`. The YAML line is the only copy of the id. There is no compatibility read that keeps using the rule file once this lands.

The shard is only safe if every created id reaches the default branch. The generated production job therefore serialises, starts from the default branch's state, and commits every shard change even after a partial failure, a cancellation, or a timeout. A CI run that cannot commit state (any plan other than `PRODUCTION`) is refused a create before the vendor call. That closes [opentide#554](https://github.com/opentidehq/opentide/issues/554), where every staging rerun created another remote rule.

## Motivation

Deploy has to update a Defender custom detection, a SentinelOne STAR rule, or a CrowdStrike correlation rule on the id the vendor returned at create time. The id is per tenant: the same Tide rule deployed to two tenants has two ids. Nothing in the detection content is that id.

The implementation stores it on the rule and writes it back by splicing a line into the YAML. That has five consequences.

1. **The rule file is deployment state.** A create dirties a file authors treat as content. The diff mixes a vendor id with the detection change that triggered the deploy.
2. **The spelling deploy writes is illegal at validation.** Deploy writes `rule_id::<tenant>:`. Static validation does not run the loader that folds that alias, so the key is unknown and `opentide validate` fails the file deploy just wrote. The map forms `rule_id` and `rule_id_bundle` are the spellings validation accepts, and they are not the spelling the writer emits.
3. **Sharing publishes the id.** [RFC 0005](0005-sharing-system.md) carries the rule document verbatim. A `rule_id::<tenant>` line and a `rule_id_bundle` map travel to MISP with the rule. The id is an address on a tenant, not intelligence.
4. **The splice is brittle.** It matches a whole line, inserts four spaces regardless of indent, and on delete removes a line only when the text matches exactly, including the id's rendering. A map-form id, a different indent, or a doubled space survives a deletion and the next deploy updates or fails against a stale binding.
5. **Two platforms accept a field they ignore.** HarfangLab addresses Sigma and YARA rules by `metadata.uuid`. Carbon Black addresses the IOC by `metadata.uuid` and the report by title. Both still take `rule_id_bundle`, so the block looks like it reconciles an id.

Sharing already established `.opentide/states/` as the place for generated synchronization state (`.opentide/states/sharing.jsonl`). Deployment is the subsystem [specs/sharing.md](../specs/sharing.md) said would get its own state there. The record is one shard per rule, because the binding is per rule and per tenant, and because this record is not a cache.

Stakeholders:

- **Detection engineers** with Defender, SentinelOne, or CrowdStrike rules already in production. Their ids have to move, once, in a commit that contains both the stripped YAML and the new shards.
- **Catalogue reviewers** who currently see vendor ids in rule diffs, and who share rules outward.
- **Implementers (opentide)** who maintain three copies of the same write-back (Defender inline, SentinelOne and CrowdStrike through `ExternalIdHelper`) and a loader alias that exists to undo it.

## Research

Observed in opentide at `d01f8c16616ac477786203209fcc27b60a826b01`. This is what the shard replaces. It is not a behaviour to preserve past the migration.

### Who assigns the id

| Platform | How the next deploy finds the remote rule | Where the id lives today |
|----------|--------------------------------------------|--------------------------|
| `defender_for_endpoint` | Graph beta `id` from `POST /security/rules/detectionRules`. The client stores `int(response["id"])`. Update is `PATCH .../detectionRules/{id}`. Delete expects HTTP 204. | `configurations.defender_for_endpoint.rule_id`, a `dict[str, int]` keyed by tenant name. The writer emits `rule_id::<tenant>:`. |
| `sentinel_one` | STAR rule id returned by `create_update_detection_rule` (int). | `rule_id_bundle: dict[str, int]`. The writer emits `rule_id::<tenant>:`. |
| `crowdstrike` | `resources[0].id` from the create response (string). | `rule_id_bundle: dict[str, str]`. The writer emits `rule_id::<tenant>:`. |
| `sentinel` | Analytics rule id is `metadata.uuid` (`create_or_update` / `delete` `rule_id=`). | Nowhere. Nothing is written back. |
| `harfanglab` | Sigma id and YARA meta id are `metadata.uuid`. | `rule_id_bundle` is loaded and never read. |
| `carbon_black_cloud` | IOC id is `metadata.uuid`. The report is matched by title. | `rule_id_bundle` is loaded and never read. |
| `splunk` | Saved search. No vendor id in the block. | No field. |
| `elastic` ([RFC 0007](0007-elastic-security-platform.md), accepted, spec not yet a file) | Kibana `rule_id` is set to `metadata.uuid`. Kibana's internal `id` is never stored. | No write-back. This RFC does not change that decision. |

Tenant names are the map keys. SentinelOne and CrowdStrike look up `tenant_config.name.strip()`. Defender looks up the tenant name it was given. The written line uses that same string inside `rule_id::<tenant>:`.

### The two writers

SentinelOne and CrowdStrike call `ExternalIdHelper` in `src/opentide/deployment/utils.py`.

Insert, after the line whose text with one trailing colon removed equals the platform identifier (`sentinel_one`, `crowdstrike`):

```python
updated.append(f"    rule_id::{tenant_name}: {rule_id}\n")
```

The indent is four spaces, not the indent of the platform key. Remove deletes a line only when its stripped text is exactly `rule_id::{tenant_name}: {rule_id}`.

Defender does not use that helper. `defender_for_endpoint/deployer.py` duplicates it. Insert matches the line `defender_for_endpoint:` and appends `    rule_id::{tenant}: {rule_id}`. Delete matches `rule_id::{tenant}: {rule_id}`. On create the comment in the log is "write back the ID to the file".

A missing id on `DELETION` does not call the vendor. The deployer logs that the rule has to be removed by hand. That failure mode stays: without an id there is nothing to delete. The difference is where a present id is read from.

### The loader alias

`src/opentide/loading/platform_loader.py`:

- `_external_rule_id` returns `rule_id_bundle` immediately when that key is present, and otherwise folds every `rule_id::<tenant>` key into a dict. SentinelOne, CrowdStrike, HarfangLab, and Carbon Black use it.
- Defender folds `rule_id::<tenant>` first. It reads the `rule_id` map only when that fold is empty.

So the file deploy writes is the alias, and the file validation accepts is the map. [specs/platforms/index.md](../specs/platforms/index.md) 1.0 said a raw `rule_id::<tenant>` key fails `opentide validate`. Production rules that have been deployed carry the key validation rejects.

### Gitignore

`opentide setup` writes `.opentide/states/` as a single gitignore line (`src/opentide/cli/services/setup/repo.py`, `_write_gitignore`). That matches [specs/sharing.md](../specs/sharing.md): `sharing.jsonl` is a regenerable cache, and deleting it only turns a later `unchanged` into `updated`, because the connector finds the MISP Event by organisation plus object uuid.

A deployment shard is not that kind of file. Deleting it, or never committing it, drops the only Defender, SentinelOne, or CrowdStrike id. The next deploy creates a new remote rule beside the old one. `DELETION` then cannot see the original. The scaffold ignore has to narrow to `sharing.jsonl` before any shard is written.

### Inflight

CI writes `.opentide/inflight/<uuid>.json` (`inflight.shard::1.0`). Setup creates that directory and does not gitignore it. Moving it to `.opentide/states/inflight/` is [#31](https://github.com/opentidehq/specifications/issues/31), after this RFC, so the git policy for `.opentide/states/` is settled before a third occupant arrives. This RFC does not change the inflight path, the shard schema, or the `generate inflight` jobs.

### Sysdig

[Issue #8](https://github.com/opentidehq/specifications/issues/8) drafts a `rule_id_bundle` on `configurations.sysdig`, described as the same per-tenant map. RFC 0004 is still reserved and has no file here. When that RFC is written, a Sysdig-assigned id goes in the deployment shard. It does not go on the block.

## Detailed design

### 1. The shard

| Path | What it is | Committed? |
|------|------------|------------|
| `.opentide/states/sharing.jsonl` | Sharing cache. Unchanged. | No. Implementations SHOULD gitignore this file. |
| `.opentide/states/deployment/<uuid>.json` | Vendor id for one rule. | **Yes.** Implementations MUST NOT gitignore this directory. |
| `.opentide/inflight/<uuid>.json` | Preview overlay. Unchanged by this RFC. | Unchanged. |

`<uuid>` is `metadata.uuid` in lowercase canonical form. One file per rule that has at least one stored external id. A rule that has never been deployed to Defender, SentinelOne, or CrowdStrike has no file. Deploying that rule to Sentinel, Splunk, HarfangLab, Carbon Black, or Elastic does not create one.

The file is UTF-8 JSON, two-space indent, one trailing newline. Object keys are sorted at every level so a rewrite of one tenant does not reshuffle the others.

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

| Field | Required | Meaning |
|-------|----------|---------|
| `schema` | yes | The string `deployment.state::1.0`. |
| `object_uuid` | yes | Lowercase canonical UUID. MUST equal the filename stem exactly. A mismatch, or a non-canonical spelling of either, fails the rule with `deployment_state_uuid_mismatch` and deploy does not create a remote rule. |
| `platforms` | yes | Map of platform identifier to a map of tenant name to external id. |

The tenant name is the platform tenant `name`, with surrounding whitespace stripped. Lookup strips the same way. A stored tenant key MUST be non-empty and MUST equal its own stripped form; `" contoso "` fails `deployment_state_shape` instead of silently missing the lookup and creating a second rule. One binding per pair of platform and tenant. The external id is a JSON string, never a JSON number.

| Platform | `external_id` |
|----------|----------------|
| `defender_for_endpoint` | Canonical decimal integer, no sign and no leading zeroes (`12345`). This is the Graph detection-rule `id` the client stores with `int()`. |
| `sentinel_one` | Canonical decimal integer. The STAR rule id. |
| `crowdstrike` | The create-response id, verbatim, with at least one non-whitespace character. It is not parsed as an integer. |

A later platform that needs a vendor id is added to this table. It does not gain a field on its block. A platform key other than the three in the table fails `deployment_state_platform`.

Root keys other than the three above are preserved when a writer rewrites the file, so a newer field can survive an older CLI. Inside a platform object every key is a tenant name and every value is a string. A non-string tenant value fails `deployment_state_shape`.

Writers are `opentide deploy`, `opentide deploy migrate-state`, and the CI replay in [§6](#6-ci-persistence). A hand edit is possible and the next deploy overwrites the tenant entry it touches. Other tenants and other platforms in the same file stay as they were. A writer MUST read the file, change one tenant entry, and write the rest back. Create writes the entry only after the vendor returns an id. A failed create writes nothing. A successful delete removes that tenant entry, then the platform key when it has no tenants, then the file when `platforms` is empty.

#### Canonical form

A non-canonical shard is the quietest way to lose an id: an uppercase filename is never found by a lowercase lookup, so deploy would create a new lowercase shard and a duplicate remote rule. So writers MUST emit, and readers MUST enforce:

- The filename stem and `object_uuid` are the lowercase canonical uuid and are equal. Anything else is `deployment_state_uuid_mismatch`.
- Two shard files whose names differ only by case, or canonicalise to the same uuid, are `deployment_state_uuid_mismatch`. The reader fails closed: no create for that rule. Before treating a shard as absent, a reader looks for a case-insensitive match.
- Tenant keys are non-empty with no surrounding whitespace, or `deployment_state_shape`.
- Keys are sorted at every level, with a two-space indent and one trailing newline.

Readers MAY treat an empty `platforms` and an empty platform map as no bindings. Writers MUST remove an empty platform map and MUST delete a shard with no binding. The JSON Schema follows the reader: it accepts the empty maps, and the writer form is checked separately.

A shard whose `object_uuid` is no longer in the registry (an orphan) is kept. It is the only handle on a remote rule whose YAML was removed while the rule may still run.

### 2. Schema changes

No new `metadata.schema`. No new `platform::<identifier>::1.1`. The platform schema id stays `platform::<identifier>::1.0` on the existing spec file. Only the spec documents' `version` advances (to 1.1, with a history row). The break is that the keys below become invalid keys.

Minting `::1.1` would make every rule change its `schema:` line on top of the id migration. The identifier is already not a closed enum (legacy values such as `defender_for_endpoint::2.3` still validate). A new id would not tell an old file what to do with `rule_id::Contoso`. Removing the key does.

`rule::1.0` is unchanged. `configurations` stays a map of platform blocks.

#### Keys removed

| Platform | Spec | Removed from the block | After acceptance |
|----------|------|------------------------|------------------|
| `defender_for_endpoint` | [defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md) | `rule_id` (`map[string, int]`) and the loader alias `rule_id::<tenant>` | Create, update, and delete use the shard. |
| `sentinel_one` | [sentinel-one-1.0.md](../specs/platforms/sentinel-one-1.0.md) | `rule_id_bundle` (`map[string, int]`) and `rule_id::<tenant>` | Same. The requirement that bundle values are integers moves to the shard string pattern. |
| `crowdstrike` | [crowdstrike-1.0.md](../specs/platforms/crowdstrike-1.0.md) | `rule_id_bundle` (`map[string, string]`) and `rule_id::<tenant>` | Same. |
| `harfanglab` | [harfanglab-1.0.md](../specs/platforms/harfanglab-1.0.md) | `rule_id_bundle` and `rule_id::<tenant>` | Still addressed by `metadata.uuid`. The unused field is gone. Migration does not copy it into a shard. |
| `carbon_black_cloud` | [carbon-black-cloud-1.0.md](../specs/platforms/carbon-black-cloud-1.0.md) | `rule_id_bundle` and `rule_id::<tenant>` | IOC id remains `metadata.uuid`. Report match remains the title. The unused field is gone. Migration does not copy it into a shard. |

#### Keys that stay

| Platform | Identity after this RFC |
|----------|-------------------------|
| `sentinel` | `metadata.uuid` is the analytics rule id. No shard entry. |
| `splunk` | Saved search. No shard entry. |
| `harfanglab` | `metadata.uuid` on the Sigma rule and the YARA meta id. No shard entry. |
| `carbon_black_cloud` | `metadata.uuid` on the IOC; report title on the report. No shard entry. |
| `elastic` | [RFC 0007](0007-elastic-security-platform.md): Kibana `rule_id` is `metadata.uuid`; the internal id is not stored. No shard entry. Elastic never stores external ids, and its block never gains one. |

A legacy key on any of these platforms is invalid too (`external_id_in_rule`). Migration removes it without storing it ([§3](#the-command)).

#### Edits inside each platform spec

Acceptance edits the `::1.0` files in place, bumps each document's `version` to 1.1, and adds a history row. The field row, the requirement that names the field, and the deploy sentences that read or write it all go.

`defender-for-endpoint-1.0.md`:

- Summary no longer says the id is stored on the block.
- The requirement that `rule_id` may be omitted goes away with the field.
- The deploy table's `DISABLEMENT` row updates the bound rule with `isEnabled: false`; without a binding, deploy reports `external_id_missing` (warning) and makes no HTTP call.
- The deploy table's `DELETION` row deletes the bound rule and removes the binding after the delete succeeds; without a binding, `external_id_missing`.
- The other row updates when a binding exists, and otherwise creates and durably records the returned id in the shard. It does not write the rule file.

`sentinel-one-1.0.md` and `crowdstrike-1.0.md`: the same replacement of `rule_id_bundle` with the shard and the same three rows (STAR status `Disabled`; Falcon `inactive`). The CrowdStrike paragraph that recorded the deployer's reversed `active`/`inactive` mapping goes: [opentide#555](https://github.com/opentidehq/opentide/pull/555) fixes the mapping, and the spec states the shared strategy.

`harfanglab-1.0.md` and `carbon-black-cloud-1.0.md`: delete the field row and the requirements that say the bundle may be present and is not read. State that legacy keys are invalid and that migration removes them as `external_id_unused`. Deploy behaviour is otherwise the same text.

[platforms/index.md](../specs/platforms/index.md): replace [External rule ids](../specs/platforms/index.md#external-rule-ids) with the rule that no block carries a vendor id, a table of how each platform (Elastic included) is addressed, and a pointer at the deployment-state spec. The sentence that says loaders fold `rule_id::<tenant>` before the unknown-key check goes away with the alias. The Splunk loader aliases and the Defender `quarantine_files` alias stay.

[workspace.md](../specs/workspace.md): add the path to the `.opentide/` table and the example tree. State that `.opentide/states/deployment/` is generated and committed, that `.opentide/states/sharing.jsonl` stays a gitignored cache, and that `.opentide/states/` is never ignored whole. Add the production write-back to the CI jobs table. The inflight section stays on `.opentide/inflight/`.

[sharing.md](../specs/sharing.md): the sentence that a later subsystem gets its own file under `.opentide/states/` becomes: sharing owns the regenerable cache `sharing.jsonl`; deployment owns the committed shard directory; a further subsystem MUST say whether its state is a cache or an authoritative record and whether it is committed. Sharing's ledger fields are unchanged.

[deployment.md](../specs/deployment.md): one section. Update, disablement, and deletion for Defender, SentinelOne, and CrowdStrike require the binding; a create needs a destination that is not ignored and a run that can persist state. Strategies themselves do not change.

[validation.md](../specs/validation.md): the schema check reports `external_id_in_rule` and suppresses the generic unknown-key error for the same field. Full-workspace validation validates every shard, orphans included. A missing shard is not an error. Every `--file` target must match an object.

New [specs/deployment-state.md](../specs/deployment-state.md), `schema_id: deployment.state::1.0`, holding the shard format, canonical form, migration, git policy, deploy decisions, CI requirements, the diagnostic catalogue, and exit semantics. `schemas/deployment.state.1.0.schema.json` is the JSON Schema for the shard, on the same footing as `schemas/inflight.shard.1.0.schema.json`: a checker artifact, not a second normative source.

`SPECS.md`, `CHANGELOG.md`, `llms.txt`, and the site navigation (`site/meta.json`) gain the new spec and the new versions in the same change.

#### Fixtures

| Fixture | Expectation |
|---------|-------------|
| `fixtures/deployment/valid/<uuid>.json` | One shard with all three platforms, in the exact writer form: sorted keys, two-space indent, one trailing newline, string ids, integer ids in canonical decimal. |
| `fixtures/deployment/invalid/*.json` | One file per failure the checker can see: bad `schema`, filename / `object_uuid` mismatch, non-canonical (uppercase) uuid, JSON number instead of string, leading-zero Defender id, empty external id, whitespace around a tenant key (`deployment_state_shape`), and a shard naming `sentinel` (`deployment_state_platform`). |
| Existing `fixtures/platforms/*.yaml` | Stay valid. None of them carry `rule_id` or `rule_id_bundle`; the checker asserts it. |
| `fixtures/deployment/invalid/rule-with-rule-id*.yaml` | The `rule_id` map, the `rule_id::<tenant>` line, and a `rule_id_bundle` on HarfangLab each fail `external_id_in_rule`. They live under `fixtures/deployment/` so the object checker, which does not walk platform blocks, is not the thing that has to learn the code. |

`scripts/deployment_state_fixtures.py` checks them from `scripts/validate.py`, and `scripts/test_deployment_state_fixtures.py` unit-tests the checker, including the cases no fixture can hold on a case-insensitive file system (two shard names that differ only by case).

No vocabulary change. No change under `specs/objects/` or `schemas/pins/`.

### 3. Existing rules must migrate

This section is the upgrade. A catalogue that skips it and deploys with the new CLI does not "keep working".

Defender, SentinelOne, and CrowdStrike will not look up a remote rule by `metadata.uuid`, by display name, or by walking the tenant and guessing. The id written into the rule on the last create is the only handle. After the keys are illegal, that handle exists only in the shard. A deploy with neither the key nor the shard **creates a new remote rule** and leaves the previous one in place, still firing. `DELETION` of the original then reports `external_id_missing`, because the id was thrown away.

There is no dual-read. Deploy does not open the rule looking for `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>`. If any of those keys is present, on any platform block, deploy fails that rule with `external_id_in_rule` **before any platform client is built or HTTP call made**, whether or not a shard entry also exists. That holds on every path that can reach a vendor: `deploy`, `deploy --dry-run`, a plan narrowed by `--platform`, `--skip-unconfigured`, `validate query --live`, and direct deployer or MCP calls. Validate fails the same rule with the same code. The only command that reads the old keys is the migration.

```mermaid
flowchart TD
  start["opentide deploy, one rule, one tenant"] --> legacy{"rule still has rule_id, rule_id_bundle, or rule_id:: ?"}
  legacy -->|yes| stop["external_id_in_rule\nno HTTP, no shard write"]
  legacy -->|no| shard{"shard has this platform and tenant?"}
  shard -->|yes| upd["update, disable, or delete and drop the entry"]
  shard -->|no, deletion or disablement| missing["external_id_missing (warning)\nno HTTP"]
  shard -->|no, create| ignored{"deployment state gitignored?"}
  ignored -->|yes| refuse1["deployment_state_ignored\nno HTTP"]
  ignored -->|no| persist{"CI run under a plan other than PRODUCTION?"}
  persist -->|yes| refuse2["deployment_state_unpersisted\nno HTTP"]
  persist -->|no| create["create, then write the returned id into the shard"]
```

`DELETION` or `DISABLEMENT` with no shard entry does not create. It reports `external_id_missing` and does not call the vendor, which is today's missing-id path. It is a warning, not an error: nothing is known to exist on that tenant, so there is nothing opentide can act on, and a rule retired before it was ever deployed must not fail every later run. The message says that a remote copy, if one exists, has to be removed by hand. [§5](#5-what-deploy-does-with-the-shard) has the full table.

#### What has to be migrated

On every platform block, at the block root only (not inside `query`, `exclusions`, `alert`, or any other nested key):

| Key | Shape today | Where it shows up |
|-----|-------------|-------------------|
| `rule_id::<tenant>` | scalar, int or string | The line deploy actually writes. Validation already rejects it. |
| `rule_id` | map of tenant name to int | Defender's model field. Validation accepts it. |
| `rule_id_bundle` | map of tenant name to int or string | SentinelOne, CrowdStrike, HarfangLab, Carbon Black. |

Both of these Defender shapes are the same binding and both have to move:

```yaml
configurations:
  defender_for_endpoint:
    rule_id::Contoso: 12345
    enabled: true
    schema: platform::defender_for_endpoint::1.0
    query: |
      DeviceProcessEvents
      | where FileName =~ "cmd.exe"
```

```yaml
configurations:
  defender_for_endpoint:
    rule_id:
      Contoso: 12345
      Fabrikam: 67890
```

SentinelOne and CrowdStrike use `rule_id_bundle` or the same `rule_id::<tenant>` line. CrowdStrike values may be strings.

#### The command

`opentide deploy migrate-state` does the move. It does not call a vendor API and it does not deploy.

1. **Refuse a gitignored destination.** If Git ignores `.opentide/states/deployment/` (for example through a `.opentide/states/` line), the command exits `1` with `deployment_state_ignored` and **does not edit any rule**. "Ignored" is decided with Git's complete ignore semantics (see [§4](#4-git-policy)). The message names the ignore source and the replacement: ignore `.opentide/states/sharing.jsonl` only. Setup today writes the directory ignore, and it does not rewrite an existing `.gitignore`, so every existing workspace hits this until someone changes that line. The command does not edit `.gitignore` itself.
2. **Scan rule files.** Every `.yaml` and `.yml` file under the configured rule directory, recursively, including files in subfolders that deploy itself skips. An id in a nested file still has to move.
3. **Collect bindings** from the three keys above.
4. **Write the shard first**, for Defender, SentinelOne, and CrowdStrike only, and make that write durable before the YAML changes. A crash after the shard write and before the YAML edit leaves both copies. The next run sees that they agree and strips the YAML.
5. **Then remove the keys from the YAML** without rewriting the rest of the document. Comments, key order, and unrelated whitespace stay. The migration deletes the external-id lines and the `rule_id` / `rule_id_bundle` mapping blocks. It does not round-trip the file through a parser that drops comments.
6. **Leave a failing rule untouched.** The same tenant mapped twice, or mapped to a different id than the shard already holds, is `external_id_conflict` for that rule. A bad value is `external_id_shape`; an unparseable file is `yaml_parse`; a missing or invalid `metadata.uuid` is `invalid_uuid`. In every case that rule's YAML and that rule's shard are not modified. Other rules still migrate. The command exits `1`.
7. **Drop every other platform's keys loudly.** For every platform other than Defender, SentinelOne, and CrowdStrike, including Sentinel, Splunk, HarfangLab, Carbon Black Cloud, and Elastic, a `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>` is removed from the YAML and is **not** written to a shard. Those deployers never read the value; copying it into the shard would pretend it is a live address. Each discarded binding is printed as an `external_id_unused` warning (platform, tenant, value, source file) before the YAML is edited. The value remains in git history of the rule file.
8. **A clean second run is a success.** No legacy keys, shards already in place, exit `0`. `external_id_unused` warnings alone also exit `0`.

A value that is not a scalar string or int, a `rule_id` / `rule_id_bundle` that is not a mapping, an empty tenant name, an empty id, or a Defender or SentinelOne value that is not a canonical decimal integer fails that rule with `external_id_shape` and leaves it untouched.

Integer scalars are stored as canonical decimal strings. `12345` and `"12345"` become `"12345"`. A string with a leading zero fails `external_id_shape` on Defender and SentinelOne rather than being rewritten to a different integer. CrowdStrike strings are copied verbatim.

#### The commit

The migration is not finished when the command exits `0`. It is finished when the default branch contains, in the same commit:

- every rule with the legacy keys removed, and
- every new or updated file under `.opentide/states/deployment/`, and
- a `.gitignore` that does not exclude that directory.

A commit that strips the YAML and forgets the shards, or a shard directory that git never sees, is the duplicate-rule failure. `opentide deploy` MUST refuse to **create** a remote rule when the deployment-state directory is gitignored (`deployment_state_ignored`, error), including when the ignore is the existing `.opentide/states/` line. An update or delete that can read an existing binding still runs, and warns with the same code, so a tree that already has the files is not stuck while gitignore is fixed.

If the shard write fails after the vendor has created a rule, deploy reports `deployment_state_write_failed` and includes the platform, tenant, and id in that error. It does not delete the remote rule to roll the create back. The same code covers a binding that cannot be removed after a successful delete.

#### Worked example

Before, a file deploy has already spliced:

```yaml
configurations:
  defender_for_endpoint:
    rule_id::Contoso: 12345
    enabled: true
    schema: platform::defender_for_endpoint::1.0
    status: PRODUCTION
    query: |
      DeviceProcessEvents
      | where FileName =~ "cmd.exe"
```

After `migrate-state`, that line is gone and the rest of the file is unchanged. The new file `.opentide/states/deployment/00000000-0000-4000-8003-000000000010.json` holds:

```json
{
  "object_uuid": "00000000-0000-4000-8003-000000000010",
  "platforms": {
    "defender_for_endpoint": {
      "Contoso": "12345"
    }
  },
  "schema": "deployment.state::1.0"
}
```

The next deploy to tenant `Contoso` patches detection rule `12345`. It does not post a second rule. A deploy that runs on a checkout where this JSON is absent, and where the YAML line is already gone, posts a second rule.

### 4. Git policy

| Path | Policy |
|------|--------|
| `.opentide/states/sharing.jsonl` | SHOULD be gitignored. Cache. |
| `.opentide/states/deployment/` | MUST be committed. MUST NOT be gitignored. |
| `.opentide/states/` | MUST NOT be gitignored as a whole. |
| `.opentide/inflight/` | Unchanged until [#31](https://github.com/opentidehq/specifications/issues/31). |

`opentide setup` MUST stop writing `.opentide/states/` as an ignore rule. The ignore it writes for a new repository is `.opentide/states/sharing.jsonl`. Setup does not rewrite an existing `.gitignore`; `migrate-state` and the create guard are what stop an old ignore from hiding the shards.

Whether the shard directory is ignored MUST be decided with the repository's complete Git ignore semantics: nested `.gitignore` files, parent-directory patterns, wildcards, negations, `.git/info/exclude`, and `core.excludesFile`. Implementations MUST NOT decide it by searching `.gitignore` text, which misses `**/states/`, a global excludes file, and a negation that re-includes the directory. A fail-safe false positive (reporting ignored when Git would not) is acceptable; a false negative is the duplicate-rule failure.

### 5. What deploy does with the shard

For Defender, SentinelOne, and CrowdStrike, per tenant the deployment plan already selected, in this order:

| Situation | Code | Level | Result |
|-----------|------|-------|--------|
| Legacy key (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) on **any** platform block of the rule | `external_id_in_rule` | error | Rule refused on every path, before any client is built. No HTTP. |
| Shard unreadable, wrong platform, or not canonical (including a case-variant duplicate) | its `deployment_state_*` code | error | Rule refused. No HTTP. Fail closed: no create. |
| Binding present | — | — | Update, disable, or delete. Delete removes the binding, then an empty platform map, then the file. If the directory is ignored, `deployment_state_ignored` is a warning and the action still runs. |
| No binding, `DELETION` or `DISABLEMENT` | `external_id_missing` | **warning** | No HTTP. Sets `DEPLOYMENT_WARNING_RAISED`; does not fail the run. Nothing is known to exist on that tenant; a remote copy, if any, must be removed by hand. |
| No binding, create, shard directory gitignored | `deployment_state_ignored` | error | No HTTP. |
| No binding, create, **the run cannot persist state** | `deployment_state_unpersisted` | error | Refused before any HTTP call. |
| No binding, create, otherwise | — | — | Create, then write the binding. A write failure is `deployment_state_write_failed` (error, includes the id, no rollback). |

Disablement is an update that sets the vendor's disabled state, using the shard id. It does not remove the entry.

**The run cannot persist state** when it runs in CI (Azure Pipelines, GitHub Actions, or GitLab CI is detected) under any deployment plan other than `PRODUCTION`: `STAGING`, `FULL`, `ALWAYS`, `MANUAL`, `DEBUG`. Only the generated production job commits shards ([§6](#6-ci-persistence)). Before this rule, every pull-request rerun of `deploy --plan STAGING` created another Defender, SentinelOne, or CrowdStrike rule on the staging tenant, and a tenant with `deployment = "ALWAYS"` received one untracked staging copy and then a production copy after merge ([opentide#554](https://github.com/opentidehq/opentide/issues/554)). Documenting "use separate tenants and clean up by hand" would have kept the very duplicate this RFC exists to remove.

- A local run (no CI detected) may create. The operator commits the shard.
- `opentide deploy --persist-state-externally` lifts the refusal for an operator who persists `.opentide/states/deployment/` some other way. It is documented, opt-in, and never emitted by generated CI. It does not lift `deployment_state_ignored`.
- Updates, disablements, and deletes that already have a binding are always allowed.

Deploy continues with independent rules after a per-rule error and exits `1` if any selected rule reported an error-level code. Warnings alone (`external_id_missing`, `deployment_state_ignored` on an update or delete) exit `0`.

The shard is the record of what opentide created. It is not rebuilt by listing the tenant's rules and matching titles. A title match is how a renamed rule, or two rules with one name, would update the wrong remote object.

### 6. CI persistence

A created id that never reaches the default branch is a future duplicate. So the production job that `opentide setup` generates for GitHub Actions, GitLab CI, and Azure Pipelines (`opentide deploy --plan PRODUCTION` on the default branch) commits deployment state itself. It MUST:

1. **Serialise production jobs.** GitHub: job-level `concurrency: {group: opentide-production-<branch>, cancel-in-progress: false}` (superseded by deployment-state 1.1, [specifications#43](https://github.com/opentidehq/specifications/issues/43): GitHub cancels pending runs, so the production job has no concurrency group). GitLab: `resource_group: opentide-production`. Azure: the strongest serialisation available from YAML (`lockBehavior: sequential`), with the generated file stating that it only takes effect when an Exclusive Lock check is configured on the resource the stage uses.
2. **Overlay the default-branch tip's state before deploying.** Before the dry run and the deploy, fetch the default branch and replace `.opentide/states/deployment/` in the working tree with the tip's copy: remove the directory first so the tip's deletions hold, and leave it absent if the tip has none. The tip descends from the triggering commit, so it already contains that commit's state and every later production write-back. Without this, a job that starts on an older commit cannot see the ids a newer job recorded and creates them again.
3. **Write back whenever the deploy started**, including after a partial failure, a cancellation, or a timeout. GitHub: `if: ${{ always() && steps.deploy.outcome != 'skipped' }}`. Azure: `condition: and(always(), eq(variables['OPENTIDE_DEPLOY_STARTED'], 'true'))`. GitLab: the equivalent, preferably from `after_script` gated on a marker the deploy writes; where the job cannot run the write-back on cancellation or timeout, the generated file says so.
4. **Stage shards independently of rule files.** Every shard change is staged unconditionally. A rule file the deploy changed (promotion rewrites `status`) is committed only if `opentide validate --strict` passes on exactly those files. The file list is read NUL-delimited (`git diff -z --name-only`, `read -r -d ''`), and `opentide validate --file` fails when any `--file` target matches no object, so a path with a newline or an unmatched path cannot slip past validation. A rule file that fails is left out and the job fails after the state is pushed; it never costs a shard.
5. **Replay on conflict.** When the push is rejected and the rebase conflicts, abort the rebase, reset to the new tip, and replay this run's delta per platform and tenant (`opentide deploy replay-state <state-commit>`), never by copying shard files, which would revert other runs' bindings and resurrect deleted shards. When the same binding changed on both sides, keep this run's binding (the newest record of what it created), report `deployment_state_conflict` with both values, publish, and fail the job so an operator removes the duplicate remote rule.
6. **Recover on every terminal failure.** Once the state commit exists, every terminal failure (push retries exhausted, fetch failure, replay failure) prints the state diff and makes a best-effort push of the commit to `refs/opentide/deployment-state/<commit>` (a shell `trap` on `EXIT`), then fails. One ref per commit, so a later failure never overwrites an earlier one.
7. **Keep the ids in the log.** `external_id_recorded` (platform, tenant, id, rule) is logged at `WARNING`, visible at the default console level, so the CI log holds every id even if the write-back never ran. It is a log record, not a diagnostic, and does not change the exit code.

Staging, pull-request, and merge-request jobs do not commit state; §5 refuses their creates instead.

### 7. Other surfaces

- **Validation.** The schema check reports `external_id_in_rule` for a legacy key at the root of any platform block and suppresses the generic unknown-key error for the same field, so the author sees one actionable code. Full-workspace validation validates every `*.json` under `.opentide/states/deployment/`, orphans included, because an orphan shard is the only handle on a remote rule and a malformed one would otherwise go unnoticed. A missing shard is not an error.
- **MCP `deploy_rule`.** Resets the deployment outcome flags before it runs and reports `status: failed` with the error when the deployment outcome failed, instead of reporting success for a refused rule.
- **Status and reporting.** CLI, MCP, and exports read ids from deployment state only, never from YAML. An unreadable shard is reported with its `deployment_state_*` code.

### 8. Diagnostics and exit codes

| Code | Level | Behaviour |
|------|-------|-----------|
| `external_id_in_rule` | error | Legacy key on any platform block; rule refused on every validate and deploy path before any client or HTTP call. |
| `external_id_missing` | warning | `DELETION` or `DISABLEMENT` with no binding; no HTTP. |
| `external_id_shape` | migration error | Invalid tenant or id shape; that rule and shard untouched. |
| `external_id_conflict` | migration error | Duplicate binding, or disagreement with an existing shard; that rule untouched. |
| `external_id_unused` | warning | Legacy key removed from a platform that is not state-backed, not stored. |
| `deployment_state_ignored` | error before a create (and in `migrate-state`); warning for an update or delete with a usable binding | Git ignores the shard directory. |
| `deployment_state_unpersisted` | error | A create in a run that cannot persist state; refused before any HTTP call. |
| `deployment_state_write_failed` | error | The shard could not be updated after a successful create or delete; includes the id; no rollback. |
| `deployment_state_uuid_mismatch` | error | Filename and `object_uuid` disagree or are not canonical, or two files name one uuid. |
| `deployment_state_platform` | error | The shard names a platform that is not state-backed. |
| `deployment_state_shape` | error | The shard is unreadable or violates `deployment.state::1.0`. |
| `deployment_state_conflict` | CI replay diagnostic | Same binding changed concurrently; this run's kept, both printed, state published, job fails. |
| `yaml_parse`, `invalid_uuid` | migration errors | Existing generic codes; that rule untouched. |

`opentide deploy migrate-state` exits `0` after a successful migration, a clean idempotent run, or `external_id_unused` warnings only, and `1` if any rule fails or the deployment state is ignored. `opentide deploy` continues with independent rules and exits `1` if any selected rule reported an error-level code above.

## Drawbacks

- **The shard is a second file, and losing it duplicates production rules.** That is the cost of taking the id out of the only file people already commit. The migration command, the gitignore refusal, the persistence guard, the CI write-back, and the fail-closed deploy exist because of it.
- **Every deployed Defender, SentinelOne, and CrowdStrike rule needs a one-time commit.** Rules that only target Sentinel, Splunk, HarfangLab, Carbon Black, or Elastic have nothing to move.
- **Legacy keys on platforms that are not state-backed are deleted, not stored.** That covers HarfangLab and Carbon Black bundles and any stray key on Sentinel, Splunk, or Elastic. They were not addresses. Recovery is the git history of the rule file, plus the `external_id_unused` lines the command prints.
- **The tenant name is the key.** Renaming a tenant in `platforms/<id>.toml` orphans the entry. The next deploy creates a new remote rule under the new name. The old id remains in the shard under the old name until something removes it.
- **Concurrency is bounded, not eliminated.** Generated production jobs serialise and start from the default branch's state, so two of them no longer race to create the same rule. Two operators running local deploys at once, or an Azure project without an Exclusive Lock check, can still both see no binding. Replay then keeps the newer id and fails loudly with `deployment_state_conflict` so the duplicate is removed by hand. There is no lock across machines.
- **Staging CI can no longer create on state-backed platforms.** A pull-request run under `STAGING`, `FULL`, `ALWAYS`, or `MANUAL` refuses a create with `deployment_state_unpersisted`. A team that relied on staging copies of new Defender, SentinelOne, or CrowdStrike rules must create them from a local run and commit the shard, or pass `--persist-state-externally` with its own persistence. Updates and deletes of bound rules still run, but a delete from such a run removes the binding only on the runner: the committed shard keeps it, and the next production run's update or delete fails against the missing remote rule rather than creating a duplicate.
- **GitLab may not run the write-back on cancellation or timeout.** That depends on the GitLab and runner versions. The generated file says so, and the `external_id_recorded` log lines are the recovery path.
- **Keeping `platform::*::1.0` means the schema id does not advertise the break.** The history row on each platform spec and the validation failure `external_id_in_rule` are what a catalogue sees. A reader who only checks `schema:` will think nothing changed.
- **Committed shards still contain tenant names and vendor ids.** They no longer sit inside the document `opentide share` publishes. Tenant names that authors wrote in `tenants` or in exclusions still do.

## Alternatives

- **Keep the write-back on the rule.** The id stays beside the detection, validate keeps rejecting the line deploy writes, and sharing keeps publishing tenant addresses.
- **One JSONL ledger, on the sharing model.** Sharing's ledger is a cache keyed by object, connector, and target, and it is safe to delete. A deployment id is a record keyed by rule and tenant. One file per rule is what a reviewer diffs when a single rule is deployed. A ledger also fights the per-uuid shard the inflight work already uses.
- **Rediscover the id by listing remote rules and matching the display name.** Defender's display name is the Tide rule `name`, which is not unique, and a rename would retarget a different rule. A wrong match is worse than a duplicate.
- **Dual-read: shard if present, otherwise the YAML.** A catalogue can then skip the migration forever, and the day someone deletes the YAML keys, deploy creates duplicates. Fail-closed is the migration.
- **New `platform::*::1.1` spec files that omit the field.** Every rule would also change `schema:`. The identifier is not a closed enum, so the new id does not force the key off old files. The key has to become illegal on `::1.0`.
- **Store integer ids as JSON numbers.** CrowdStrike ids are strings, and one field type keeps the shard uniform. The integer constraint is a pattern on the string.
- **A bare directory outside `.opentide/states/` so the current gitignore can stay.** The states directory is the place sharing defined for this. The gitignore is what changes. It was written when that directory held only a cache.
- **Gitignore the shards and keep them on the deploy runner.** A clean CI checkout would create a second rule on every run.
- **Let staging CI create and document the duplicates.** That was the first implementation's behaviour ([opentide#554](https://github.com/opentidehq/opentide/issues/554)). Every rerun is a new remote rule, and an `ALWAYS` tenant gets a staging copy and a production copy. Refusing the create before the vendor call is the only outcome that keeps the invariant without a new commit path from pull requests.
- **Commit shards from pull-request jobs.** Those runs check out a merge ref or a fork, and their commits would race the merge itself. Persisting from one serialised production job is simpler to reason about.
- **Copy the run's shard directory over the tip on conflict.** It reverts bindings other runs recorded and resurrects shards that were deleted. Replay per platform and tenant keeps both runs' work.
- **Make `external_id_missing` an error.** A rule retired before it was ever deployed would then fail every later deploy, and there is nothing opentide can do about it. The warning carries the manual-cleanup instruction.
- **Decide "ignored" by searching `.gitignore` text.** It misses wildcards, nested files, negations, `info/exclude`, and a global excludes file. A false negative is a duplicate rule.
- **Move inflight in this RFC.** [#31](https://github.com/opentidehq/specifications/issues/31) does that later. Mixing the path move with the id migration puts two unrelated catalogue changes in one upgrade.

## Unresolved questions

None. The questions the draft left open are decided:

| # | Question | Decision |
|---|----------|----------|
| 1 | Should the generated deploy workflow commit shard updates? | **Yes.** The generated production job commits every shard change to the default branch, after success, partial failure, cancellation, or timeout, serialised, starting from the tip's state, with per-tenant replay and a side-ref fallback ([§6](#6-ci-persistence)). Other CI jobs cannot create on state-backed platforms ([§5](#5-what-deploy-does-with-the-shard)). |
| 2 | Should a command delete shards whose `object_uuid` is no longer in the registry? | **No.** Orphan shards are retained: the file is the handle for a rule removed from the tree while the remote rule may still exist. Full-workspace validation still checks them. |
| 3 | Is a tenant rename worth an alias list on the shard? | **No.** A rename is a new key. There are no aliases in `deployment.state::1.0`. |
| 4 | If a later change needs another vendor-assigned identifier (Carbon Black's report id, a Splunk saved-search id, Sysdig), where does it go? | **In the shard.** It joins the platform table in §1 through a spec change. It never goes back onto the rule block. |

## References

- Spec-change issue: [specifications#30](https://github.com/opentidehq/specifications/issues/30)
- Inflight path, deferred: [specifications#31](https://github.com/opentidehq/specifications/issues/31)
- opentide implementation: [opentide#396](https://github.com/opentidehq/opentide/issues/396), [opentide#555](https://github.com/opentidehq/opentide/pull/555)
- Staging creates refused: [opentide#554](https://github.com/opentidehq/opentide/issues/554); production write-back: [opentide#548](https://github.com/opentidehq/opentide/issues/548)
- Normative text: [specs/deployment-state.md](../specs/deployment-state.md)
- Normative text this replaced on acceptance: [specs/platforms/index.md](../specs/platforms/index.md#external-rule-ids), [defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md), [sentinel-one-1.0.md](../specs/platforms/sentinel-one-1.0.md), [crowdstrike-1.0.md](../specs/platforms/crowdstrike-1.0.md), [harfanglab-1.0.md](../specs/platforms/harfanglab-1.0.md), [carbon-black-cloud-1.0.md](../specs/platforms/carbon-black-cloud-1.0.md)
- State directory this extends: [specs/sharing.md](../specs/sharing.md), [specs/workspace.md](../specs/workspace.md), [RFC 0005](0005-sharing-system.md)
- Elastic identity, unchanged: [RFC 0007](0007-elastic-security-platform.md)
- Sysdig draft that must not grow another `rule_id_bundle`: [specifications#8](https://github.com/opentidehq/specifications/issues/8)
- opentide writers and loader: `src/opentide/deployment/utils.py` (`ExternalIdHelper`), `src/opentide/platforms/defender_for_endpoint/deployer.py`, `src/opentide/platforms/sentinel_one/deployer.py`, `src/opentide/platforms/crowdstrike/deployer.py`, `src/opentide/loading/platform_loader.py`, `src/opentide/cli/services/setup/repo.py`
- Governance: [GOVERNANCE.md](../GOVERNANCE.md), [RFC 0001](0001-authority-model.md)
