# RFC 0021: Microsoft Defender on the Graph beta custom detection contract

- **RFC:** 0021
- **Title:** Microsoft Defender on the Graph beta custom detection contract (`microsoft_defender`, replacing `defender_for_endpoint`)
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-24
- **Accepted:** 2026-11-25. The owner decided to move Defender to the Microsoft Graph beta custom detection contract for opentide 1.0.0 GA. That is a major break, with the rule's `metadata.uuid` as the Defender rule id. The owner approved the four decisions of this RFC on 2026-11-25: recreating a legacy rule under the uuid and then deleting it (§5), deploy refusing the old platform's blocks (§6), this RFC as accepted with a spec-change issue, and the smaller design choices (§2–§4). The owner then directed three further changes, all accepted as breaking: the old platform is hard deprecated (§6); beta is the supported contract, fully modelled (§3); and the platform is renamed `microsoft_defender` (§2). The normative text is [specs/platforms/microsoft-defender-1.0.md](../specs/platforms/microsoft-defender-1.0.md) 1.0, [specs/platforms/defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md) 1.4 (deprecated), [specs/deployment-state.md](../specs/deployment-state.md) 1.10, [specs/deployment.md](../specs/deployment.md) 1.5, [specs/platforms/index.md](../specs/platforms/index.md) 1.11, [specs/validation.md](../specs/validation.md) 1.16, [specs/workspace.md](../specs/workspace.md) 1.6, and [specs/visibility.md](../specs/visibility.md) 1.2.
- **Supersedes:** [RFC 0010](0010-deployment-external-ids.md) for Microsoft Defender for Endpoint only
- **Issue:** [#104](https://github.com/opentidehq/specifications/issues/104)
- **Implementation:** to be tracked in [opentidehq/opentide](https://github.com/opentidehq/opentide) issues, for 1.0.0 GA (1.0.0-rc.5 ships `defender_for_endpoint`).

## Summary

opentide's Defender platform is renamed and moves to the Microsoft Graph **beta** custom detection API, `https://graph.microsoft.com/beta/security/rules/detectionRules`. The new platform is **`microsoft_defender`** (Microsoft Defender), with the block schema **`platform::microsoft_defender::1.0`**. opentide 1.0 does not ship `defender_for_endpoint`: the new contract exists only under the new name, and old blocks migrate to it.

The block's keys:

- `schedule` (an ISO 8601 frequency, and a beta lookback) replaces `scheduling`.
- `alert` keeps title, description, severity, recommendation, and techniques. It sends the techniques as Graph `tactics`, derived through the bundled ATT&CK vocabulary, and adds custom details and beta event grouping.
- `entities` (Graph's seventeen entity kinds) replaces `impacted_entities`.
- `actions` (Graph's sixteen automated actions) replaces the old response actions.
- `scope.device_groups` replaces `scope.selection`. A beta `incident` block sets incident correlation.
- The rule's `status` follows the deployment status.

Beta is the supported contract. Every writable beta property is modelled, or listed in the spec as not modelled with its reason; a test checks that against a snapshot of the beta docs.

The Defender rule id becomes the rule's **`metadata.uuid`**. Graph takes a client-provided `id` on create, so Defender is addressed like Sentinel and Elastic and leaves the deployment-state platforms. A rule created before 1.0 under a Defender-assigned id is recreated under the uuid and then deleted.

A `defender_for_endpoint` block is hard deprecated. It is still read, and `opentide validate` gives a strong warning, `defender_platform_renamed`, that no configuration can silence. `opentide migrate` moves it to `microsoft_defender`, and deploy refuses it with `defender_platform_retired`.

## Motivation

Microsoft deprecated, then removed on **2026-10-01**, every custom detection property `defender_for_endpoint` deploys to, other than the query text, display name, title, description, severity, and recommended actions. The Graph beta documentation ([References](#references)) reads:

| `defender_for_endpoint` sends | Graph (beta) | Replacement |
|-------------------------------|--------------|-------------|
| `isEnabled` | deprecated, "will be removed from this resource on 2026-10-01" | `status` (`enabled`, `disabled`, `autoDisabled`) |
| `schedule.period` (`0`, `1H`, `3H`, `12H`, `24H`) | deprecated, removal 2026-10-01 | `schedule.frequency`, an ISO 8601 duration; beta adds `schedule.lookback` |
| `alertTemplate.category` | deprecated, removal 2026-10-01 (already removed from opentide in platform 1.3) | `alertTemplate.tactics` |
| `alertTemplate.mitreTechniques` | deprecated, removal 2026-10-01 | `alertTemplate.tactics[{tactic, techniques[{technique, subTechniques}]}]` |
| `alertTemplate.impactedAssets` | deprecated, removal 2026-10-01 | `alertTemplate.entityMappings` |
| `detectionAction.responseActions` | deprecated, removal 2026-10-01 | `detectionAction.automatedActions` |
| `organizationalScope.scopeType`, `scopeNames` | deprecated, removal 2026-10-01 | `organizationalScope.deviceGroups` |

The date has passed. A `defender_for_endpoint` block can no longer be deployed as specified: the deployer sends properties the service no longer has. That is a break opentide cannot absorb with a minor version, because the shape of the block (`impacted_entities`, `actions`, `scheduling`) is the shape of the removed wire format.

The same documentation changes identity. The create request's `id` is "the client-provided unique identifier of the rule. Required." Before 1.0, opentide let Defender assign a decimal id and kept it per tenant in a committed deployment-state shard ([RFC 0010](0010-deployment-external-ids.md)). That brought all its machinery: create guards in CI, write-backs, replay on conflict, `external_id_missing`. With a client id, the rule's `metadata.uuid` is the id in every tenant, as for Sentinel and Elastic, and Defender needs none of that.

Microsoft has dropped the "for Endpoint" name and unified its products under Microsoft Defender. The custom detection rule is a Defender XDR object that reads Endpoint, Office 365, Identity, and Cloud Apps tables. A break of this size is the time to take the product's name.

Who is affected: every workspace with a Defender block. Each workspace runs `opentide migrate` once, and the first `microsoft_defender` deploy replaces each existing Defender rule with one under the uuid.

## Detailed design

### 1. Affected specs

| Path | Change |
|------|--------|
| `specs/platforms/microsoft-defender-1.0.md` | **New**, spec version 1.0, `schema_id: platform::microsoft_defender::1.0`, `status: normative`, `supersedes: platform::defender_for_endpoint::1.0`. |
| `specs/platforms/defender-for-endpoint-1.0.md` | 1.3 → **1.4**, `status: deprecated`. Kept, per [AGENTS.md](../AGENTS.md). Requirements for reading a block, the warning, the deploy refusal, and the conflict. The pre-1.0 deploy table is kept for the record. |
| `specs/deployment-state.md` | 1.9 → **1.10**. Defender leaves the state-backed set. A `defender_for_endpoint` binding is a legacy binding, and the shard key keeps that name: readers accept it, deploy never writes one, and a `microsoft_defender` deploy retires it. Schema id and shard JSON Schema unchanged. |
| `specs/deployment.md` | 1.4 → **1.5**. Microsoft Defender addresses its rule by uuid. A deleted `microsoft_defender` rule is retired by uuid, and an orphan legacy binding by its id. |
| `specs/platforms/index.md` | 1.10 → **1.11**. Schema table, capability matrix, `--live` allowlist, static-validation bar, external-id table, generated defaults. |
| `specs/validation.md` | 1.15 → **1.16**. Advisories `defender_platform_renamed` (not configurable) and `microsoft_defender_no_entities`; `microsoft_defender` in the `--live` allowlist; the fixture checker. |
| `specs/workspace.md` | 1.5 → **1.6**. The shard directory no longer lists Defender as state-backed. |
| `specs/visibility.md` | 1.1 → **1.2**. The KQL system is `microsoft_defender`; `defender_for_endpoint` is read as it and migrated. |
| `specs/objects/rule-1.0.md`, `rule-1.1.md` | `configurations.microsoft_defender` is added; `defender_for_endpoint` is marked deprecated. |
| `rfcs/0010-deployment-external-ids.md` | Marked superseded in part, for Defender. |
| `SPECS.md`, `CHANGELOG.md`, `rfcs/README.md`, `llms.txt`, `site/meta.json` | Index rows. |

Vocabularies: none change. The tactic table reads the existing `att&ck` vocabulary's `tide.vocab.stages`.

### 2. `microsoft_defender` and `platform::microsoft_defender::1.0`

The field tables are in the spec. The decisions behind them:

**The name.** The configuration key is `microsoft_defender`, the display name "Microsoft Defender", and the schema `platform::microsoft_defender::1.0`. It is a new platform identifier, so it starts at 1.0. The `--platform` value, the tenants configuration (`.opentide/configurations/platforms/microsoft_defender.toml`), the capability matrix, the `--live` allowlist, and visibility log sources all say `microsoft_defender`. Only the deployment-state shard keeps `platforms.defender_for_endpoint`, as the key of legacy bindings. `schema` may be omitted, as on every platform; when set it must be `platform::microsoft_defender::1.0`. The key alone tells a new block from an old one, so no schema inference is needed.

**`alert`.** `title`, `description`, `severity`, `recommendation`, and `techniques` keep their old names and defaults, so migration copies them. Severity gains a final default, `Medium`, for a rule that sets neither `alert.severity` nor `response.alert_severity`. `Critical` is sent as `high`, Graph's highest.

**Tactics.** Graph nests techniques in tactics: `tactics: [{tactic, techniques: [{technique, subTechniques}]}]`. Deploy derives that tree from the technique ids, which are `alert.techniques` or else the objective's (as before). Each id's `tide.vocab.stages` in the bundled `att&ck` vocabulary gives its tactics, and a sub-technique files under its parent. Stealth and Defense Impairment (ATT&CK v19's split of Defense Evasion) both send `DefenseEvasion`, as Sentinel does. Non-Enterprise and unknown ids are left out with a warning.

There is **no explicit `alert.tactics` key**. A tactic is only meaningful in Graph with the techniques under it, and the vocabulary already knows each technique's tactics. A hand-written list could only repeat them or contradict them.

**Custom details** (`alert.custom_details`, name → column) and **event grouping** (`alert.grouping`, beta-only, `alert_per_event` or `single_alert`) are new.

**Entities.** `entities` covers all seventeen kinds of Graph's `entityMappingConfiguration`. Each kind is a list of mappings, as in Graph. A field is the Graph property without its `Column` suffix, in snake_case (`deviceIdColumn` → `device_id`), and its value is the result column, sent verbatim. The old platform lower-cased the column's first character, because Graph took an identifier enum (`deviceId`). `entityMappings` takes the column name (`DeviceId`).

**Schedule.** `schedule.frequency` is `NRT`, `<n>H`, or `<n>D`, sent as an ISO 8601 duration (`PT0S` for NRT). The old platform's five values (`NRT`, `1H`, `3H`, `12H`, `24H`) remain valid, so migration is a move. `schedule.lookback` (beta-only) is `<n>H` or `<n>D`, never shorter than the frequency and never with NRT, the two rules Graph states.

**Actions.** `actions` holds Graph's sixteen `automatedActionSet` members as snake_case keys. Each is a list of targets whose fields name result columns (`device_id`, `sha1`, `account_sid`, …), plus `isolation_type` and `device_groups`.

**Scope, incident, status, exclusions.** `scope.device_groups` replaces `scope.selection`, and no `scope` means every device. `incident.exclude_from_correlation` (beta-only) sets `incidentConfiguration`. `PREVIEW`, `RELEASE`, and `UNIVERSAL` send `status: enabled`, `DISABLEMENT` sends `disabled`, and `DELETION` deletes. Exclusions are unchanged.

**Codes.** Every code about the new platform's block, deploy, and advisories uses the platform identifier as its prefix, `microsoft_defender_` (for example `microsoft_defender_lookback`). That is the convention of every other platform (`google_secops_`, `bitdefender_`, `graylog_`), and it keeps codes unique across platform specs, as [validation.md](../specs/validation.md#platform-advisories) requires. It also lets a search for the platform find all of its codes. A shorter prefix (`defender_`, `mde_`, `msd_`) was rejected: `mde_` names Defender for Endpoint, the name being dropped; `defender_` would also catch Bitdefender's `bitdefender_` codes in a plain-text search; and an abbreviation is something readers must decode. The four codes about the retired platform start with `defender_` (`defender_platform_renamed`, `defender_platform_retired`, `defender_platform_conflict`, `defender_migrate_unmapped`), so a search for the old name finds them.

**Constraints, advisories, diagnostics.** The constraint codes:

- `microsoft_defender_schema`
- `microsoft_defender_frequency`, `microsoft_defender_lookback`
- `microsoft_defender_severity`, `microsoft_defender_grouping`, `microsoft_defender_custom_details`
- `microsoft_defender_entity_kind`, `microsoft_defender_entity_mapping`
- `microsoft_defender_action_kind`, `microsoft_defender_action_target`, `microsoft_defender_isolation_type`
- `microsoft_defender_column`, `microsoft_defender_scope`, `microsoft_defender_incident`

There are two advisories, `defender_platform_renamed` and `microsoft_defender_no_entities`. Deploy adds three diagnostics: `microsoft_defender_rule_absent`, `microsoft_defender_legacy_delete_failed`, and `microsoft_defender_legacy_retired`.

### 3. The beta API is the contract

opentide targets and supports the Graph **beta** custom detection API. Microsoft is slow to promote features to v1.0, and the beta-only ones (lookback, event grouping, incident correlation) are needed. The deployer always calls `https://graph.microsoft.com/beta/security/rules/detectionRules`, and no setting changes that.

**Completeness.** The spec's [Beta API coverage](../specs/platforms/microsoft-defender-1.0.md#beta-api-coverage) section accounts for every property of every type the API uses: `detectionRule`, `queryCondition`, `ruleSchedule`, `detectionAction`, `alertTemplate`, `alertCustomDetails`, `entityMappingConfiguration` and the seventeen `*EntityMapping` types, `mitreTactic`, `mitreTechnique`, `automatedActionSet` and its seven action types, `organizationalScope`, and `incidentConfiguration`. That is 130 properties in 36 types. Each is either modelled by a key of the block or listed under "Beta properties not modelled" with one of three reasons:

- **read-only:** `createdBy`, `createdDateTime`, `lastModifiedBy`, `lastModifiedDateTime`;
- **deprecated:** `isEnabled`, `detectorId`, `lastRunDetails`, `queryCondition.lastModifiedDateTime`, `period`, `nextRunDateTime`, `category`, `impactedAssets`, `mitreTechniques`, `responseActions`, `scopeType`, `scopeNames`;
- **set by deploy:** `id`, `displayName`, `description`, `status`, `queryText`, `alertTemplate.tactics`, and the four `mitreTactic` and `mitreTechnique` properties.

The audit found no writable property missing from the block. The enum values not accepted are listed too: `autoDisabled`, which Defender sets, and every enum's `unknownFutureValue` sentinel. [fixtures/platforms/microsoft-defender/graph-beta-properties.json](../fixtures/platforms/microsoft-defender/graph-beta-properties.json) snapshots the docs' Properties tables and enums. The test fails when a snapshot property is neither modelled nor listed, or when a listed reason contradicts the docs' read-only or deprecated marks.

**Validation from the docs.** Every modelled property is checked against what the beta docs state. The docs state these constraints:

- enum values: `alertTemplate.severity` is `informational`, `low`, `medium`, or `high`; `eventGroupingKind` is `alertPerEvent` or `singleAlert`; `isolationType` is `full` or `selective`;
- lookback ≥ frequency;
- no lookback with a zero (NRT) frequency.

Every listed enum value is accepted, and anything else is rejected under a named code. Where the docs say nothing, the spec says so rather than invent a rule. They give no allowed frequencies, no maximum lookback, no required field in an entity mapping or action target, and no custom-detail limits. The few opentide shape rules are marked as opentide's: a mapping or target is not empty, and `scope` is not an empty list. An earlier draft required fields per action and limited `frequency` to five values; both were invented, and both are gone.

**v1.0, for information.** Every property the block sends, except `schedule.lookback`, `alertTemplate.eventGroupingKind`, and `detectionAction.incidentConfiguration`, also exists in v1.0 with the same name and shape. A block that sets none of those three is therefore also a valid v1.0 request. That is recorded as a fact, not a plan: opentide does not target v1.0.

### 4. Identity: the uuid is the Defender rule id

Every call addresses `{base}/{uuid}`, the lowercase canonical `metadata.uuid`:

| Strategy | Calls |
|----------|-------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `PATCH {base}/{uuid}`; on `404`, `POST {base}` with `id: {uuid}`. A `409` on the `POST` (a concurrent create) is followed by one more `PATCH`. |
| `DISABLEMENT` | `PATCH {base}/{uuid}` with `status: disabled`; on `404`, nothing is created (`microsoft_defender_rule_absent`, a warning), unless a legacy rule is being adopted. |
| `DELETION` | `DELETE {base}/{uuid}`; `404` is "already gone". |

Trying `PATCH` first makes the steady state, an update, a single call. A `404` on `PATCH` is the only absence signal; deploy never lists rules or matches names. No create needs deployment state, so the CI create guards (`deployment_state_ignored`, `deployment_state_unpersisted`) and `external_id_missing` do not apply to Microsoft Defender. `--prune` retires a deleted `microsoft_defender` rule by uuid, as for Sentinel and Elastic.

### 5. Rules created before 1.0

A tenant may hold a rule that opentide created before 1.0 under a Defender-assigned decimal id `L`, recorded in the rule's shard under `platforms.defender_for_endpoint.<tenant>`. Graph documents no way to change a rule's `id` (the update request has no `id`), so that rule can never become the uuid rule. There are two choices:

- **(A) Recreate, then delete.** The first `microsoft_defender` deploy to the tenant deploys the uuid rule, then deletes `L`, then removes the binding.
- **(B) Keep a legacy binding.** Keep addressing `L` through the shard until the rule is retired, and use the uuid only for new rules.

This RFC chooses **(A)**:

- The owner's direction is that the uuid is the new truth. (B) keeps two identities for Defender indefinitely. Every deploy path, status report, retirement, and CI guard would have to handle both for as long as any rule created before 1.0 GA lives, and Defender would stay state-backed in practice.
- (A) is self-healing and needs no persisted state. If the run cannot commit the shard, the binding survives on the default branch; the next run's `DELETE {base}/L` answers `404` and removes it. Nothing is ever created from a shard, so the duplicate-rule failure RFC 0010 guards against cannot happen here.
- The order protects coverage: the uuid rule is deployed **before** `L` is deleted, so the tenant never lacks the detection. If the uuid rule fails, `L` is kept. If deleting `L` fails, both run until the next deploy retries (`microsoft_defender_legacy_delete_failed`, an error).

What (A) costs: the alert and incident history stays attached to the legacy rule's alerts. Between the two calls, both rules run and may both alert. Neither cost can be avoided without (B)'s permanent second identity.

Deployment-state changes ([deployment-state 1.10](../specs/deployment-state.md#legacy-defender-bindings)):

- `platforms.defender_for_endpoint` stays a valid key of `deployment.state::1.0`, with its decimal pattern, so every shard written before 1.0 still validates. There is no `microsoft_defender` key. The shard schema and JSON Schema do not change.
- Deploy never writes a Defender binding. It removes one after retiring `L` (`204` or `404`), and `--prune` retires an orphan one by deleting `L`.
- `opentide deploy migrate-state` still moves a pre-RFC-0010 Defender `rule_id` key into a binding. That binding is what lets the next `microsoft_defender` deploy retire the rule.
- `opentide migrate` does not touch shards.

### 6. `defender_for_endpoint`: renamed and hard deprecated

`specs/platforms/defender-for-endpoint-1.0.md` gets `status: deprecated` and stays. A `configurations.defender_for_endpoint` block, of any schema version:

- **Is read.** Static validation applies the full old contract, so a broken block still reports its real errors.
- **Warns, strongly.** The platform is **hard deprecated**, at the owner's direction: every block must migrate to the contract of the API Microsoft serves today. `opentide validate` reports **`defender_platform_renamed`** at `configurations.defender_for_endpoint`. It stays a warning, so validate exits 0 and CI pipelines keep running until a workspace has migrated; deploy is where the block stops. Its message says plainly:
  - the platform is renamed to `microsoft_defender` and is hard deprecated;
  - Microsoft removed its wire format on 2026-10-01;
  - `opentide deploy` refuses the block;
  - run `opentide migrate` now (with a link to the migration table).

  It is emitted under every setting and on every surface. No configuration can lower or silence it: not a `lint.toml` severity override, a quiet profile, an ignore list, or a per-rule suppression. The code folds in the earlier draft's `defender_schema_deprecated`.
- **Conflicts.** A rule with both a `defender_for_endpoint` and a `microsoft_defender` block is **`defender_platform_conflict`**, an error in validate and deploy.
- **Migrates.** `opentide migrate` rewrites the workspace ([microsoft-defender-1.0](../specs/platforms/microsoft-defender-1.0.md#migration-from-defender_for_endpoint)):

  | What | Rewrite |
  |------|---------|
  | `configurations.defender_for_endpoint` in each rule file | Moved to `configurations.microsoft_defender`, key by key, in place; the rest of the file is byte-identical |
  | `response.procedure.searches[].system: defender_for_endpoint` | `system: microsoft_defender` |
  | `.opentide/configurations/platforms/defender_for_endpoint.toml` | Renamed `microsoft_defender.toml`; `[platform] identifier` and `name` rewritten; tenants, credentials, and modifiers kept |
  | `.opentide/configurations/visibility.toml`, `system = "defender_for_endpoint"` | `system = "microsoft_defender"` |

  The key mapping goes through Graph's former identifier enums: `impacted_entities` (`deviceId` → `hosts.device_id`, `accountSid` → `accounts.sid`, `recipientEmailAddress` → `mailboxes.primary_address`, …), device flags (an action on the `DeviceId` column), `allow_block` (`allow_files` or `block_files`), `quarantine_file` (`stop_and_quarantine_files`), and the user actions (their column). Some values cannot be mapped: `accountId`, `servicePrincipalId`, `servicePrincipalName`, `senderDisplayName`, a non-hash file identifier, and a `Specific` selection with no groups. Each is the error **`defender_migrate_unmapped`**, and that rule is left unchanged so the author maps it by hand rather than losing an entity or an action silently. Tenant names are unchanged, so legacy bindings still match. Generated CI files name no platform and are not rewritten. Deployment state is not touched.
- **Is refused by deploy.** Deploy reports **`defender_platform_retired`** (error) for the block on each selected tenant, makes no call, touches no state, and exits 1; the rule's other platform blocks still deploy. `--platform defender_for_endpoint` is a usage error that names `microsoft_defender`.

Why refuse rather than deploy through the new mapping:

- The old wire format no longer exists, so such a deploy could only be a translated `microsoft_defender` deploy.
- The translation is not total, so it would drop entities or response actions without the author seeing it.
- The first `microsoft_defender` deploy recreates the rule under its uuid and deletes the old one. That tenant change should follow a reviewed YAML diff, not a CLI upgrade.

The owner wants clear warnings. The warning comes at validate time, before anything reaches a tenant, and the error at deploy names the one command that fixes it.

### 7. Fixtures

| Path | What it proves |
|------|----------------|
| `fixtures/platforms/microsoft-defender.yaml` | A valid rule using every block key, beta-only keys included |
| `fixtures/platforms/microsoft-defender-complete.yaml` and `fixtures/platforms/microsoft-defender/rule-microsoft-defender-complete.create.api.json` | Every key of every field table set once (all 17 entity kinds and 16 actions with every field), and its create body for tenant `contoso`. It is also the spec's complete example |
| `fixtures/platforms/microsoft-defender/rule-microsoft-defender.create.api.json`, `.update.api.json`, `.disable.api.json` | The Graph bodies deploy sends, derived by the tests from the spec's tables |
| `fixtures/platforms/microsoft-defender/migrated.yaml` | `opentide migrate` of `fixtures/platforms/defender-for-endpoint.yaml` (kept) |
| `fixtures/platforms/microsoft-defender/graph-beta-properties.json` | The beta docs snapshot the coverage test reads |
| `fixtures/invalid/rule-microsoft-defender-lookback-nrt.yaml` | `microsoft_defender_lookback` |
| `fixtures/invalid/rule-microsoft-defender-entity-field.yaml` | `microsoft_defender_entity_mapping` |
| `fixtures/invalid/rule-microsoft-defender-action-target.yaml` | `microsoft_defender_action_target` |
| `fixtures/invalid/rule-microsoft-defender-old-keys.yaml` | `unknown_field`: old keys on a `microsoft_defender` block |
| `fixtures/invalid/rule-defender-both-platforms.yaml` | `defender_platform_conflict` |

`scripts/test_platform_microsoft_defender.py` derives the bodies and the migration from the spec's tables and checks them against the goldens. It also checks beta coverage, the complete block against the field tables, and the spec's example against the fixture.

### 8. Implementation notes for opentide

- A `microsoft_defender` platform: a `MicrosoftDefenderConfig` model for `platform::microsoft_defender::1.0`, its bundled `platforms/microsoft_defender.toml`, and its deployer and query validator. The `defender_for_endpoint` model stays for reading only. Its deployer and enablement go away.
- The deployer: the beta base URL, `PATCH` then `POST`, the legacy retirement, and no shard writes.
- `opentide validate`: `defender_platform_renamed`, always emitted and not configurable; `defender_platform_conflict`.
- `opentide deploy`: `defender_platform_retired`; `--platform defender_for_endpoint` is a usage error naming `microsoft_defender`.
- `opentide migrate`: the four rewrites in §6 and `defender_migrate_unmapped`.
- `generate extract` writes `microsoft_defender` blocks from the tenant's rules.
- The bundled Microsoft Defender rule template carries every key the spec defines, in the order and with the column names of the spec's [complete block](../specs/platforms/microsoft-defender-1.0.md#examples) (`fixtures/platforms/microsoft-defender-complete.yaml`). The required keys (`query`, `schedule.frequency`) are set, every optional key is present but commented out, and the beta-only keys are marked as such.
- The generated JSON Schema default for the `microsoft_defender` `schema` is `platform::microsoft_defender::1.0` ([platforms/index.md](../specs/platforms/index.md#generated-schema-drift)).

## Drawbacks

- Every Defender rule is replaced in every tenant on its first `microsoft_defender` deploy. Alert history stays on the old rule, and both rules briefly run.
- Beta can change without notice. opentide takes that risk deliberately. The coverage test, re-run against a fresh snapshot, shows what changed.
- Every workspace must run `opentide migrate` before its Defender rules deploy again. Rules whose old values cannot be mapped need a hand edit. The rename also touches the platform TOML and visibility configuration.
- Seventeen entity kinds and sixteen actions are a larger surface to validate and document than the old three entities and nine actions.

## Alternatives

- **Keep `defender_for_endpoint` and change only the deployer.** The block's shape is the removed wire format (`impacted_entities` as single columns, flag-style device actions with no column, `scheduling` strings). It cannot express entity lists, email or file-hash actions, custom details, or lookback. A minor version cannot fix that without breaking every block.
- **A `platform::defender_for_endpoint::2.0` under the old key.** This was the first draft of this RFC. It keeps a name Microsoft has dropped, and it needed schema inference to tell 1.0 from 2.0 blocks under one key. Rejected by the owner in favour of the rename.
- **Graph v1.0.** Loses lookback, event grouping, and incident correlation, which are needed. Rejected by the owner.
- **Stay state-backed, with the uuid as the client id.** Recording an id that always equals `metadata.uuid` adds nothing and keeps all of RFC 0010's create guards for Defender.
- **Keep legacy bindings until each rule is retired (B in section 5).** Two permanent identities; rejected above.
- **Deploy old blocks through the new mapping.** Rejected in section 6.
- **An explicit `alert.tactics` key.** Rejected in section 2.
- **A shorter code prefix.** Rejected in section 2.

## Unresolved questions

The Graph documentation leaves these open. The spec takes the stated position; a live tenant should confirm each before 1.0.0 GA.

1. **NRT encoding.** `ruleSchedule.lookback` says NRT rules have "a zero frequency" but no document shows the value. The spec sends `PT0S`. Graph may expect `PT0M`, `P0D`, or refuse NRT through this API.
2. **404 on update and delete.** The update and delete pages document only `200` and `204`. The spec assumes `404` for an id the tenant does not have, on `PATCH` and on `DELETE`, and `409` for a `POST` whose `id` exists. If Graph answers otherwise (`400`, `403`), deploy must `GET {base}/{uuid}` first.
3. **PATCH semantics for nested objects.** The update page says an omitted `incidentConfiguration` value "leaves the existing setting unchanged". It does not say whether a `PATCH` replaces `detectionAction.alertTemplate`, `entityMappings`, `automatedActions`, `organizationalScope`, or `customDetails` wholesale or merges them, nor whether an omitted `lookback` or `eventGroupingKind` resets to the default. If they merge, removing a key from the YAML would not clear it in the tenant; a 1.x minor would then send explicit empty values (`[]`, `{}`, `alertPerEvent`, `false`).
4. **Tactic values.** `mitreTactic.tactic` is documented with the example `Exploit`, not an ATT&CK tactic, while the create example sends `Execution`. The spec sends ATT&CK tactic names without spaces (`InitialAccess`, `DefenseEvasion`, `CommandAndControl`). Whether Graph wants that form, display names, or `TA` ids, and whether it knows ATT&CK v19 technique ids (sent as resolved), is open.
5. **Technique nesting.** The create example puts `T1059.001` in `technique`, while `mitreTechnique.subTechniques` is documented for sub-technique ids. The spec sends the parent in `technique` and the sub-technique in `subTechniques`.
6. **Which entity mappings Defender honours.** All seventeen kinds are documented on one type shared by every Defender XDR product. Which ones a tenant with only Defender for Endpoint (no Office, Identity, or Cloud Apps) accepts or shows, which columns each kind needs to resolve an entity, and whether a rule must map at least one entity, are not documented. The spec accepts every kind, requires one field per mapping (an opentide shape rule), and only warns (`microsoft_defender_no_entities`) when there is none. The same holds for action targets: the docs name no required field.
7. **Frequencies and lookback bounds.** Which frequencies Defender accepts, and the maximum `lookback`, are not documented. The spec accepts any `NRT`, `<n>H`, or `<n>D` and enforces only what the docs state (lookback ≥ frequency, none with NRT); Defender's answer at deploy decides the rest. The frequencies Defender has offered are `NRT`, `1H`, `3H`, `12H`, and `24H`.
8. **The client id.** The documented constraints on `id` (characters, length, case) are none. The spec assumes a 36-character lowercase uuid is accepted and that ids are compared exactly.
9. **Legacy ids on the beta endpoint.** The spec assumes a rule created through the old contract is addressable at `{base}/{decimal id}` on beta, so that it can be deleted there.
10. **Custom detail limits.** The number of custom details, and the characters a name may hold, are not documented.

## References

- Microsoft Graph documentation source, beta: [`detectionRule`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-detectionrule.md), [`alertTemplate`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-alerttemplate.md), [`detectionAction`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-detectionaction.md), [`ruleSchedule`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-ruleschedule.md), [`queryCondition`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-querycondition.md), [`entityMappingConfiguration`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-entitymappingconfiguration.md) and its seventeen `*EntityMapping` types, [`mitreTactic`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-mitretactic.md), [`mitreTechnique`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-mitretechnique.md), [`automatedActionSet`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-automatedactionset.md) and its action types, [`organizationalScope`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-organizationalscope.md), [`incidentConfiguration`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-incidentconfiguration.md), [`alertCustomDetails`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-alertcustomdetails.md), [`enums-security`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/enums-security.md) (the former `impactedAsset` and `responseAction` identifier enums migration maps from), [create](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-rulesroot-post-detectionrules.md), [update](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-detectionrule-update.md), [delete](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-rulesroot-delete-detectionrules.md).
- The same paths under `api-reference/v1.0/`, for the informational note in section 3.
- [RFC 0010](0010-deployment-external-ids.md) — deployment external ids, superseded here for Defender
- [RFC 0007](0007-elastic-security-platform.md) — Elastic, the precedent for `metadata.uuid` as the vendor rule id
- [specs/platforms/defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md) 1.3 — `alert.category` removed for the same Graph deprecation ([opentide#1704](https://github.com/opentidehq/opentide/issues/1704))
- [opentidehq/specifications#104](https://github.com/opentidehq/specifications/issues/104) — the spec-change issue
