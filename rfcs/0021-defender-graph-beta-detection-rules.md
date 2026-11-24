# RFC 0021: Defender for Endpoint on the Graph beta custom detection contract

- **RFC:** 0021
- **Title:** Defender for Endpoint on the Microsoft Graph beta custom detection contract (`platform::defender_for_endpoint::2.0`)
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-24
- **Accepted:** 2026-11-24. Moving Defender for Endpoint to the Graph beta custom detection contract, as a major break with the rule's `metadata.uuid` as the Defender rule id, for opentide 1.0.0 GA, is the owner's decision. The design choices below are this RFC's and are open to review on its PR. The normative text is [specs/platforms/defender-for-endpoint-2.0.md](../specs/platforms/defender-for-endpoint-2.0.md) 2.0, [specs/platforms/defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md) 1.4 (deprecated), [specs/deployment-state.md](../specs/deployment-state.md) 1.9, [specs/deployment.md](../specs/deployment.md) 1.5, [specs/platforms/index.md](../specs/platforms/index.md) 1.11, [specs/validation.md](../specs/validation.md) 1.16, and [specs/workspace.md](../specs/workspace.md) 1.6.
- **Supersedes:** [RFC 0010](0010-deployment-external-ids.md) for Microsoft Defender for Endpoint only
- **Issue:** none yet. [AGENTS.md](../AGENTS.md) asks for a spec-change issue before an RFC; one should be opened and linked here.
- **Implementation:** to be tracked in [opentidehq/opentide](https://github.com/opentidehq/opentide) issues, for 1.0.0 GA (1.0.0-rc.5 ships 1.0).

## Summary

opentide's Microsoft Defender for Endpoint platform moves to the Microsoft Graph **beta** custom detection API, `https://graph.microsoft.com/beta/security/rules/detectionRules`, under a new block schema, **`platform::defender_for_endpoint::2.0`**:

- `schedule` (an ISO 8601 frequency, and a beta lookback) replaces `scheduling`;
- `alert` keeps title, description, severity, recommendation, and techniques, sends the techniques as Graph `tactics` derived through the bundled ATT&CK vocabulary, and adds custom details and beta event grouping;
- `entities` (Graph's seventeen entity kinds) replaces `impacted_entities`;
- `actions` (Graph's sixteen automated actions) replaces the 1.0 response actions;
- `scope.device_groups` replaces `scope.selection`; a beta `incident` block sets incident correlation;
- the rule's `status` follows the deployment status.

The Defender rule id becomes the rule's **`metadata.uuid`**. Graph takes a client-provided `id` on create, so Defender is addressed like Sentinel and Elastic and leaves the deployment-state platforms. A rule opentide 1.x created under a Defender-assigned id is recreated under the uuid and then deleted.

`platform::defender_for_endpoint::1.0` is deprecated: it is still read, `opentide validate` warns with `defender_schema_deprecated`, `opentide migrate` rewrites it to 2.0, and deploy refuses it with `defender_schema_retired`.

## Motivation

Microsoft deprecated, then removed on **2026-10-01**, every custom detection property opentide 1.0 deploys to, other than the query text, display name, title, description, severity, and recommended actions. The Graph beta documentation ([References](#references)) reads:

| opentide 1.0 sends | Graph (beta) | Replacement |
|--------------------|--------------|-------------|
| `isEnabled` | deprecated, "will be removed from this resource on 2026-10-01" | `status` (`enabled`, `disabled`, `autoDisabled`) |
| `schedule.period` (`0`, `1H`, `3H`, `12H`, `24H`) | deprecated, removal 2026-10-01 | `schedule.frequency`, an ISO 8601 duration; beta adds `schedule.lookback` |
| `alertTemplate.category` | deprecated, removal 2026-10-01 (already removed from opentide in platform 1.3) | `alertTemplate.tactics` |
| `alertTemplate.mitreTechniques` | deprecated, removal 2026-10-01 | `alertTemplate.tactics[{tactic, techniques[{technique, subTechniques}]}]` |
| `alertTemplate.impactedAssets` | deprecated, removal 2026-10-01 | `alertTemplate.entityMappings` |
| `detectionAction.responseActions` | deprecated, removal 2026-10-01 | `detectionAction.automatedActions` |
| `organizationalScope.scopeType`, `scopeNames` | deprecated, removal 2026-10-01 | `organizationalScope.deviceGroups` |

The date has passed. A 1.0 block can no longer be deployed as specified: the deployer sends properties the service no longer has. That is a break opentide cannot absorb with a minor version of the 1.0 spec, because the shape of the block (`impacted_entities`, `actions`, `scheduling`) is the shape of the removed wire format.

The same documentation changes identity. The create request's `id` is "the client-provided unique identifier of the rule. Required." opentide 1.x let Defender assign a decimal id and kept it per tenant in a committed deployment-state shard ([RFC 0010](0010-deployment-external-ids.md)), with all the machinery that implies: create guards in CI, write-backs, replay on conflict, `external_id_missing`. With a client id, the rule's `metadata.uuid` is the id in every tenant, as for Sentinel and Elastic, and none of that is needed for Defender.

Beta rather than v1.0: Graph v1.0 has the same `detectionRule` minus three properties (`schedule.lookback`, `alertTemplate.eventGroupingKind`, `detectionAction.incidentConfiguration`), all of which detection engineers ask for. The owner chose beta. This RFC keeps v1.0 one URL away for every rule that does not use those three keys.

Who is affected: every workspace with a Defender block. Each block needs `opentide migrate` once, and the first 2.0 deploy replaces each existing Defender rule with one under the uuid.

## Detailed design

### 1. Affected specs

| Path | Change |
|------|--------|
| `specs/platforms/defender-for-endpoint-2.0.md` | **New**, spec version 2.0, `schema_id: platform::defender_for_endpoint::2.0`, `status: normative`. |
| `specs/platforms/defender-for-endpoint-1.0.md` | 1.3 → **1.4**, `status: deprecated`. Kept, per [AGENTS.md](../AGENTS.md). Requirements for reading a 1.0 block, the warning, and the deploy refusal; the 1.x deploy table kept for the record. |
| `specs/deployment-state.md` | 1.8 → **1.9**. Defender leaves the state-backed set. A `defender_for_endpoint` binding is a legacy binding: readers accept it, deploy never writes one, a 2.0 deploy retires it. Schema id and shard JSON Schema unchanged. |
| `specs/deployment.md` | 1.4 → **1.5**. Defender addresses its rule by uuid; retirement of a deleted 2.0 rule by uuid and of an orphan legacy binding by its id. |
| `specs/platforms/index.md` | 1.10 → **1.11**. Schema table, capability matrix, static-validation bar, external-id table. |
| `specs/validation.md` | 1.15 → **1.16**. Advisories `defender_schema_deprecated` and `defender_no_entities`; the fixture checker applies the Defender 2.0 constraints. |
| `specs/workspace.md` | 1.5 → **1.6**. The shard directory no longer lists Defender as state-backed. |
| `specs/objects/rule-1.0.md`, `rule-1.1.md` | `configurations.defender_for_endpoint` names both schemas. Additive. |
| `rfcs/0010-deployment-external-ids.md` | Marked superseded in part, for Defender. |
| `SPECS.md`, `CHANGELOG.md`, `rfcs/README.md`, `llms.txt`, `site/meta.json` | Index rows. |

Vocabularies: none change. The tactic table reads the existing `att&ck` vocabulary's `tide.vocab.stages`.

### 2. `platform::defender_for_endpoint::2.0`

The field tables are in the spec. The decisions behind them:

**Routing.** A 2.0 block must say `schema: platform::defender_for_endpoint::2.0`. A Defender block with no `schema`, with `platform::defender_for_endpoint::1.0`, or with a legacy identifier is a 1.0 block. Every Defender block written so far is 1.0, so the only safe default for a missing `schema` is 1.0; guessing the version from the keys would turn a typo into a silent version switch.

**`alert`.** `title`, `description`, `severity`, `recommendation`, and `techniques` keep their 1.0 names and defaults, so migration copies them. Severity gains a final default, `Medium`, for a rule that sets neither `alert.severity` nor `response.alert_severity` (1.0 sent nothing, which the template cannot take). `Critical` is still sent as `high`, Graph's highest.

**Tactics.** Graph nests techniques in tactics: `tactics: [{tactic, techniques: [{technique, subTechniques}]}]`. Deploy derives that tree from the technique ids, which are `alert.techniques` or else the objective's (as in 1.2): each id's `tide.vocab.stages` in the bundled `att&ck` vocabulary gives its tactics; a sub-technique files under its parent. Stealth and Defense Impairment (ATT&CK v19's split of Defense Evasion) both send `DefenseEvasion`, as Sentinel does. Non-Enterprise and unknown ids are left out with a warning, as in 1.2.

There is **no explicit `alert.tactics` key**. A tactic is only meaningful in Graph with the techniques under it, the vocabulary already knows each technique's tactics, and a hand-written list could only repeat them or contradict them. If a need for a technique-less tactic appears, an additive `alert.tactics` can come in a 2.x minor.

**Custom details** (`alert.custom_details`, name → column) and **event grouping** (`alert.grouping`, beta-only, `alert_per_event` or `single_alert`) are new.

**Entities.** `entities` replaces `impacted_entities` and covers all seventeen kinds of Graph's `entityMappingConfiguration`: `hosts`, `accounts`, `mailboxes`, `files`, `processes`, `ips`, `urls`, `dns`, `registry_values`, `mail_messages`, `mail_clusters`, `cloud_applications`, `oauth_applications`, `security_groups`, `azure_resources`, `amazon_resources`, `google_cloud_resources`. Each kind is a list of mappings, as in Graph. A field is the Graph property without its `Column` suffix, in snake_case (`deviceIdColumn` → `device_id`), and its value is the result column, sent verbatim. All seventeen are in 2.0 because the type is identical in Graph v1.0 and beta, the same custom detection reads Office, Identity, and Cloud Apps tables, and leaving kinds out would only force a 2.1 later. Which kinds Defender actually surfaces is [question 6](#unresolved-questions).

Columns are now sent as written. 1.0 lower-cased the first character because Graph took an identifier enum (`deviceId`); `entityMappings` takes the column name (`DeviceId`).

**Schedule.** `schedule.frequency` keeps 1.0's five values, `NRT`, `1H`, `3H`, `12H`, `24H`, sent as `PT0S`, `PT1H`, `PT3H`, `PT12H`, `P1D`. Keeping the values makes migration a move, not a translation, and they are the frequencies Defender has offered. `schedule.lookback` (beta-only) is `<n>H` or `<n>D`, never shorter than the frequency and never with NRT, the two rules Graph states.

**Actions.** `actions` holds Graph's sixteen `automatedActionSet` members as snake_case keys, each a list of targets whose fields name result columns (`device_id`, `sha1`, `account_sid`, …), plus `isolation_type` and `device_groups`. Unlike 1.0, a device action names its device column; migration writes `DeviceId`, the column 1.0's implicit `deviceId` identifier meant.

**Scope and incident.** `scope.device_groups` replaces `scope.selection` and `scope.device_groups`; no `scope` means every device. `incident.exclude_from_correlation` (beta-only) sets `incidentConfiguration`.

**Status.** `PREVIEW`, `RELEASE`, and `UNIVERSAL` send `status: enabled`; `DISABLEMENT` sends `disabled`; `DELETION` deletes.

**Exclusions** are unchanged.

**Constraints and advisories.** Eleven constraint codes (`defender_frequency`, `defender_lookback`, `defender_severity`, `defender_grouping`, `defender_custom_details`, `defender_entity_kind`, `defender_entity_mapping`, `defender_action_kind`, `defender_action_target`, `defender_column`, `defender_scope`) and two advisories (`defender_schema_deprecated`, `defender_no_entities`).

### 3. Beta now, v1.0 later

The three beta-only keys are `schedule.lookback`, `alert.grouping`, and `incident`. The spec requires that deploy send a beta-only property only when its key is set, that a block without them produce a body holding only v1.0 properties, and that the deprecated properties never be sent. Every other property 2.0 sends has the same name and shape in v1.0, and v1.0's create also requires `detectionAction`, which 2.0 always sends. So a later move to `https://graph.microsoft.com/v1.0/security/rules/detectionRules` is a URL change for every rule that uses none of the three keys. That move is a later minor version; it has to decide what a block with a beta-only key does (stay on beta, or fail).

### 4. Identity: the uuid is the Defender rule id

Every call addresses `{base}/{uuid}`, the lowercase canonical `metadata.uuid`:

| Strategy | Calls |
|----------|-------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `PATCH {base}/{uuid}`; on `404`, `POST {base}` with `id: {uuid}`. A `409` on the `POST` (a concurrent create) is followed by one more `PATCH`. |
| `DISABLEMENT` | `PATCH {base}/{uuid}` with `status: disabled`; on `404`, nothing is created (`defender_rule_absent`, a warning), unless a legacy rule is being adopted. |
| `DELETION` | `DELETE {base}/{uuid}`; `404` is "already gone". |

`PATCH` first makes the steady state, an update, one call. A `404` on `PATCH` is the only absence signal; deploy never lists rules or matches names. No create needs deployment state, so the CI create guards (`deployment_state_ignored`, `deployment_state_unpersisted`) and `external_id_missing` no longer apply to Defender. `--prune` retires a deleted 2.0 rule by uuid, as for Sentinel and Elastic.

### 5. Rules opentide 1.x created

A tenant may hold a rule that opentide 1.x created under a Defender-assigned decimal id `L`, recorded in the rule's shard under `platforms.defender_for_endpoint.<tenant>`. Graph documents no way to change a rule's `id` (the update request has no `id`), so that rule can never become the uuid rule. Two choices:

- **(A) Recreate, then delete.** The first 2.0 deploy to the tenant deploys the uuid rule, then deletes `L`, then removes the binding.
- **(B) Keep a legacy binding.** Keep addressing `L` through the shard until the rule is retired, and use the uuid only for new rules.

This RFC chooses **(A)**:

- The owner's direction is that the uuid is the new truth. (B) keeps two identities for Defender indefinitely: every deploy path, status report, retirement, and CI guard would have to handle both, for as long as any rule created before 1.0 GA lives, and Defender would stay state-backed in practice.
- (A) is self-healing and needs no persisted state. If the run cannot commit the shard, the binding survives on the default branch; the next run's `DELETE {base}/L` answers `404` and removes it. Nothing is ever created from a shard, so the duplicate-rule failure RFC 0010 guards against cannot happen here.
- Order protects coverage: the uuid rule is deployed **before** `L` is deleted, so the tenant never lacks the detection. If the uuid rule fails, `L` is kept. If deleting `L` fails, both run until the next deploy retries (`defender_legacy_delete_failed`, an error).

What (A) costs: the alert and incident history stays attached to the legacy rule's alerts, and for the moment between the two calls both rules run and may both alert. Neither is avoidable without (B)'s permanent second identity.

Deployment-state changes ([deployment-state 1.9](../specs/deployment-state.md#legacy-defender-bindings)):

- `platforms.defender_for_endpoint` stays a valid key of `deployment.state::1.0`, with its decimal pattern, so every shard opentide 1.x wrote still validates. The shard schema and JSON Schema do not change.
- Deploy never writes a Defender binding. It removes one after retiring `L` (`204` or `404`), and `--prune` retires an orphan one by deleting `L`.
- `opentide deploy migrate-state` still moves a pre-RFC-0010 Defender `rule_id` key into a binding: that binding is what lets the next 2.0 deploy retire the rule.
- A 1.0 block never touches its binding: deploy refuses the block first.

### 6. Deprecation of 1.0

The 1.0 spec file gets `status: deprecated` and stays. A 1.0 block:

- **Is read.** Static validation applies the full 1.0 contract, so a broken 1.0 block still reports its real errors.
- **Warns.** `opentide validate` reports **`defender_schema_deprecated`** (warning) at `configurations.defender_for_endpoint.schema`, or at the block when `schema` is missing. The message says 1.0 is deprecated, that deploy refuses it, and to run `opentide migrate`, and links the migration table. The code follows the platform-prefixed naming of every other platform advisory, so it is unique and greppable; a later deprecation of another platform schema picks its own prefix.
- **Migrates.** `opentide migrate` rewrites the block key by key ([table](../specs/platforms/defender-for-endpoint-2.0.md#migration-from-10)). It edits only that block, calls nothing, and leaves deployment state alone. It maps every 1.0 `impacted_entities` value through Graph's former identifier enums (`deviceId` → `hosts.device_id`, `accountSid` → `accounts.sid`, `recipientEmailAddress` → `mailboxes.primary_address`, …), every device flag to an action on the `DeviceId` column, `allow_block` to `allow_files` or `block_files`, `quarantine_file` to `stop_and_quarantine_files`, and the user actions to their column. What cannot be mapped (`accountId`, `servicePrincipalId`, `servicePrincipalName`, `senderDisplayName`, a non-hash file identifier, a `Specific` selection with no groups) is the error **`defender_migrate_unmapped`**, and that block is left unchanged so the author maps it by hand rather than losing an entity or an action silently.
- **Is refused by deploy.** Deploy reports **`defender_schema_retired`** (error) for the block on each selected tenant, makes no call, touches no state, and exits 1; the rule's other platform blocks still deploy.

Why refuse rather than deploy through the 2.0 mapping: the old wire format no longer exists, so a 1.0 deploy could only be a translated 2.0 deploy; the translation is not total, so it would drop entities or response actions without the author seeing it; and the first 2.0 deploy recreates the rule under its uuid and deletes the old one, a tenant change that should follow a reviewed YAML diff, not a CLI upgrade. The owner wants clear warnings: the warning comes at validate time, before anything reaches a tenant, and the error at deploy names the one command that fixes it.

### 7. Fixtures

| Path | What it proves |
|------|----------------|
| `fixtures/platforms/defender-for-endpoint-2.0.yaml` | A valid 2.0 rule using every block key, beta-only keys included |
| `fixtures/platforms/defender-for-endpoint/rule-defender-2.0.create.api.json`, `.update.api.json`, `.disable.api.json` | The Graph bodies deploy sends for it, derived by the tests from the spec's tables |
| `fixtures/platforms/defender-for-endpoint/migrated-2.0.yaml` | `opentide migrate` of `fixtures/platforms/defender-for-endpoint.yaml` (1.0, kept) |
| `fixtures/invalid/rule-defender-lookback-nrt.yaml` | `defender_lookback` |
| `fixtures/invalid/rule-defender-entity-field.yaml` | `defender_entity_mapping` |
| `fixtures/invalid/rule-defender-action-target.yaml` | `defender_action_target` |
| `fixtures/invalid/rule-defender-1.0-keys.yaml` | `unknown_field`: 1.0 keys on a 2.0 block |

`scripts/test_platform_defender_for_endpoint.py` derives the three bodies and the migration from the spec's tables and compares them with the goldens.

### 8. Implementation notes for opentide

- A `DefenderConfigV2` model for `platform::defender_for_endpoint::2.0`, routed by `schema`; the 1.0 model stays for reading.
- The deployer: the beta base URL, `PATCH`-then-`POST`, the legacy retirement, no shard writes; `defender_schema_retired` for 1.0.
- `opentide migrate`: the Defender block rewrite and `defender_migrate_unmapped`.
- `generate extract` writes 2.0 blocks from the tenant's rules.
- The generated JSON Schema default for the Defender `schema` (`defender_for_endpoint::2.3` today, [platforms/index.md](../specs/platforms/index.md#generated-schema-drift)) and the bundled template become `platform::defender_for_endpoint::2.0`.

## Drawbacks

- Every Defender rule is replaced in every tenant on its first 2.0 deploy. Alert history stays on the old rule, and both rules briefly run.
- Beta can change without notice. opentide takes on that risk for three properties; section 3 keeps the exit to v1.0 cheap.
- Workspaces must run `opentide migrate` before their Defender rules deploy again. Rules whose 1.0 values cannot be mapped need a hand edit.
- Seventeen entity kinds and sixteen actions are a larger surface to validate and document than 1.0's three entities and nine actions.

## Alternatives

- **Keep `platform::defender_for_endpoint::1.0` and change the deployer.** The 1.0 block's shape is the removed wire format (`impacted_entities` as single columns, flag-style device actions with no column, `scheduling` strings), and it cannot express entity lists, email or file-hash actions, custom details, or lookback. A minor version cannot fix that without breaking every block.
- **Graph v1.0 now.** Loses lookback, event grouping, and incident correlation. Rejected by the owner; section 3 keeps it one step away.
- **Stay state-backed, with the uuid as the client id.** Recording an id that always equals `metadata.uuid` adds nothing and keeps all of RFC 0010's create guards for Defender.
- **Keep legacy bindings until each rule is retired (B in section 5).** Two permanent identities; rejected above.
- **Deploy 1.0 blocks through the 2.0 mapping.** Rejected in section 6.
- **Infer the schema from the block's keys.** A missing `schema` with 2.0-looking keys would be ambiguous with a broken 1.0 block. An explicit `schema` is one line.
- **An explicit `alert.tactics` key.** Rejected in section 2.

## Unresolved questions

The Graph documentation leaves these open. The spec takes the stated position; a live tenant should confirm each before 1.0.0 GA.

1. **NRT encoding.** `ruleSchedule.lookback` says NRT rules have "a zero frequency" but no document shows the value. The spec sends `PT0S`. Graph may expect `PT0M`, `P0D`, or refuse NRT through this API.
2. **404 on update and delete.** The update and delete pages document only `200` and `204`. The spec assumes `404` for an id the tenant does not have, on `PATCH` and on `DELETE`, and `409` for a `POST` whose `id` exists. If Graph answers otherwise (`400`, `403`), deploy must `GET {base}/{uuid}` first.
3. **PATCH semantics for nested objects.** The update page says an omitted `incidentConfiguration` value "leaves the existing setting unchanged". It does not say whether a `PATCH` replaces `detectionAction.alertTemplate`, `entityMappings`, `automatedActions`, `organizationalScope`, or `customDetails` wholesale or merges them, nor whether an omitted `lookback` or `eventGroupingKind` resets to the default. If they merge, removing a key from the YAML would not clear it in the tenant; a 2.x minor would then send explicit empty values (`[]`, `{}`, `alertPerEvent`, `false`) where Graph v1.0 also accepts them.
4. **Tactic values.** `mitreTactic.tactic` is documented with the example `Exploit`, not an ATT&CK tactic, while the create example sends `Execution`. The spec sends ATT&CK tactic names without spaces (`InitialAccess`, `DefenseEvasion`, `CommandAndControl`). Whether Graph wants that form, display names, or `TA` ids, and whether it knows ATT&CK v19 technique ids (sent as resolved), is open.
5. **Technique nesting.** The create example puts `T1059.001` in `technique`, while `mitreTechnique.subTechniques` is documented for sub-technique ids. The spec sends the parent in `technique` and the sub-technique in `subTechniques`.
6. **Which entity mappings Defender honours.** All seventeen kinds are documented on one type shared by every Defender XDR product. Which ones a Defender for Endpoint tenant (without Office, Identity, or Cloud Apps) accepts or shows, which columns each kind needs to resolve an entity, and whether a rule must map at least one entity, are not documented. The spec accepts every kind, requires one field per mapping, and only warns (`defender_no_entities`) when there is none.
7. **Frequencies and lookback bounds.** Whether `frequency` accepts durations other than the five 1.0 values, and the maximum `lookback`, are not documented. The spec keeps the five values and only enforces lookback ≥ frequency.
8. **The client id.** The documented constraints on `id` (characters, length, case) are none. The spec assumes a 36-character lowercase uuid is accepted and that ids are compared exactly.
9. **Legacy ids on the beta endpoint.** The spec assumes a rule created through the old contract is addressable at `{base}/{decimal id}` on beta, so that it can be deleted there.
10. **Custom detail limits.** The number of custom details, and the characters a name may hold, are not documented.

## References

- Microsoft Graph documentation source, beta: [`detectionRule`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-detectionrule.md), [`alertTemplate`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-alerttemplate.md), [`detectionAction`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-detectionaction.md), [`ruleSchedule`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-ruleschedule.md), [`queryCondition`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-querycondition.md), [`entityMappingConfiguration`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-entitymappingconfiguration.md) and its seventeen `*EntityMapping` types, [`mitreTactic`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-mitretactic.md), [`mitreTechnique`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-mitretechnique.md), [`automatedActionSet`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-automatedactionset.md) and its action types, [`organizationalScope`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-organizationalscope.md), [`incidentConfiguration`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-incidentconfiguration.md), [`alertCustomDetails`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-alertcustomdetails.md), [`enums-security`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/enums-security.md) (the former `impactedAsset` and `responseAction` identifier enums migration maps from), [create](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-rulesroot-post-detectionrules.md), [update](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-detectionrule-update.md), [delete](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-rulesroot-delete-detectionrules.md).
- The same paths under `api-reference/v1.0/` for the v1.0 comparison in section 3.
- [RFC 0010](0010-deployment-external-ids.md) — deployment external ids, superseded here for Defender
- [RFC 0007](0007-elastic-security-platform.md) — Elastic, the precedent for `metadata.uuid` as the vendor rule id
- [specs/platforms/defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md) 1.3 — `alert.category` removed for the same Graph deprecation ([opentide#1704](https://github.com/opentidehq/opentide/issues/1704))
