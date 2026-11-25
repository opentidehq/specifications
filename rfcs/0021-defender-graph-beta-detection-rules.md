# RFC 0021: Microsoft Defender on the Graph beta custom detection contract

- **RFC:** 0021
- **Title:** Microsoft Defender on the Graph beta custom detection contract (`microsoft_defender`)
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-24
- **Accepted:** 2026-11-25, by the owner. opentide 1.0 ships Microsoft Defender as `microsoft_defender` on the Microsoft Graph beta custom detection contract, with the rule's `metadata.uuid` as the Defender rule id. The pre-1.0 `defender_for_endpoint` platform is removed and has no successor path. The normative text is:
  - [specs/platforms/microsoft-defender-1.0.md](../specs/platforms/microsoft-defender-1.0.md) 1.0;
  - [specs/platforms/defender-for-endpoint-1.0.md](../specs/platforms/defender-for-endpoint-1.0.md) 1.4 (removed, kept as a record);
  - [specs/deployment-state.md](../specs/deployment-state.md) 1.10, [specs/deployment.md](../specs/deployment.md) 1.5, [specs/workspace.md](../specs/workspace.md) 1.6;
  - [specs/platforms/index.md](../specs/platforms/index.md) 1.11, [specs/validation.md](../specs/validation.md) 1.16, [specs/visibility.md](../specs/visibility.md) 1.2.
- **Supersedes:** [RFC 0010](0010-deployment-external-ids.md) for Microsoft Defender for Endpoint only
- **Issue:** [#104](https://github.com/opentidehq/specifications/issues/104)
- **Implementation:** to be tracked in [opentidehq/opentide](https://github.com/opentidehq/opentide) issues, for 1.0.0 GA.

## Summary

opentide 1.0 adds **`microsoft_defender`** (Microsoft Defender), a Microsoft Defender XDR custom detection platform with the block schema **`platform::microsoft_defender::1.0`**. Its contract is the Microsoft Graph **beta** custom detection API, `https://graph.microsoft.com/beta/security/rules/detectionRules`. The block models every writable beta property, and its constraints are the ones the docs state:

- `schedule`: an ISO 8601 frequency and a beta lookback;
- `alert`: title, description, severity, recommendation, techniques, custom details, and beta event grouping, with `tactics` derived from the techniques through the bundled ATT&CK vocabulary;
- `entities`: Graph's seventeen entity kinds;
- `actions`: Graph's sixteen automated actions;
- `scope.device_groups`, a beta `incident` block, and `status` from the deployment status.

The Defender rule id is the rule's **`metadata.uuid`**. Graph takes a client-provided `id` on create, so the platform is addressed like Sentinel and Elastic and keeps no deployment state.

The pre-1.0 `defender_for_endpoint` platform is removed. opentide 1.0 is the first release, and that platform existed only in pre-1.0 betas, so it has no deprecation period, migration, or legacy handling. `configurations.defender_for_endpoint` is an unknown key, and its shard key is gone.

## Motivation

Microsoft deprecated, then removed on 2026-10-01, the custom detection properties the pre-1.0 `defender_for_endpoint` platform deployed to:

- `isEnabled`, `schedule.period`, `alertTemplate.category`, `alertTemplate.mitreTechniques`, `alertTemplate.impactedAssets`, `detectionAction.responseActions`, and `organizationalScope.scopeType` and `scopeNames`;
- their replacements: `status`, `schedule.frequency`, `alertTemplate.tactics`, `alertTemplate.entityMappings`, `detectionAction.automatedActions`, and `organizationalScope.deviceGroups`.

That platform's block had the shape of the removed wire format and could not be repaired with a minor version. The create request now takes a client-provided `id` ("the client-provided unique identifier of the rule. Required."), so the rule's `metadata.uuid` can be the Defender rule id in every tenant, and the deployment-state machinery of [RFC 0010](0010-deployment-external-ids.md) is not needed.

Beta rather than v1.0: Microsoft is slow to promote features to v1.0, and the beta-only ones (lookback, event grouping, incident correlation) are needed. Microsoft has also dropped the "for Endpoint" name; the custom detection rule is a Defender XDR object that reads Endpoint, Office 365, Identity, and Cloud Apps tables.

## Detailed design

### 1. Affected specs

| Path | Change |
|------|--------|
| `specs/platforms/microsoft-defender-1.0.md` | **New**, spec version 1.0, `schema_id: platform::microsoft_defender::1.0`, `status: normative`. |
| `specs/platforms/defender-for-endpoint-1.0.md` | 1.3 → **1.4**: marked removed (`status: deprecated`, the term [GOVERNANCE](../GOVERNANCE.md) has for a withdrawn spec), kept as a record, defining no behaviour. Its fixture is removed. |
| `specs/deployment-state.md` | 1.9 → **1.10**. `defender_for_endpoint` leaves the state-backed platforms and the shard; `microsoft_defender` keeps no shard. The shard JSON Schema drops the key. |
| `specs/deployment.md` | 1.4 → **1.5**. Microsoft Defender needs no binding; `--prune` retires a deleted rule by uuid. |
| `specs/platforms/index.md` | 1.10 → **1.11**. Schema table, capability matrix, `--live` allowlist, static-validation bar, external-id table, generated defaults. |
| `specs/validation.md` | 1.15 → **1.16**. `--live` allowlist; advisory `microsoft_defender_no_entities`; fixture checker. |
| `specs/workspace.md` | 1.5 → **1.6**. Shard directory description. |
| `specs/visibility.md` | 1.1 → **1.2**. The Defender KQL system is `microsoft_defender`. |
| `specs/objects/rule-1.0.md`, `rule-1.1.md` | `configurations.microsoft_defender` replaces `configurations.defender_for_endpoint`. |
| `specs/platforms/exabeam-1.0.md` | Prose: no longer cites Defender for Endpoint as state-backed. |
| `rfcs/0010-deployment-external-ids.md` | Marked superseded in part, for Defender for Endpoint. |
| `SPECS.md`, `CHANGELOG.md`, `rfcs/README.md`, `llms.txt`, `site/meta.json` | Index rows. |

Vocabularies: none change.

### 2. The platform and its block

**Name.** The configuration key is `microsoft_defender`, the display name "Microsoft Defender", and the schema `platform::microsoft_defender::1.0`. The same identifier is used for the `--platform` value, the tenants configuration (`.opentide/configurations/platforms/microsoft_defender.toml`), the capability matrix, the `--live` allowlist, and visibility log sources.

**`alert`.** Severity defaults to `response.alert_severity`, and then to `Medium`. `Critical` is sent as `high`, Graph's highest.

**Tactics.** Graph nests techniques in tactics: `tactics: [{tactic, techniques: [{technique, subTechniques}]}]`. Deploy derives that tree from the technique ids, which are `alert.techniques` or else the objective's. Each id's `tide.vocab.stages` in the bundled `att&ck` vocabulary gives its tactics, and a sub-technique files under its parent. Stealth and Defense Impairment (ATT&CK v19's split of Defense Evasion) both send `DefenseEvasion`, as Sentinel does. Non-Enterprise and unknown ids are left out with a warning. There is **no explicit `alert.tactics` key**: a tactic is only meaningful in Graph with the techniques under it, the vocabulary already knows each technique's tactics, and a hand-written list could only repeat or contradict them.

**Entities.** `entities` covers all seventeen kinds of Graph's `entityMappingConfiguration`, each a list of mappings. A field is the Graph property without its `Column` suffix, in snake_case (`deviceIdColumn` → `device_id`), and its value is the result column, sent verbatim.

**Schedule.** `schedule.frequency` is `NRT`, `<n>H`, or `<n>D`, sent as an ISO 8601 duration (`PT0S` for NRT). `schedule.lookback` (beta-only) is `<n>H` or `<n>D`.

**Actions.** `actions` holds Graph's sixteen `automatedActionSet` members as snake_case keys. Each is a list of targets whose fields name result columns, plus `isolation_type` and `device_groups`.

**Scope, incident, status, exclusions.** `scope.device_groups`; with no `scope`, the rule applies to every device. `incident.exclude_from_correlation` (beta-only). `PREVIEW`, `RELEASE`, and `UNIVERSAL` send `status: enabled`, `DISABLEMENT` sends `disabled`, and `DELETION` deletes. KQL exclusions take Sentinel's shape.

**Codes.** Every code uses the platform identifier as its prefix, `microsoft_defender_`, as every other platform does (`google_secops_`, `bitdefender_`, `graylog_`). That keeps codes unique across platform specs ([validation.md](../specs/validation.md#platform-advisories)) and findable by searching for the platform. Shorter prefixes were rejected:

- `mde_` names Defender for Endpoint;
- `defender_` matches Bitdefender's `bitdefender_` codes in a plain-text search;
- an abbreviation is something readers must decode.

The codes:

- constraints: `microsoft_defender_schema`, `_frequency`, `_lookback`, `_severity`, `_grouping`, `_custom_details`, `_entity_kind`, `_entity_mapping`, `_action_kind`, `_action_target`, `_isolation_type`, `_column`, `_scope`, `_incident`;
- advisory: `microsoft_defender_no_entities`;
- deploy warning: `microsoft_defender_rule_absent`.

### 3. The beta API is the contract

The deployer always calls the beta endpoint, and no setting changes that.

**Completeness.** The spec's [Beta API coverage](../specs/platforms/microsoft-defender-1.0.md#beta-api-coverage) accounts for every property of every type the API uses: `detectionRule`, `queryCondition`, `ruleSchedule`, `detectionAction`, `alertTemplate`, `alertCustomDetails`, `entityMappingConfiguration` and the seventeen `*EntityMapping` types, `mitreTactic`, `mitreTechnique`, `automatedActionSet` and its seven action types, `organizationalScope`, and `incidentConfiguration`. That is 130 properties in 36 types. Each is modelled by a key of the block, or listed under "Beta properties not modelled" with one of three reasons:

- **read-only:** `createdBy`, `createdDateTime`, `lastModifiedBy`, `lastModifiedDateTime`;
- **deprecated:** `isEnabled`, `detectorId`, `lastRunDetails`, `queryCondition.lastModifiedDateTime`, `period`, `nextRunDateTime`, `category`, `impactedAssets`, `mitreTechniques`, `responseActions`, `scopeType`, `scopeNames`;
- **set by deploy:** `id`, `displayName`, `description`, `status`, `queryText`, `alertTemplate.tactics`, and the four `mitreTactic` and `mitreTechnique` properties.

The enum values not accepted are listed too: `autoDisabled`, which Defender sets, and every enum's `unknownFutureValue` sentinel. [fixtures/platforms/microsoft-defender/graph-beta-properties.json](../fixtures/platforms/microsoft-defender/graph-beta-properties.json) snapshots the docs' Properties tables and enums. A test fails when a snapshot property is neither modelled nor listed, or when a listed reason contradicts the docs' read-only or deprecated marks.

**Validation from the docs.** Every modelled property is checked against what the beta docs state:

- enum values: `alertTemplate.severity` is `informational`, `low`, `medium`, or `high`; `eventGroupingKind` is `alertPerEvent` or `singleAlert`; `isolationType` is `full` or `selective`;
- lookback ≥ frequency;
- no lookback with a zero (NRT) frequency.

Every listed enum value is accepted, and anything else is rejected under a named code. Where the docs say nothing, the spec says so instead of inventing a rule. The docs give no allowed frequencies, no maximum lookback, no required field in an entity mapping or action target, and no custom-detail limits. The few opentide shape rules (a mapping or target is not empty, `scope` is not an empty list) are marked as opentide's.

**v1.0, for information.** Every property the block sends, except `schedule.lookback`, `alertTemplate.eventGroupingKind`, and `detectionAction.incidentConfiguration`, also exists in v1.0 with the same name and shape. A block that sets none of those three is therefore also a valid v1.0 request. That is a fact, not a plan: opentide does not target v1.0.

### 4. Identity and calls

Every call addresses `{base}/{uuid}`, the lowercase canonical `metadata.uuid`:

| Strategy | Calls |
|----------|-------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `PATCH {base}/{uuid}`; on `404`, `POST {base}` with `id: {uuid}`. A `409` on the `POST` (a concurrent create) is followed by one more `PATCH`. |
| `DISABLEMENT` | `PATCH {base}/{uuid}` with `status: disabled`; on `404`, nothing is created (`microsoft_defender_rule_absent`, a warning). |
| `DELETION` | `DELETE {base}/{uuid}`; `404` is "already gone". |

Trying `PATCH` first makes the steady state, an update, a single call. A `404` on `PATCH` is the only absence signal; deploy never lists rules or matches names. No create needs deployment state, so the CI create guards (`deployment_state_ignored`, `deployment_state_unpersisted`) and `external_id_missing` do not apply. `--prune` retires a deleted rule by uuid, as for Sentinel and Elastic.

### 5. Fixtures

| Path | What it proves |
|------|----------------|
| `fixtures/platforms/microsoft-defender.yaml` | A valid rule with beta-only keys |
| `fixtures/platforms/microsoft-defender-complete.yaml` and `fixtures/platforms/microsoft-defender/rule-microsoft-defender-complete.create.api.json` | Every key of every field table set once, and its create body; also the spec's complete example |
| `fixtures/platforms/microsoft-defender/rule-microsoft-defender.create.api.json`, `.update.api.json`, `.disable.api.json` | The Graph bodies deploy sends, derived by the tests from the spec's tables |
| `fixtures/platforms/microsoft-defender/graph-beta-properties.json` | The beta docs snapshot the coverage test reads |
| `fixtures/invalid/rule-microsoft-defender-lookback-nrt.yaml` | `microsoft_defender_lookback` |
| `fixtures/invalid/rule-microsoft-defender-entity-field.yaml` | `microsoft_defender_entity_mapping` |
| `fixtures/invalid/rule-microsoft-defender-action-target.yaml` | `microsoft_defender_action_target` |
| `fixtures/invalid/rule-microsoft-defender-unknown-key.yaml` | `unknown_field` |

`scripts/test_platform_microsoft_defender.py` derives the bodies from the spec's tables and compares them with the goldens. It also checks beta coverage, checks the complete block against the field tables, and checks the spec's example against the fixture.

### 6. Implementation notes for opentide

- The `microsoft_defender` platform: a `MicrosoftDefenderConfig` model, a bundled `platforms/microsoft_defender.toml`, a deployer (beta URL; `PATCH` then `POST`; no deployment state), and a KQL query validator.
- `defender_for_endpoint` is deleted: its model, loader, deployer, configuration, and shard key. A block, a `--platform` value, or a shard entry with that name gets the generic error for an unknown key, platform, or shard platform.
- `generate extract` writes `microsoft_defender` blocks.
- The bundled rule template carries every key the spec defines, in the order and with the column names of the spec's [complete block](../specs/platforms/microsoft-defender-1.0.md#examples) (`fixtures/platforms/microsoft-defender-complete.yaml`). The required keys (`query`, `schedule.frequency`) are set, every optional key is present but commented out, and the beta-only keys are marked.
- The generated JSON Schema default for `schema` is `platform::microsoft_defender::1.0`.

## Drawbacks

- Beta can change without notice. opentide takes that risk deliberately; the coverage test, re-run against a fresh snapshot, shows what changed.
- Seventeen entity kinds and sixteen actions are a large surface to validate and document.
- Pre-1.0 beta users of `defender_for_endpoint` rewrite their blocks by hand, and remove by hand any tenant rules those betas created.

## Alternatives

- **Graph v1.0.** Loses lookback, event grouping, and incident correlation, which are needed.
- **Keep the name `defender_for_endpoint`, with a 2.0 schema.** Keeps a name Microsoft has dropped and needs schema inference under one key.
- **State-backed, with the uuid as the client id.** Recording an id that always equals `metadata.uuid` adds nothing.
- **An explicit `alert.tactics` key, or a shorter code prefix.** Rejected in section 2.

## Unresolved questions

The Graph documentation leaves these open. The spec takes the stated position; a live tenant should confirm each before 1.0.0 GA.

1. **NRT encoding.** `ruleSchedule.lookback` says NRT rules have "a zero frequency" but no document shows the value. The spec sends `PT0S`. Graph may expect `PT0M`, `P0D`, or refuse NRT through this API.
2. **404 on update and delete.** The update and delete pages document only `200` and `204`. The spec assumes `404` for an id the tenant does not have, on `PATCH` and on `DELETE`, and `409` for a `POST` whose `id` exists. If Graph answers otherwise (`400`, `403`), deploy must `GET {base}/{uuid}` first.
3. **PATCH semantics for nested objects.** The update page says an omitted `incidentConfiguration` value "leaves the existing setting unchanged". It does not say whether a `PATCH` replaces `detectionAction.alertTemplate`, `entityMappings`, `automatedActions`, `organizationalScope`, or `customDetails` wholesale or merges them, nor whether an omitted `lookback` or `eventGroupingKind` resets to the default. If they merge, removing a key from the YAML would not clear it in the tenant; a 1.x minor would then send explicit empty values (`[]`, `{}`, `alertPerEvent`, `false`).
4. **Tactic values.** `mitreTactic.tactic` is documented with the example `Exploit`, not an ATT&CK tactic, while the create example sends `Execution`. The spec sends ATT&CK tactic names without spaces (`InitialAccess`, `DefenseEvasion`, `CommandAndControl`). Whether Graph wants that form, display names, or `TA` ids, and whether it knows ATT&CK v19 technique ids (sent as resolved), is open.
5. **Technique nesting.** The create example puts `T1059.001` in `technique`, while `mitreTechnique.subTechniques` is documented for sub-technique ids. The spec sends the parent in `technique` and the sub-technique in `subTechniques`.
6. **Which entity mappings Defender honours.** All seventeen kinds are documented on one type shared by every Defender XDR product. Which ones a tenant with only Defender for Endpoint (no Office 365, Identity, or Cloud Apps) accepts or shows, which columns each kind needs to resolve an entity, and whether a rule must map at least one entity, are not documented. The spec accepts every kind, requires one field per mapping (an opentide shape rule), and only warns (`microsoft_defender_no_entities`) when there is none. The same holds for action targets: the docs name no required field.
7. **Frequencies and lookback bounds.** Which frequencies Defender accepts, and the maximum `lookback`, are not documented. The spec accepts any `NRT`, `<n>H`, or `<n>D` and enforces only what the docs state (lookback ≥ frequency, none with NRT); Defender's answer at deploy decides the rest. The frequencies Defender has offered are `NRT`, `1H`, `3H`, `12H`, and `24H`.
8. **The client id.** The documented constraints on `id` (characters, length, case) are none. The spec assumes a 36-character lowercase uuid is accepted and that ids are compared exactly.
9. **Custom detail limits.** The number of custom details, and the characters a name may hold, are not documented.

## References

- Microsoft Graph documentation source, beta: [`detectionRule`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-detectionrule.md), [`alertTemplate`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-alerttemplate.md), [`detectionAction`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-detectionaction.md), [`ruleSchedule`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-ruleschedule.md), [`queryCondition`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-querycondition.md), [`entityMappingConfiguration`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-entitymappingconfiguration.md) and its seventeen `*EntityMapping` types, [`mitreTactic`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-mitretactic.md), [`mitreTechnique`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-mitretechnique.md), [`automatedActionSet`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-automatedactionset.md) and its action types, [`organizationalScope`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-organizationalscope.md), [`incidentConfiguration`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-incidentconfiguration.md), [`alertCustomDetails`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/security-alertcustomdetails.md), [`enums-security`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/resources/enums-security.md), [create](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-rulesroot-post-detectionrules.md), [update](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-detectionrule-update.md), [delete](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/security-rulesroot-delete-detectionrules.md).
- The same paths under `api-reference/v1.0/`, for the informational note in section 3.
- [RFC 0010](0010-deployment-external-ids.md) — deployment external ids; superseded here for Defender for Endpoint, which this RFC removes
- [RFC 0007](0007-elastic-security-platform.md) — Elastic, the precedent for `metadata.uuid` as the vendor rule id
- [opentidehq/specifications#104](https://github.com/opentidehq/specifications/issues/104) — the spec-change issue
