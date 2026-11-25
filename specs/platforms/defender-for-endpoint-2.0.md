---
spec: platform-defender-for-endpoint
version: "2.0"
schema_id: platform::defender_for_endpoint::2.0
status: normative
supersedes: platform::defender_for_endpoint::1.0
---

# Microsoft Defender for Endpoint (`platform::defender_for_endpoint::2.0`)

## Summary

`configurations.defender_for_endpoint` with `schema: platform::defender_for_endpoint::2.0` is a Microsoft Defender XDR custom detection rule, deployed through the Microsoft Graph **beta** custom detection API, `https://graph.microsoft.com/beta/security/rules/detectionRules`. The detection text is KQL (advanced hunting). Query validation is supported.

The Defender rule id is the rule's `metadata.uuid`. Graph takes a client-provided `id` on create, so opentide addresses the rule as Sentinel and Elastic do, and keeps no Defender id in [deployment state](../deployment-state.md). A tenant rule that opentide 1.x created under a Defender-assigned id is retired by the first 2.0 deploy ([Legacy rules](#legacy-rules)).

This schema replaces [`platform::defender_for_endpoint::1.0`](defender-for-endpoint-1.0.md), which is deprecated: Microsoft removed every property 1.0 maps to, other than the query, title, description, severity and recommended actions, on 2026-10-01. `opentide migrate` rewrites a 1.0 block to 2.0 ([Migration from 1.0](#migration-from-10)). The proposal is [RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md).

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- A 2.0 block MUST set `schema: platform::defender_for_endpoint::2.0`. A Defender block whose `schema` is missing, `platform::defender_for_endpoint::1.0`, or a legacy identifier (`defender_for_endpoint::2.3` and the same shape) is a [1.0 block](defender-for-endpoint-1.0.md).
- Static validation MUST require `query` and `schedule.frequency`. `query` MUST be non-blank KQL. Every other key MAY be omitted.
- Unknown keys MUST fail static validation, at any level of the block. The 1.0 keys `scheduling`, `impacted_entities`, and `alert.category` are unknown keys in 2.0.
- The block MUST NOT contain `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>`. Each fails `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).
- Static validation MUST reject a block that breaks a [constraint](#constraints), under its code.
- Deploy MUST address the Defender rule by the lowercase canonical `metadata.uuid`: the create body's `id` and the `{id}` of every update and delete. Deploy MUST NOT read, write, or create a `defender_for_endpoint` binding in deployment state, except to retire a [legacy rule](#legacy-rules).
- Deploy MUST send the [beta-only](#beta-only-keys) properties only when their key is set. A block that sets no beta-only key MUST produce a request body that holds only properties the Graph v1.0 `detectionRule` also defines.
- Deploy MUST derive the alert's MITRE tactics from its techniques through the bundled `att&ck` vocabulary ([ATT&CK](#attck)). There is no key that sets tactics.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL. Multiline. Compiled with matching `exclusions` before deploy. |
| `schedule` | [DefenderSchedule](#schedule-defenderschedule) | yes | — | How often the rule runs, and how far back each run reads. |
| `alert` | [DefenderAlert](#alert-defenderalert) | optional | null | The alert template. Every field has a deploy-time default. |
| `entities` | [DefenderEntities](#entities-defenderentities) | optional | null | Result columns mapped to the alert's entities. Replaces 1.0 `impacted_entities`. |
| `actions` | [DefenderActions](#actions-defenderactions) | optional | null | Automated actions run on the entities a detection finds. Replaces 1.0 `actions`. |
| `scope` | [DefenderScope](#scope-defenderscope) | optional | null | Device groups the rule applies to. Omitted: every device. |
| `incident` | [DefenderIncident](#incident-defenderincident) | optional | null | Incident correlation. **Beta-only.** |
| `exclusions` | list[[DefenderExclusion](#exclusions-defenderexclusion)] | optional | null | Per-tenant KQL fragments appended to `query`. |

### `schedule` (DefenderSchedule)

| Field | Type | Required | Default | Graph | Description |
|-------|------|----------|---------|-------|-------------|
| `frequency` | string | yes | — | `schedule.frequency` | `NRT`, `1H`, `3H`, `12H`, or `24H`. |
| `lookback` | string | optional | null | `schedule.lookback` | **Beta-only.** How far back each run reads: `<n>H` or `<n>D`, `n` a positive integer without a leading zero. MUST NOT be shorter than `frequency`. MUST NOT be set with `frequency: NRT`. Omitted, Defender derives the lookback from the frequency. |

`frequency` is sent as an ISO 8601 duration:

| `frequency` | `schedule.frequency` |
|-------------|----------------------|
| `NRT` | `PT0S` (near real time: Graph's zero frequency) |
| `1H` | `PT1H` |
| `3H` | `PT3H` |
| `12H` | `PT12H` |
| `24H` | `P1D` |

`lookback` `<n>H` is sent as `PT<n>H` and `<n>D` as `P<n>D`. For the comparison with `frequency`, `1D` is `24H`.

### `alert` (DefenderAlert)

| Field | Type | Required | Default | Graph | Description |
|-------|------|----------|---------|-------|-------------|
| `title` | string | optional | rule `name` | `alertTemplate.title` | Alert title. |
| `description` | string | optional | rule `description` | `alertTemplate.description` | Alert description. |
| `severity` | string | optional | `response.alert_severity`, else `Medium` | `alertTemplate.severity` | `Informational`, `Low`, `Medium`, `High`, or `Critical`, sent lower-cased; `Critical` is sent as `high`. |
| `recommendation` | string | optional | null | `alertTemplate.recommendedActions` | Recommended actions text. Not sent when unset. |
| `techniques` | list[string] | optional | null | `alertTemplate.tactics` | MITRE ATT&CK technique or sub-technique ids (`T1528`, `T1059.001`). An empty list counts as unset. Left out, the techniques of the rule's objective are used. Sent grouped by tactic ([ATT&CK](#attck)). |
| `custom_details` | map[string, string] | optional | null | `alertTemplate.customDetails` | Alert custom details: detail name to result column. Not sent when unset. |
| `grouping` | string | optional | null | `alertTemplate.eventGroupingKind` | **Beta-only.** `alert_per_event` (sent as `alertPerEvent`) or `single_alert` (`singleAlert`). `single_alert` groups the events of one run into one alert; it does not merge alerts across runs. Omitted, Defender creates one alert per event. |

A `custom_details` name is a non-blank string. A value is a [column name](#column-names).

### ATT&CK

The alert's `tactics` are derived, never written. The technique ids are `alert.techniques` when it is set and not empty, and the techniques of the rule's objective (through `detection_model`) otherwise; the two are never merged.

1. Keep Enterprise techniques only. An id missing from the bundled `att&ck` vocabulary, or whose vocabulary name starts with `Mobile : ` or `Industrial : `, is left out, and deploy warns naming it.
2. Each id yields its parent technique (the id before `.`, or the id itself) and, for a sub-technique, the sub-technique.
3. Map each id's `tide.vocab.stages` to Graph tactics with the table below. A sub-technique uses its own stages. A stage outside the table emits no tactic.
4. Emit one `mitreTactic` per tactic, in table order: `{"tactic": <tactic>, "techniques": [...]}`. Under it, one `mitreTechnique` per parent technique, sorted by id: `{"technique": "T1059", "subTechniques": ["T1059.001"]}`, its sub-techniques sorted. `subTechniques` is omitted when empty. A parent named only through a sub-technique is listed under the sub-technique's tactics.
5. With no technique left, `tactics` is not sent.

| `att&ck` stage | Graph `tactic` |
|----------------|----------------|
| Reconnaissance | `Reconnaissance` |
| Resource Development | `ResourceDevelopment` |
| Initial Access | `InitialAccess` |
| Execution | `Execution` |
| Persistence | `Persistence` |
| Privilege Escalation | `PrivilegeEscalation` |
| Stealth, Defense Impairment, Defense Evasion (legacy) | `DefenseEvasion` |
| Credential Access | `CredentialAccess` |
| Discovery | `Discovery` |
| Lateral Movement | `LateralMovement` |
| Collection | `Collection` |
| Command and Control | `CommandAndControl` |
| Exfiltration | `Exfiltration` |
| Impact | `Impact` |

ATT&CK v19 renamed Defense Evasion (TA0005) to Stealth and split Defense Impairment (TA0112) out of it; Defender's tactic list predates the split, so both are sent as `DefenseEvasion`, as Sentinel does. Stealth and Defense Impairment for one technique yield one `DefenseEvasion` entry.

There is no `alert.tactics` key. Graph nests techniques inside tactics, and the vocabulary already records each technique's tactics, so a separate list could only repeat the techniques or contradict them.

### Column names

Every value that names a result column (entity mappings, action targets, custom details) is the column as the query's output spells it, sent verbatim. Deploy MUST NOT change its case. It MUST be a KQL identifier, `[A-Za-z_][A-Za-z0-9_]*` (`defender_column`). Whether the column exists in the query's output is checked by Defender at deploy, not by static validation.

1.0 lower-cased a column's first character because Graph then took an identifier enum (`deviceId`); 2.0 sends the column name itself (`DeviceId`).

### `entities` (DefenderEntities)

Each key is an entity kind and holds a list of mappings. A mapping is a map from field to [column name](#column-names) with at least one field. Each field is sent as the Graph property in the table, under `alertTemplate.entityMappings.<Graph kind>`. Omitted kinds are not sent; an empty `entities` sends no `entityMappings`.

A field's YAML key is its Graph property without the `Column` suffix, in snake_case.

| Kind | Graph kind | Fields (YAML → Graph property) |
|------|------------|--------------------------------|
| `hosts` | `hosts` | `device_id` → `deviceIdColumn`, `name` → `nameColumn`, `dns_domain` → `dnsDomainColumn`, `netbios_name` → `netBiosNameColumn`, `nt_domain` → `ntDomainColumn` |
| `accounts` | `accounts` | `aad_user_id` → `aadUserIdColumn`, `sid` → `sidColumn`, `upn` → `upnColumn`, `upn_suffix` → `upnSuffixColumn`, `name` → `nameColumn`, `nt_domain` → `ntDomainColumn`, `dns_domain` → `dnsDomainColumn` |
| `mailboxes` | `mailboxes` | `primary_address` → `primaryAddressColumn` |
| `files` | `files` | `name` → `nameColumn`, `sha1` → `sha1Column`, `sha256` → `sha256Column` |
| `processes` | `processes` | `sha1` → `sha1Column`, `sha256` → `sha256Column` |
| `ips` | `ips` | `address` → `addressColumn`, `scope` → `scopeColumn` |
| `urls` | `urls` | `address` → `addressColumn` |
| `dns` | `dns` | `domain_name` → `domainNameColumn`, `host_ip_address` → `hostIpAddressColumn`, `server_ip` → `serverIpColumn` |
| `registry_values` | `registryValues` | `key` → `keyColumn`, `value_name` → `valueNameColumn` |
| `mail_messages` | `mailMessages` | `network_message_id` → `networkMessageIdColumn`, `recipient` → `recipientColumn`, `sender` → `senderColumn`, `subject` → `subjectColumn` |
| `mail_clusters` | `mailClusters` | `query` → `queryColumn`, `source` → `sourceColumn` |
| `cloud_applications` | `cloudApplications` | `app_id` → `appIdColumn`, `name` → `nameColumn` |
| `oauth_applications` | `oAuthApplications` | `oauth_app_id` → `oAuthAppIdColumn` |
| `security_groups` | `securityGroups` | `object_id` → `objectIdColumn`, `sid` → `sidColumn`, `distinguished_name` → `distinguishedNameColumn` |
| `azure_resources` | `azureResources` | `resource_id` → `resourceIdColumn` |
| `amazon_resources` | `amazonResources` | `amazon_resource_id` → `amazonResourceIdColumn` |
| `google_cloud_resources` | `googleCloudResources` | `full_resource_name` → `fullResourceNameColumn` |

All seventeen kinds of Graph's `entityMappingConfiguration` are in 2.0. The same kinds are in Graph v1.0, so none is beta-only. Defender for Endpoint tables yield hosts, accounts, files, processes, ips, urls, and registry values; the other kinds come from the Defender for Office 365, Identity, and Cloud Apps tables that the same custom detection reads. Which mappings each product surfaces on the alert is not specified here ([RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md#unresolved-questions)).

### `actions` (DefenderActions)

Each key is an automated action and holds a list of targets. Each target is sent under `detectionAction.automatedActions.<Graph action>`. Omitted actions are not sent; an empty `actions` sends no `automatedActions`.

| Action | Graph action | Target fields | Required |
|--------|--------------|---------------|----------|
| `isolate_devices` | `isolateDevices` | `device_id` → `deviceIdColumn`; `isolation_type` → `isolationType`, `full` or `selective` | both |
| `collect_investigation_packages` | `collectInvestigationPackages` | `device_id` → `deviceIdColumn` | `device_id` |
| `run_antivirus_scans` | `runAntivirusScans` | `device_id` → `deviceIdColumn` | `device_id` |
| `initiate_investigations` | `initiateInvestigations` | `device_id` → `deviceIdColumn` | `device_id` |
| `restrict_app_executions` | `restrictAppExecutions` | `device_id` → `deviceIdColumn` | `device_id` |
| `allow_files` | `allowFiles` | `sha1` → `sha1Column`, `sha256` → `sha256Column`, `device_groups` → `deviceGroupNames` | `sha1` or `sha256` |
| `block_files` | `blockFiles` | `sha1` → `sha1Column`, `sha256` → `sha256Column`, `device_groups` → `deviceGroupNames` | `sha1` or `sha256` |
| `stop_and_quarantine_files` | `stopAndQuarantineFiles` | `device_id` → `deviceIdColumn`, `sha1` → `sha1Column` | both |
| `disable_users` | `disableUsers` | `account_sid` → `accountSidColumn` | `account_sid` |
| `force_user_password_resets` | `forceUserPasswordResets` | `account_sid` → `accountSidColumn` | `account_sid` |
| `mark_users_as_compromised` | `markUsersAsCompromised` | `account_object_id` → `accountObjectIdColumn` | `account_object_id` |
| `soft_delete_emails` | `softDeleteEmails` | `network_message_id` → `networkMessageIdColumn`, `recipient` → `recipientColumn` | both |
| `hard_delete_emails` | `hardDeleteEmails` | same as `soft_delete_emails` | both |
| `move_emails_to_deleted_items` | `moveEmailsToDeletedItems` | same as `soft_delete_emails` | both |
| `move_emails_to_inbox` | `moveEmailsToInbox` | same as `soft_delete_emails` | both |
| `move_emails_to_junk` | `moveEmailsToJunk` | same as `soft_delete_emails` | both |

Fields ending in `→ …Column` take a [column name](#column-names). `device_groups` is a non-empty list of device group names; omitted, the file action applies to every device group. The sixteen actions are Graph's `automatedActionSet` in both v1.0 and beta.

### `scope` (DefenderScope)

| Field | Type | Required | Graph | Description |
|-------|------|----------|-------|-------------|
| `device_groups` | list[string] | yes | `detectionAction.organizationalScope.deviceGroups` | Non-empty list of device group names, none blank. |

With no `scope`, `organizationalScope` is not sent and the rule applies to every device. 1.0's `selection: All` is the absent `scope`.

### `incident` (DefenderIncident)

**Beta-only.**

| Field | Type | Required | Graph | Description |
|-------|------|----------|-------|-------------|
| `exclude_from_correlation` | boolean | yes | `detectionAction.incidentConfiguration.isExcludedFromIncidentCorrelation` | `true`: each alert opens its own single-alert incident. `false`: alerts may be correlated with related alerts (Defender's default). |

### `exclusions[]` (DefenderExclusion)

Unchanged from 1.0. Same shape and tenant matching as Sentinel exclusions. See [sentinel-1.0.md](sentinel-1.0.md#exclusions-sentinelexclusion).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL fragment appended after the base query. The key is required. An empty string is accepted. |
| `reason` | string | yes | — | Why the exclusion exists. Not sent to Defender. |
| `tenant` | string | optional | null | Limit the exclusion to one tenant name. |
| `let` | map[string, scalar] | optional | null | KQL `let` bindings. String, number, or boolean. |

### Beta-only keys

These keys map to properties that Graph defines in `beta` only. They are the only reason 2.0 deploys through `beta`.

| Key | Graph property |
|-----|----------------|
| `schedule.lookback` | `schedule.lookback` |
| `alert.grouping` | `detectionAction.alertTemplate.eventGroupingKind` |
| `incident` | `detectionAction.incidentConfiguration` |

Every other property 2.0 sends exists with the same name and shape in Graph v1.0. Moving the deployer to `https://graph.microsoft.com/v1.0/security/rules/detectionRules` is a change of that URL alone for every block that sets none of these keys. Such a move is a later minor version of this spec; it would have to say what a block that sets a beta-only key does.

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code. Paths are under `configurations.defender_for_endpoint`.

| Code | Constraint | `field_path` |
|------|------------|--------------|
| `defender_frequency` | `schedule.frequency` is `NRT`, `1H`, `3H`, `12H`, or `24H`. | `schedule.frequency` |
| `defender_lookback` | `schedule.lookback` is `<n>H` or `<n>D`, `n` a positive integer without a leading zero; it is not set with `frequency: NRT`; it is not shorter than `frequency`. | `schedule.lookback` |
| `defender_severity` | `alert.severity` is `Informational`, `Low`, `Medium`, `High`, or `Critical`. | `alert.severity` |
| `defender_grouping` | `alert.grouping` is `alert_per_event` or `single_alert`. | `alert.grouping` |
| `defender_custom_details` | `alert.custom_details` is a map of non-blank names to strings. | `alert.custom_details` |
| `defender_entity_kind` | Every key of `entities` is a kind in the [entities](#entities-defenderentities) table. | `entities.<kind>` |
| `defender_entity_mapping` | Every kind holds a list; every mapping is a map with at least one field, and every field is one of its kind's fields. | `entities.<kind>.<N>` |
| `defender_action_kind` | Every key of `actions` is an action in the [actions](#actions-defenderactions) table. | `actions.<action>` |
| `defender_action_target` | Every action holds a non-empty list; every target has its action's required fields and no other field; `isolation_type` is `full` or `selective`; `device_groups` is a non-empty list of non-blank names. | `actions.<action>.<N>` |
| `defender_column` | Every column name (entity field, action column, custom detail value) is a non-empty string matching `[A-Za-z_][A-Za-z0-9_]*`. | the field |
| `defender_scope` | `scope.device_groups` is a non-empty list of non-blank names. | `scope` |

### Advisories

Advisories are [warnings](../validation.md#platform-advisories): validation reports them under their code and never rejects the rule.

| Code | When | Why |
|------|------|-----|
| `defender_schema_deprecated` | A Defender block is a [1.0 block](defender-for-endpoint-1.0.md#deprecation). | 1.0 is deprecated and deploy refuses it. The message MUST name `opentide migrate` and this spec. |
| `defender_no_entities` | A 2.0 block maps no entity (`entities` unset, empty, or every kind empty). | The alert names no device, user, or mailbox, so it cannot be triaged or acted on by entity. |

### Request body

Create and update send the same body. Create adds `id`; update omits it.

| Graph property | Value |
|----------------|-------|
| `id` | lowercase canonical `metadata.uuid` (create only) |
| `displayName` | block `name`, else rule `name` |
| `description` | rule `description` |
| `status` | from the [deployment status](#deployment-status) |
| `queryCondition.queryText` | `query` compiled with the tenant's matching `exclusions` |
| `schedule` | [`schedule`](#schedule-defenderschedule) |
| `detectionAction.alertTemplate` | [`alert`](#alert-defenderalert) with its defaults, `tactics` ([ATT&CK](#attck)), and `entityMappings` ([`entities`](#entities-defenderentities)) |
| `detectionAction.automatedActions` | [`actions`](#actions-defenderactions), when set |
| `detectionAction.organizationalScope` | [`scope`](#scope-defenderscope), when set |
| `detectionAction.incidentConfiguration` | [`incident`](#incident-defenderincident), when set (beta-only) |

A property whose key is unset is omitted, never sent as `null`. The deprecated Graph properties (`isEnabled`, `schedule.period`, `alertTemplate.category`, `alertTemplate.mitreTechniques`, `alertTemplate.impactedAssets`, `detectionAction.responseActions`, `organizationalScope.scopeType`, `organizationalScope.scopeNames`) MUST NOT be sent.

The goldens for the fixture rule are under [fixtures/platforms/defender-for-endpoint/](../../fixtures/platforms/defender-for-endpoint/).

### Deployment status

| Block status strategy | Graph `status` |
|-----------------------|----------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `enabled` |
| `DISABLEMENT` | `disabled` |
| `DELETION` | — (the rule is deleted) |
| `INERT` | — (not deployed) |

Defender sets `autoDisabled` on a rule that keeps failing. The next deploy of an enabled status sends `enabled` again.

### Deploy

Per rule and per tenant the run selected, with `{base}` = `https://graph.microsoft.com/beta/security/rules/detectionRules` and `{uuid}` the lowercase canonical `metadata.uuid`:

| Strategy | Calls | Result |
|----------|-------|--------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `PATCH {base}/{uuid}` with the body. On `404`, `POST {base}` with the body and `id`. | `update`, or `create` after a `404`. |
| `DISABLEMENT` | `PATCH {base}/{uuid}` with the body (`status: disabled`). On `404`: `POST` with `id` only when the tenant has a [legacy binding](#legacy-rules); otherwise no create. | `update`; `create` when adopting; otherwise `skipped` with `defender_rule_absent`. |
| `DELETION` | `DELETE {base}/{uuid}`. | `delete` on `204`; `skipped` ("already gone") on `404`. |
| `INERT` | none | not deployed |

- A `POST` answered `409` means the rule exists (a concurrent run created it). Deploy MUST send the `PATCH` once more and MUST NOT retry the `POST`.
- Any other non-2xx answer fails that rule on that tenant. Deploy continues with other tenants and rules and exits 1.
- A `404` on `PATCH` is the only signal that the rule is absent. Deploy MUST NOT list remote rules or match display names to find it.
- No create needs deployment state, so `deployment_state_ignored` and `deployment_state_unpersisted` never refuse a 2.0 create. A dry run makes no call and shows the call it would make first.
- `--prune` retires a deleted 2.0 rule by `DELETE {base}/{uuid}`, as Sentinel and Elastic do, and each orphan legacy binding by its id ([deployment.md](../deployment.md#retiring-deleted-rules)).

### Legacy rules

opentide 1.x created Defender rules under a Defender-assigned decimal id and recorded it as a binding under `platforms.defender_for_endpoint.<tenant>` in the rule's [deployment-state shard](../deployment-state.md). Graph does not let a client change a rule's `id`, so such a rule can never become the UUID-addressed rule. 2.0 replaces it: it deploys the UUID rule first, then deletes the legacy rule, then forgets the binding.

For a rule with a 2.0 block and a legacy binding `L` on a tenant the run deploys to, with any strategy but `INERT`, after the [Deploy](#deploy) calls:

| # | Situation | Calls | Result |
|---|-----------|-------|--------|
| 1 | The UUID rule's calls failed | none | `L` and its binding are kept. The legacy rule keeps running. The next run retries. |
| 2 | They succeeded, or the UUID rule was already gone (`DELETION`) | `DELETE {base}/L` | — |
| 2a | `204` or `404` | — | The binding is removed (then an empty platform map, then the shard), and `defender_legacy_retired` is logged at `WARNING` with tenant, `L`, and the uuid. |
| 2b | Any other answer | — | `defender_legacy_delete_failed` (error). The binding is kept; both rules run until the next deploy retries the delete. |
| 2c | The binding removal fails after `2a` | — | `deployment_state_write_failed` ([deployment-state.md](../deployment-state.md#deploy-decisions)). |

- The UUID rule is deployed before the legacy rule is deleted, so the tenant is never without the detection. Between the two calls both rules run and may each raise an alert.
- Alert and incident history stay on the legacy rule's alerts; the new rule starts its own.
- Retiring a legacy rule needs no persisted state. A run that cannot commit the shard leaves the binding on the default branch; the next run's `DELETE` answers `404` and removes it.
- A legacy binding on a tenant the run does not deploy to is left alone. `opentide deploy migrate-state` still moves a pre-RFC-0010 `rule_id` into a legacy binding, so that the next 2.0 deploy can retire that rule.
- A 1.0 block never retires a legacy rule: deploy refuses the block first ([defender-for-endpoint-1.0](defender-for-endpoint-1.0.md#deprecation)).

### Diagnostics

| Code | Level | Raised by | Meaning |
|------|-------|-----------|---------|
| `defender_schema_deprecated` | warning | validate | A [1.0 block](defender-for-endpoint-1.0.md#deprecation). The message names `opentide migrate`. |
| `defender_schema_retired` | error | deploy | Deploy of a 1.0 block, refused before any call to that tenant. The rule's other platform blocks still deploy. |
| `defender_migrate_unmapped` | error | migrate | A 1.0 value with no 2.0 equivalent ([Migration from 1.0](#migration-from-10)). The block is left unchanged. |
| `defender_rule_absent` | warning | deploy | `DISABLEMENT` found no rule with the uuid on the tenant, and the tenant has no legacy binding. Nothing is created. |
| `defender_legacy_delete_failed` | error | deploy | The legacy rule could not be deleted after the UUID rule deployed. |
| `defender_legacy_retired` | log record | deploy | A legacy rule was deleted and its binding removed. Like `external_id_recorded`, it is not a diagnostic: it does not set `DEPLOYMENT_WARNING_RAISED` or change the exit code. |

### Migration from 1.0

`opentide migrate` rewrites a [1.0 block](defender-for-endpoint-1.0.md) into a 2.0 block. It edits only the `configurations.defender_for_endpoint` block; the rest of the file stays byte-identical. It calls no API, deploys nothing, and does not touch deployment state. A rule whose block holds a value with no 2.0 equivalent is left unchanged and reported as `defender_migrate_unmapped`, naming each value; other rules still migrate. A 2.0 block is left unchanged.

A 1.0 column value `C` names Graph's identifier `c`, `C` with its first character lower-cased. Migration writes the column with its first character upper-cased (`deviceId` and `DeviceId` both become `DeviceId`), the column 1.0 deploy made Defender read.

| 1.0 key | 2.0 |
|---------|-----|
| `schema` (any 1.0 form, or missing) | `schema: platform::defender_for_endpoint::2.0` |
| `enabled`, `name`, `status`, `flags`, `tenants`, `contributors` | unchanged |
| `query`, `exclusions` | unchanged |
| `scheduling: X` | `schedule: {frequency: X}` |
| `alert.title`, `alert.description`, `alert.severity`, `alert.recommendation`, `alert.techniques` | unchanged |
| `alert.category` | dropped (already invalid in 1.0 since 1.3) |
| `impacted_entities.device` | `entities.hosts: [{<field>: C}]`: `device_id` for `deviceId`; `name` for `deviceName`, `remoteDeviceName`, `targetDeviceName`, `destinationDeviceName` |
| `impacted_entities.user` | `entities.accounts: [{<field>: C}]`: `aad_user_id` for `accountObjectId`, `recipientObjectId`, `processAccountObjectId`; `sid` for `accountSid`, `requestAccountSid`, `initiatingAccountSid`; `upn` for `accountUpn`, `initiatingProcessAccountUpn`, `targetAccountUpn`; `name` for `accountName`, `requestAccountName`, `initiatingAccountName`; `nt_domain` for `accountDomain`, `requestAccountDomain`, `initiatingAccountDomain` |
| `impacted_entities.mailbox` | `entities.mailboxes: [{primary_address: C}]` for `accountUpn`, `fileOwnerUpn`, `initiatingProcessAccountUpn`, `lastModifyingAccountUpn`, `targetAccountUpn`, `senderFromAddress`, `senderMailFromAddress`, `recipientEmailAddress` |
| `impacted_entities: {}` | no `entities` |
| `scope.selection: All` | no `scope` |
| `scope.selection: Specific`, `scope.device_groups: G` | `scope: {device_groups: G}` |
| `actions.devices.isolate_device: T` | `actions.isolate_devices: [{device_id: DeviceId, isolation_type: t}]`, `t` lower-cased |
| `actions.devices.collect_investigation_package: true` | `actions.collect_investigation_packages: [{device_id: DeviceId}]` |
| `actions.devices.run_antivirus_scan: true` | `actions.run_antivirus_scans: [{device_id: DeviceId}]` |
| `actions.devices.initiate_investigation: true` | `actions.initiate_investigations: [{device_id: DeviceId}]` |
| `actions.devices.restrict_app_execution: true` | `actions.restrict_app_executions: [{device_id: DeviceId}]` |
| a device flag `false` | nothing |
| `actions.files.allow_block` (`action: Allow` or `Block`, `identifier: C`) | `actions.allow_files` or `actions.block_files`: `[{sha1: C}]` for `sha1`, `initiatingProcessSHA1`; `[{sha256: C}]` for `sha256`, `initiatingProcessSHA256`; with `device_groups: G` when `groups.selection` is `Specific` |
| `actions.files.quarantine_file: C` (or the alias `quarantine_files`) | `actions.stop_and_quarantine_files: [{device_id: DeviceId, sha1: C}]` for `sha1`, `initiatingProcessSHA1` |
| `actions.users.mark_as_compromised: C` | `actions.mark_users_as_compromised: [{account_object_id: C}]` |
| `actions.users.disable_user: C` | `actions.disable_users: [{account_sid: C}]` |
| `actions.users.force_password_reset: C` | `actions.force_user_password_resets: [{account_sid: C}]` |
| an empty `actions`, `actions.devices`, `actions.files`, or `actions.users` | nothing |

1.0's device actions named no column: Graph took the identifier `deviceId`, the `DeviceId` column. Migration writes `DeviceId`.

What cannot be mapped, so `defender_migrate_unmapped` leaves the block unchanged:

- An `impacted_entities` value whose identifier is not in its row above: `accountId`, `servicePrincipalId`, `servicePrincipalName`, `senderDisplayName`, any value outside Graph's 1.0 identifier enums. Graph 2.0 has no mapping that takes them.
- A file identifier other than a SHA-1 or SHA-256 one for `allow_block`, or other than a SHA-1 one for `quarantine_file`.
- `scope.selection: Specific` with no `device_groups`, and `groups.selection: Specific` with no `device_groups`.

New 2.0 keys (`schedule.lookback`, `alert.custom_details`, `alert.grouping`, `incident`, and the email and file actions 1.0 lacked) are never written by migration.

### Query validation

As 1.0: `opentide validate query --platform defender_for_endpoint --live` runs the compiled query of a 1.0 or a 2.0 block against the tenant's advanced hunting. It sends no detection rule and does not refuse a 1.0 block.

## Relationships

- [platforms](index.md) — shared fields and external ids
- [defender-for-endpoint-1.0.md](defender-for-endpoint-1.0.md) — the deprecated schema this one replaces
- [deployment-state.md](../deployment-state.md) — legacy Defender bindings, read only to retire them
- [deployment.md](../deployment.md) — strategies and retirement
- [rule-1.1.md](../objects/rule-1.1.md) — parent object
- [sentinel-1.0.md](sentinel-1.0.md) — shared KQL exclusion shape, tactic folding
- [validation.md](../validation.md) — advisories and KQL query validation
- [RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md) — the proposal

## Defaults & overrides

| Field | Default |
|-------|---------|
| `alert.title` | rule `name` at deploy |
| `alert.description` | rule `description` at deploy |
| `alert.severity` | `response.alert_severity`, else `Medium`, at deploy |
| `alert.techniques` | the techniques of the rule's objective |
| `schedule.lookback` | not sent: Defender derives it from the frequency |
| `alert.grouping` | not sent: one alert per event |
| `incident` | not sent: alerts may be correlated |
| `scope` | not sent: every device |
| API version | `beta` |

There is no tenant setting that changes the API version.

## Examples

```yaml
configurations:
  defender_for_endpoint:
    enabled: true
    schema: platform::defender_for_endpoint::2.0
    status: STAGING
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
    schedule:
      frequency: 1H
      lookback: 4H
    alert:
      title: Encoded PowerShell
      severity: High
      techniques: [T1059.001, T1078.004]
      custom_details:
        CommandLine: ProcessCommandLine
      grouping: single_alert
    entities:
      hosts:
        - device_id: DeviceId
          name: DeviceName
      accounts:
        - sid: AccountSid
          name: AccountName
          nt_domain: AccountDomain
    actions:
      isolate_devices:
        - device_id: DeviceId
          isolation_type: full
    scope:
      device_groups: [Tier 0]
    incident:
      exclude_from_correlation: true
```

`alert.techniques` above yields `tactics` `InitialAccess`, `Execution`, `Persistence`, `PrivilegeEscalation`, and `DefenseEvasion` (T1078.004's Stealth stage), with T1059 under `Execution` and T1078 under the other four.

**Complete block.** Every key this spec defines, each set once: every `alert` key, both `schedule` keys, all seventeen entity kinds with every field, all sixteen actions with every target field, `scope`, `incident`, `exclusions`, and the [shared keys](index.md#shared-platform-block). Beta-only keys are marked in comments. It shows the shape, not a rule to deploy: a real rule's query returns only the columns its mappings name, and it picks only the actions it needs (it would not allow and block the same file).

```yaml
configurations:
  defender_for_endpoint:
    enabled: true
    name: Encoded PowerShell with follow-on activity
    schema: platform::defender_for_endpoint::2.0
    status: PRODUCTION
    tenants: [contoso, fabrikam]
    flags: [tier0]
    contributors: [Detection Engineering]
    # Illustrative: this block sets every key so each one is shown once. A real rule's query
    # returns exactly the columns its mappings and actions name, and picks only the actions it needs.
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
      | join kind=leftouter (DeviceNetworkEvents | project DeviceId, RemoteIP, RemoteIPType, RemoteUrl, LocalIP) on DeviceId
      | project Timestamp, ReportId, DeviceId, DeviceName, DeviceDnsDomain, DeviceNetBiosName, DeviceNtDomain,
          AccountObjectId, AccountSid, AccountUpn, AccountUpnSuffix, AccountName, AccountDomain, AccountDnsDomain,
          FileName, SHA1, SHA256, InitiatingProcessSHA1, InitiatingProcessSHA256, ProcessCommandLine,
          RemoteIP, RemoteIPType, RemoteUrl, DnsQuery, LocalIP, DnsServerIP, RegistryKey, RegistryValueName,
          NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, MailClusterQuery, MailClusterSource,
          ApplicationId, Application, OAuthApplicationId, GroupObjectId, GroupSid, GroupDistinguishedName,
          AzureResourceId, AmazonResourceName, GcpFullResourceName
    schedule:
      frequency: 1H
      lookback: 4H  # beta-only
    alert:
      title: Encoded PowerShell with follow-on activity
      description: An encoded PowerShell command ran and was followed by network, mail, and identity activity.
      severity: High
      recommendation: Review the decoded command line, isolate the device, and reset the account's credentials.
      techniques: [T1059.001, T1078.004]
      custom_details:
        CommandLine: ProcessCommandLine
        RemoteAddress: RemoteIP
      grouping: single_alert  # beta-only
    entities:
      hosts:
        - device_id: DeviceId
          name: DeviceName
          dns_domain: DeviceDnsDomain
          netbios_name: DeviceNetBiosName
          nt_domain: DeviceNtDomain
      accounts:
        - aad_user_id: AccountObjectId
          sid: AccountSid
          upn: AccountUpn
          upn_suffix: AccountUpnSuffix
          name: AccountName
          nt_domain: AccountDomain
          dns_domain: AccountDnsDomain
      mailboxes:
        - primary_address: RecipientEmailAddress
      files:
        - name: FileName
          sha1: SHA1
          sha256: SHA256
      processes:
        - sha1: InitiatingProcessSHA1
          sha256: InitiatingProcessSHA256
      ips:
        - address: RemoteIP
          scope: RemoteIPType
      urls:
        - address: RemoteUrl
      dns:
        - domain_name: DnsQuery
          host_ip_address: LocalIP
          server_ip: DnsServerIP
      registry_values:
        - key: RegistryKey
          value_name: RegistryValueName
      mail_messages:
        - network_message_id: NetworkMessageId
          recipient: RecipientEmailAddress
          sender: SenderFromAddress
          subject: Subject
      mail_clusters:
        - query: MailClusterQuery
          source: MailClusterSource
      cloud_applications:
        - app_id: ApplicationId
          name: Application
      oauth_applications:
        - oauth_app_id: OAuthApplicationId
      security_groups:
        - object_id: GroupObjectId
          sid: GroupSid
          distinguished_name: GroupDistinguishedName
      azure_resources:
        - resource_id: AzureResourceId
      amazon_resources:
        - amazon_resource_id: AmazonResourceName
      google_cloud_resources:
        - full_resource_name: GcpFullResourceName
    actions:
      isolate_devices:
        - device_id: DeviceId
          isolation_type: selective
      collect_investigation_packages:
        - device_id: DeviceId
      run_antivirus_scans:
        - device_id: DeviceId
      initiate_investigations:
        - device_id: DeviceId
      restrict_app_executions:
        - device_id: DeviceId
      allow_files:
        - sha1: SHA1
          sha256: SHA256
          device_groups: [Developer workstations]
      block_files:
        - sha1: SHA1
          sha256: SHA256
          device_groups: [Tier 0, Servers]
      stop_and_quarantine_files:
        - device_id: DeviceId
          sha1: SHA1
      disable_users:
        - account_sid: AccountSid
      force_user_password_resets:
        - account_sid: AccountSid
      mark_users_as_compromised:
        - account_object_id: AccountObjectId
      soft_delete_emails:
        - network_message_id: NetworkMessageId
          recipient: RecipientEmailAddress
      hard_delete_emails:
        - network_message_id: NetworkMessageId
          recipient: RecipientEmailAddress
      move_emails_to_deleted_items:
        - network_message_id: NetworkMessageId
          recipient: RecipientEmailAddress
      move_emails_to_inbox:
        - network_message_id: NetworkMessageId
          recipient: RecipientEmailAddress
      move_emails_to_junk:
        - network_message_id: NetworkMessageId
          recipient: RecipientEmailAddress
    scope:
      device_groups: [Tier 0, Servers]
    incident:  # beta-only
      exclude_from_correlation: true
    exclusions:
      - query: '| where DeviceName != BuildAgent'
        reason: The build agent runs encoded PowerShell on purpose.
        tenant: fabrikam
        let:
          BuildAgent: build-agent-01
```

Deployed to tenant `contoso`, the exclusion (scoped to `fabrikam`) is skipped and the query is sent unchanged. Its create body is [rule-defender-2.0-complete.create.api.json](../../fixtures/platforms/defender-for-endpoint/rule-defender-2.0-complete.create.api.json).

Fixtures:

- [fixtures/platforms/defender-for-endpoint-2.0.yaml](../../fixtures/platforms/defender-for-endpoint-2.0.yaml): the rule above, plus a `processes` mapping and a `block_files` action.
- [fixtures/platforms/defender-for-endpoint-2.0-complete.yaml](../../fixtures/platforms/defender-for-endpoint-2.0-complete.yaml): the complete block above. A test fails when a key of the field tables is missing from it.
- [fixtures/platforms/defender-for-endpoint/](../../fixtures/platforms/defender-for-endpoint/): its create, update, and disable bodies, and the migration of [fixtures/platforms/defender-for-endpoint.yaml](../../fixtures/platforms/defender-for-endpoint.yaml) (1.0).
- Invalid: [rule-defender-lookback-nrt.yaml](../../fixtures/invalid/rule-defender-lookback-nrt.yaml) (`defender_lookback`), [rule-defender-entity-field.yaml](../../fixtures/invalid/rule-defender-entity-field.yaml) (`defender_entity_mapping`), [rule-defender-action-target.yaml](../../fixtures/invalid/rule-defender-action-target.yaml) (`defender_action_target`), [rule-defender-1.0-keys.yaml](../../fixtures/invalid/rule-defender-1.0-keys.yaml) (`unknown_field`).

## History

| Version | Date | Notes |
|---------|------|-------|
| 2.0 | 2026-11-25 | Examples: a complete block that sets every key, with its fixture and create body. Before release; no contract change. |
| 2.0 | 2026-11-24 | `platform::defender_for_endpoint::2.0`: the Microsoft Graph beta custom detection contract. `schedule` (frequency as ISO 8601, beta lookback), `alert` with tactics derived from techniques, custom details, and beta event grouping, `entities` (seventeen entity kinds), `actions` (sixteen automated actions), `scope.device_groups`, beta `incident`, `status` from the deployment status. The Defender rule id is `metadata.uuid`; legacy rules are recreated under the uuid and deleted. Supersedes 1.0, which is deprecated ([RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md)). |
