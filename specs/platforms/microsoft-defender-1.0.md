---
spec: platform-microsoft-defender
version: "1.1"
schema_id: platform::microsoft_defender::1.0
status: normative
supersedes: null
---

# Microsoft Defender (`platform::microsoft_defender::1.0`)

## Summary

`configurations.microsoft_defender` is a Microsoft Defender XDR custom detection rule. opentide's contract is the Microsoft Graph **beta** custom detection API, `https://graph.microsoft.com/beta/security/rules/detectionRules`. The block models every writable property of that API ([Beta API coverage](#beta-api-coverage)). The detection text is KQL (advanced hunting). Query validation is supported.

The Defender rule id is the rule's `metadata.uuid`. Graph takes a client-provided `id` on create, so opentide addresses the rule as Sentinel and Elastic do, and keeps no Defender id in [deployment state](../deployment-state.md). The proposal is [RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md).

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- The configuration key MUST be `microsoft_defender`. `schema` MAY be omitted; when set it MUST be `platform::microsoft_defender::1.0` (`microsoft_defender_schema`).
- Static validation MUST require `query` and `schedule.frequency`. `query` MUST be non-blank KQL. Every other key MAY be omitted.
- Unknown keys MUST fail static validation, at any level of the block.
- The block MUST NOT contain `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>`. Each fails `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).
- Static validation MUST reject a block that breaks a [constraint](#constraints), under its code. Every value a Graph beta enum lists for a modelled property, other than the `unknownFutureValue` sentinel, MUST be accepted.
- Deploy MUST address the Defender rule by the lowercase canonical `metadata.uuid`: the create body's `id` and the `{id}` of every update and delete. Deploy MUST NOT read, write, or create a binding in deployment state.
- Deploy MUST send the [beta-only](#beta-only-properties) properties only when their key is set, and MUST NOT send a deprecated Graph property.
- Deploy MUST derive the alert's MITRE tactics from its techniques through the bundled `att&ck` vocabulary ([ATT&CK](#attck)). There is no key that sets tactics.
- Every writable property of the beta API MUST be modelled by a key of this block or listed in [Beta properties not modelled](#beta-properties-not-modelled), with its reason.
- A tenant's `[tenants.setup]` MUST hold `tenant_id`, `client_id`, and `client_secret`, and MAY hold `ssl`. Any other setup key MUST fail configuration load ([Tenant setup](#tenant-setup)).
- Deploy MUST sign in with the OAuth 2.0 client credentials grant and MUST send every rule call to the beta endpoint. No setting changes the endpoint or the API version.
- Deploy MUST NOT send a `PATCH` or `POST` again after a transient answer (`408`, `429`, `502`, `503`, `504`) ([Errors and retries](#errors-and-retries)). A `401` gets one new token and one resend.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL. Multiline. Compiled with matching `exclusions` before deploy. |
| `schedule` | [DefenderSchedule](#schedule-defenderschedule) | yes | — | How often the rule runs, and how far back each run reads. |
| `alert` | [DefenderAlert](#alert-defenderalert) | optional | null | The alert template. Every field has a deploy-time default. |
| `entities` | [DefenderEntities](#entities-defenderentities) | optional | null | Result columns mapped to the alert's entities. |
| `actions` | [DefenderActions](#actions-defenderactions) | optional | null | Automated actions run on the entities a detection finds. |
| `scope` | [DefenderScope](#scope-defenderscope) | optional | null | Device groups the rule applies to. Omitted: every device. |
| `incident` | [DefenderIncident](#incident-defenderincident) | optional | null | Incident correlation. **Beta-only.** |
| `exclusions` | list[[DefenderExclusion](#exclusions-defenderexclusion)] | optional | null | Per-tenant KQL fragments appended to `query`. |

### Constraints from the Graph docs

The beta docs state few constraints. Each constraint below is marked with where it comes from: **Graph** when the docs state it, and **opentide** when opentide adds it for the shape of the YAML. Where the docs state nothing, the field says so and static validation checks only the type.

### `schedule` (DefenderSchedule)

| Field | Type | Required | Default | Graph | Description |
|-------|------|----------|---------|-------|-------------|
| `frequency` | string | yes | — | `schedule.frequency` | `NRT`, `<n>H`, or `<n>D`, `n` a positive integer without a leading zero. |
| `lookback` | string | optional | null | `schedule.lookback` | **Beta-only.** `<n>H` or `<n>D`. Omitted, Defender derives the lookback from the frequency. |

- **Graph:** `frequency` is an ISO 8601 duration, and near real time is a zero frequency. `lookback` "must be at least **frequency**" and is "not supported for near-real-time rules with a zero frequency".
- **Graph, unstated:** which frequencies Defender accepts, and the largest lookback. Static validation does not limit them; Defender's answer at deploy does ([RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md#unresolved-questions), question 7). The frequencies Defender has offered are `NRT`, `1H`, `3H`, `12H`, and `24H`.
- **opentide:** the `<n>H` and `<n>D` shorthand. It is sent as an ISO 8601 duration:

| Written | Sent |
|---------|------|
| `NRT` (`frequency` only) | `PT0S` |
| `<n>H` | `PT<n>H` (`1H` → `PT1H`) |
| `<n>D` | `P<n>D` (`1D` → `P1D`) |

`24H` and `1D` are the same duration; `24H` is sent as `PT24H`. For the comparison of `lookback` with `frequency`, `1D` is `24H`.

### `alert` (DefenderAlert)

| Field | Type | Required | Default | Graph | Description |
|-------|------|----------|---------|-------|-------------|
| `title` | string | optional | rule `name` | `alertTemplate.title` | Alert title. No Graph constraint. |
| `description` | string | optional | rule `description` | `alertTemplate.description` | Alert description. No Graph constraint. |
| `severity` | string | optional | `response.alert_severity`, else `Medium` | `alertTemplate.severity` | `Informational`, `Low`, `Medium`, `High`, or `Critical`, sent lower-cased; `Critical` is sent as `high`. |
| `recommendation` | string | optional | null | `alertTemplate.recommendedActions` | Recommended actions text. Not sent when unset. No Graph constraint. |
| `techniques` | list[string] | optional | null | `alertTemplate.tactics` | MITRE ATT&CK technique or sub-technique ids (`T1528`, `T1059.001`). An empty list counts as unset. Left out, the techniques of the rule's objective are used. Sent grouped by tactic ([ATT&CK](#attck)). |
| `custom_details` | map[string, string] | optional | null | `alertTemplate.customDetails` | Alert custom details: detail name to result column. Not sent when unset. |
| `grouping` | string | optional | null | `alertTemplate.eventGroupingKind` | **Beta-only.** `alert_per_event` (sent as `alertPerEvent`) or `single_alert` (`singleAlert`). `single_alert` groups the events of one run into one alert; it does not merge alerts across runs. Omitted, Defender creates one alert per event. |

- **Graph:** `alertTemplate.severity` is `informational`, `low`, `medium`, or `high`. `eventGroupingKind` is `alertPerEvent` or `singleAlert`; its `unknownFutureValue` is not a request value ("Don't use `unknownFutureValue` in requests").
- **opentide:** `severity` takes opentide's severity names, `Critical` included, and maps them onto Graph's four.
- **Graph, unstated:** limits on custom details (how many, which names). A `custom_details` name is a non-blank string (**opentide**), and a value is a [column name](#column-names).

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

ATT&CK v19 renamed Defense Evasion (TA0005) to Stealth and split Defense Impairment (TA0112) out of it. Defender's tactic list predates the split, so both are sent as `DefenseEvasion`, as Sentinel does. When one technique has both stages, they yield a single `DefenseEvasion` entry.

There is no `alert.tactics` key. Graph nests techniques inside tactics, and the vocabulary already records each technique's tactics, so a separate list could only repeat the techniques or contradict them. The docs give no list of tactic values (`mitreTactic.tactic` is documented with the example `Exploit`) ([question 4](../../rfcs/0021-defender-graph-beta-detection-rules.md#unresolved-questions)).

### Column names

Every value that names a result column (entity mappings, action targets, custom details) is the column as the query's output spells it (`DeviceId`), and is sent verbatim. Deploy MUST NOT change its case. The docs say only that it is the "name of the detection query column". Static validation requires a non-blank string (`microsoft_defender_column`); whether the column exists in the query's output is checked by Defender at deploy.

### `entities` (DefenderEntities)

Each key is an entity kind and holds a list of mappings. A mapping is a map from field to [column name](#column-names). Each field is sent as the Graph property in the table, under `alertTemplate.entityMappings.<Graph kind>`. Omitted kinds are not sent; an empty `entities` sends no `entityMappings`.

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

These are all seventeen kinds of Graph's `entityMappingConfiguration`. Defender for Endpoint tables yield hosts, accounts, files, processes, ips, urls, and registry values. The other kinds come from the Defender for Office 365, Identity, and Cloud Apps tables that the same custom detection reads.

- **Graph, unstated:** which fields a mapping needs to resolve an entity, whether a rule needs one mapping, and which kinds a tenant without the other Defender products surfaces ([question 6](../../rfcs/0021-defender-graph-beta-detection-rules.md#unresolved-questions)). Static validation does not require any particular field.
- **opentide:** a mapping has at least one field, because an empty mapping maps nothing. A block with no mapping gets the advisory `microsoft_defender_no_entities`.

### `actions` (DefenderActions)

Each key is an automated action and holds a list of targets. Each target is sent under `detectionAction.automatedActions.<Graph action>`. Omitted actions are not sent; an empty `actions` sends no `automatedActions`.

| Action | Graph action | Target fields (YAML → Graph property) |
|--------|--------------|---------------------------------------|
| `isolate_devices` | `isolateDevices` | `device_id` → `deviceIdColumn`, `isolation_type` → `isolationType` |
| `collect_investigation_packages` | `collectInvestigationPackages` | `device_id` → `deviceIdColumn` |
| `run_antivirus_scans` | `runAntivirusScans` | `device_id` → `deviceIdColumn` |
| `initiate_investigations` | `initiateInvestigations` | `device_id` → `deviceIdColumn` |
| `restrict_app_executions` | `restrictAppExecutions` | `device_id` → `deviceIdColumn` |
| `allow_files` | `allowFiles` | `sha1` → `sha1Column`, `sha256` → `sha256Column`, `device_groups` → `deviceGroupNames` |
| `block_files` | `blockFiles` | `sha1` → `sha1Column`, `sha256` → `sha256Column`, `device_groups` → `deviceGroupNames` |
| `stop_and_quarantine_files` | `stopAndQuarantineFiles` | `device_id` → `deviceIdColumn`, `sha1` → `sha1Column` |
| `disable_users` | `disableUsers` | `account_sid` → `accountSidColumn` |
| `force_user_password_resets` | `forceUserPasswordResets` | `account_sid` → `accountSidColumn` |
| `mark_users_as_compromised` | `markUsersAsCompromised` | `account_object_id` → `accountObjectIdColumn` |
| `soft_delete_emails` | `softDeleteEmails` | `network_message_id` → `networkMessageIdColumn`, `recipient` → `recipientColumn` |
| `hard_delete_emails` | `hardDeleteEmails` | same as `soft_delete_emails` |
| `move_emails_to_deleted_items` | `moveEmailsToDeletedItems` | same as `soft_delete_emails` |
| `move_emails_to_inbox` | `moveEmailsToInbox` | same as `soft_delete_emails` |
| `move_emails_to_junk` | `moveEmailsToJunk` | same as `soft_delete_emails` |

Fields ending in `…Column` take a [column name](#column-names). These are all sixteen actions of Graph's `automatedActionSet`.

- **Graph:** `isolation_type` is `full` or `selective` (`isolationType`; its `unknownFutureValue` is not a request value). `device_groups` is a list of device group names ("String collection"). Omitted, the file action applies to every device group.
- **Graph, unstated:** which target fields an action needs. Static validation does not require any particular field.
- **opentide:** an action holds a non-empty list, and a target has at least one field and only its action's fields. `device_groups`, when set, is a non-empty list of non-blank names.

### `scope` (DefenderScope)

| Field | Type | Required | Graph | Description |
|-------|------|----------|-------|-------------|
| `device_groups` | list[string] | yes | `detectionAction.organizationalScope.deviceGroups` | Device group names. |

With no `scope`, `organizationalScope` is not sent and the rule applies to every device.

- **Graph:** a "String collection" of device group names.
- **opentide:** non-empty, with no blank name. An empty scope would mean no device, which is never the intent.

### `incident` (DefenderIncident)

**Beta-only.**

| Field | Type | Required | Graph | Description |
|-------|------|----------|-------|-------------|
| `exclude_from_correlation` | boolean | yes | `detectionAction.incidentConfiguration.isExcludedFromIncidentCorrelation` | `true`: each alert opens its own single-alert incident. `false`: alerts may be correlated with related alerts (Defender's default). |

### `exclusions[]` (DefenderExclusion)

Same shape and tenant matching as Sentinel exclusions. See [sentinel-1.0.md](sentinel-1.0.md#exclusions-sentinelexclusion).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | yes | — | KQL fragment appended after the base query. The key is required. An empty string is accepted. |
| `reason` | string | yes | — | Why the exclusion exists. Not sent to Defender. |
| `tenant` | string | optional | null | Limit the exclusion to one tenant name. |
| `let` | map[string, scalar] | optional | null | KQL `let` bindings. String, number, or boolean. |

### Beta API coverage

The beta custom detection API is opentide's contract. The deployer always uses the beta endpoint. The tables above model each writable property, and the table below lists every property they do not model, with the reason. [fixtures/platforms/microsoft-defender/graph-beta-properties.json](../../fixtures/platforms/microsoft-defender/graph-beta-properties.json) is a snapshot of the Properties tables of the beta docs for every type the API uses, read on 2026-11-25. A test fails when a property of the snapshot is neither modelled nor listed here.

#### Beta-only properties

Three modelled properties exist in beta only:

| Key | Graph property |
|-----|----------------|
| `schedule.lookback` | `schedule.lookback` |
| `alert.grouping` | `detectionAction.alertTemplate.eventGroupingKind` |
| `incident` | `detectionAction.incidentConfiguration` |

For information: every other property the block sends also exists, with the same name and shape, in Graph v1.0. A block that sets none of these three keys is therefore also a valid v1.0 request. opentide does not target v1.0.

#### Beta properties not modelled

| Graph property | Reason |
|----------------|--------|
| `detectionRule.id` | Set by deploy: `metadata.uuid`. |
| `detectionRule.displayName` | Set by deploy: block `name`, else rule `name`. |
| `detectionRule.description` | Set by deploy: rule `description`. |
| `detectionRule.status` | Set by deploy: from the [deployment status](#deployment-status). |
| `detectionRule.createdBy` | Read-only. |
| `detectionRule.createdDateTime` | Read-only. |
| `detectionRule.lastModifiedBy` | Read-only. |
| `detectionRule.lastModifiedDateTime` | Read-only. |
| `detectionRule.detectorId` | Deprecated. |
| `detectionRule.isEnabled` | Deprecated: replaced by `status`. |
| `detectionRule.lastRunDetails` | Deprecated. |
| `queryCondition.queryText` | Set by deploy: `query` with the tenant's matching `exclusions`. |
| `queryCondition.lastModifiedDateTime` | Deprecated. |
| `ruleSchedule.nextRunDateTime` | Deprecated. |
| `ruleSchedule.period` | Deprecated: replaced by `frequency`. |
| `alertTemplate.tactics` | Set by deploy: derived from `alert.techniques` ([ATT&CK](#attck)). |
| `alertTemplate.category` | Deprecated: replaced by `tactics`. |
| `alertTemplate.impactedAssets` | Deprecated: replaced by `entityMappings`. |
| `alertTemplate.mitreTechniques` | Deprecated: replaced by `tactics`. |
| `mitreTactic.tactic` | Set by deploy ([ATT&CK](#attck)). |
| `mitreTactic.techniques` | Set by deploy ([ATT&CK](#attck)). |
| `mitreTechnique.technique` | Set by deploy ([ATT&CK](#attck)). |
| `mitreTechnique.subTechniques` | Set by deploy ([ATT&CK](#attck)). |
| `detectionAction.responseActions` | Deprecated: replaced by `automatedActions`. |
| `organizationalScope.scopeNames` | Deprecated: replaced by `deviceGroups`. |
| `organizationalScope.scopeType` | Deprecated: replaced by `deviceGroups`. |

Enum values not accepted:

| Enum value | Reason |
|------------|--------|
| `detectionRuleStatus.autoDisabled` | Set by Defender on a failing rule; deploy sends `enabled` or `disabled`. |
| `unknownFutureValue` (every enum) | Graph's evolvable-enum sentinel, never a request value. |

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code. Paths are under `configurations.microsoft_defender`.

| Code | Constraint | `field_path` |
|------|------------|--------------|
| `microsoft_defender_schema` | `schema`, when set, is `platform::microsoft_defender::1.0`. | `schema` |
| `microsoft_defender_frequency` | `schedule.frequency` is `NRT`, `<n>H`, or `<n>D`. | `schedule.frequency` |
| `microsoft_defender_lookback` | `schedule.lookback` is `<n>H` or `<n>D`, it is not set with `frequency: NRT`, and it is not shorter than `frequency` (the last two are Graph's). | `schedule.lookback` |
| `microsoft_defender_severity` | `alert.severity` is `Informational`, `Low`, `Medium`, `High`, or `Critical`. | `alert.severity` |
| `microsoft_defender_grouping` | `alert.grouping` is `alert_per_event` or `single_alert` (Graph's `eventGroupingKind`). | `alert.grouping` |
| `microsoft_defender_custom_details` | `alert.custom_details` is a map of non-blank names to strings. | `alert.custom_details` |
| `microsoft_defender_entity_kind` | Every key of `entities` is a kind in the [entities](#entities-defenderentities) table. | `entities.<kind>` |
| `microsoft_defender_entity_mapping` | Every kind holds a list; every mapping is a map with at least one field, and every field is one of its kind's fields. | `entities.<kind>.<N>` |
| `microsoft_defender_action_kind` | Every key of `actions` is an action in the [actions](#actions-defenderactions) table. | `actions.<action>` |
| `microsoft_defender_action_target` | Every action holds a non-empty list; every target is a map with at least one field and only its action's fields; `device_groups` is a non-empty list of non-blank names. | `actions.<action>.<N>` |
| `microsoft_defender_isolation_type` | `isolation_type` is `full` or `selective` (Graph's `isolationType`). | `actions.isolate_devices.<N>.isolation_type` |
| `microsoft_defender_column` | Every column name (entity field, action column, custom detail value) is a non-blank string. | the field |
| `microsoft_defender_scope` | `scope` is `{device_groups: [...]}`, a non-empty list of non-blank names. | `scope` |
| `microsoft_defender_incident` | `incident` is `{exclude_from_correlation: <boolean>}`. | `incident` |

### Advisories

Advisories are [warnings](../validation.md#platform-advisories): validation reports them under their code and never rejects the rule.

| Code | When | Why |
|------|------|-----|
| `microsoft_defender_no_entities` | The block maps no entity (`entities` unset, empty, or every kind empty). | The alert names no device, user, or mailbox, so it cannot be triaged or acted on by entity. |

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
| `detectionAction.incidentConfiguration` | [`incident`](#incident-defenderincident), when set |

A property whose key is unset is omitted, never sent as `null`. The deprecated Graph properties in [Beta properties not modelled](#beta-properties-not-modelled) MUST NOT be sent.

The goldens for the fixture rules are under [fixtures/platforms/microsoft-defender/](../../fixtures/platforms/microsoft-defender/).

### Deployment status

| Block status strategy | Graph `status` |
|-----------------------|----------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `enabled` |
| `DISABLEMENT` | `disabled` |
| `DELETION` | — (the rule is deleted) |
| `INERT` | — (not deployed) |

Defender sets `autoDisabled` on a rule that keeps failing. The next deploy of an enabled status sends `enabled` again.

### Tenant setup

Tenants are configured in `.opentide/configurations/platforms/microsoft_defender.toml`:

```toml
[platform]
enabled = true
name = "Microsoft Defender"

[[tenants]]
name = "contoso"
description = "Contoso production tenant"
strategies = ["PREVIEW", "RELEASE"]
[tenants.setup]
ssl = true
tenant_id = "$MDE_TENANT_ID"
client_id = "$MDE_CLIENT_ID"
client_secret = "$MDE_CLIENT_SECRET"
[tenants.parameters]
device_groups = ["Tier 0", "Servers", "Developer workstations"]
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `tenant_id` | string | yes | — | Microsoft Entra ID tenant (directory) id. |
| `client_id` | string | yes | — | Application (client) id of the app registration. |
| `client_secret` | string | yes | — | Client secret of the app registration. SHOULD be a `$ENV` reference. Never written to output. |
| `ssl` | bool | no | `true` | Shared tenant setup: TLS verification. |

There is no URL key: the endpoint is fixed. `[tenants.parameters] device_groups` MAY list the tenant's device group names; deploy does not read it, and validation does not check `scope` against it.

**App registration.** One Entra ID app registration per tenant, with a client secret and these Microsoft Graph **application** permissions, admin consent granted:

| Permission | Needed for |
|------------|------------|
| `CustomDetection.ReadWrite.All` | deploy (`PATCH`, `POST`, `DELETE`), `--prune`, the tenant check, `generate extract` |
| `ThreatHunting.Read.All` | `opentide validate query --live` and `opentide query` (`runHuntingQuery`) |

**Sign-in.** The client signs in with the client credentials grant at `https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token`, scope `https://graph.microsoft.com/.default`, keeps the token until it is due for renewal, and sends it as `Authorization: Bearer <token>` with `Content-Type: application/json`. A `401` from Graph gets one new token and one resend. A refused sign-in fails the tenant; the run continues with the other tenants.

**Tenant check.** `opentide doctor --live` signs in and reads the first page of `GET {base}`, which writes nothing. `200` passes; any other answer fails the check with Graph's status.

### Deploy

Per rule and per tenant the run selected, with `{base}` = `https://graph.microsoft.com/beta/security/rules/detectionRules` and `{uuid}` the lowercase canonical `metadata.uuid`:

| Strategy | Calls | Result |
|----------|-------|--------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | `PATCH {base}/{uuid}` with the body. On `404`, `POST {base}` with the body and `id`. | `update`, or `create` after a `404`. |
| `DISABLEMENT` | `PATCH {base}/{uuid}` with the body (`status: disabled`). On `404`, no create. | `update`; `skipped` with `microsoft_defender_rule_absent` after a `404`. |
| `DELETION` | `DELETE {base}/{uuid}`. | `delete` on `204`; `skipped` ("already gone") on `404`. |
| `INERT` | none | not deployed |

- A `POST` answered `409` means the rule exists (a concurrent run created it). Deploy MUST send the `PATCH` once more and MUST NOT retry the `POST`.
- Any other non-2xx answer fails that rule on that tenant. Deploy continues with other tenants and rules and exits 1.
- A `404` on `PATCH` is the only signal that the rule is absent. Deploy MUST NOT list remote rules or match display names to find it.
- No create needs deployment state, so `deployment_state_ignored` and `deployment_state_unpersisted` never refuse a `microsoft_defender` create. A dry run makes no call and shows the call it would make first.
- `--prune` retires a deleted `microsoft_defender` rule by `DELETE {base}/{uuid}`, as Sentinel and Elastic do ([deployment.md](../deployment.md#retiring-deleted-rules)).

#### Errors and retries

- A connection that could not be made (DNS, refused, proxy tunnel, connect timeout) is retried for every method, up to three times, after 0.5 s, 1 s, and 2 s.
- A transient answer (`408`, `429`, `502`, `503`, `504`) is retried for `DELETE` only, up to three times, honouring `Retry-After` up to 120 s. A `PATCH` or `POST` is sent once: Graph may have acted on it, and the next deploy's `PATCH` repairs the rule.
- A request not answered within 120 s is not sent again.
- Any other non-2xx answer to a rule call fails that rule on that tenant as `tenant_refused`, with the HTTP status and Graph's `error.message`.

#### Plan, dry run, and `--json`

| Output | Active status | `DISABLEMENT` | `DELETION`, `--prune` |
|--------|---------------|---------------|------------------------|
| Plan (text) | `create or update` | `disable` | `delete` |
| `--json` `changes[].action` | `upsert` | `disable` | `delete` |
| Dry run `api_request` | the `PATCH {base}/{uuid}` with its body | the same, `status: disabled` | the `DELETE {base}/{uuid}` |
| Real run | `created` or `updated` | `disabled`, or skipped (`microsoft_defender_rule_absent`) | `deleted`, or skipped ("already gone") |

A dry run makes no call and shows only the first request: the `POST` a `404` leads to is not shown. Whether an active rule is created or updated is known only from Graph's answer.

### Diagnostics

| Code | Level | Raised by | Meaning |
|------|-------|-----------|---------|
| `microsoft_defender_rule_absent` | warning | deploy | `DISABLEMENT` found no rule with the uuid on the tenant. Nothing is created. |

Every code carries the platform identifier, `microsoft_defender_`, as every other platform's codes do (`google_secops_`, `bitdefender_`).

### Query validation

`opentide validate query --platform microsoft_defender --live` runs the compiled query against the tenant's advanced hunting. It sends no detection rule.

## Relationships

- [platforms](index.md) — shared fields and external ids
- [deployment-state.md](../deployment-state.md) — Microsoft Defender keeps no shard
- [deployment.md](../deployment.md) — strategies and retirement
- [visibility.md](../visibility.md) — `system = "microsoft_defender"` log sources
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
| Graph API | beta, always |

There is no setting that changes the Graph API version. Tenants are configured in `.opentide/configurations/platforms/microsoft_defender.toml`.

## Examples

**Minimal block.** Only `query` and `schedule.frequency` are required. Every other value has a deploy-time default or is not sent; the one `hosts` mapping keeps the advisory `microsoft_defender_no_entities` away.

```yaml
configurations:
  microsoft_defender:
    enabled: true
    status: STAGING
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
      | project Timestamp, ReportId, DeviceId, DeviceName
    schedule:
      frequency: 1H
    entities:
      hosts:
        - device_id: DeviceId
```

**First example.** Beta-only keys, entities, an action, and a scope:

```yaml
configurations:
  microsoft_defender:
    enabled: true
    schema: platform::microsoft_defender::1.0
    status: STAGING
    query: |
      DeviceProcessEvents
      | where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
    schedule:
      frequency: 1H
      lookback: 4H  # beta-only
    alert:
      title: Encoded PowerShell
      severity: High
      techniques: [T1059.001, T1078.004]
      custom_details:
        CommandLine: ProcessCommandLine
      grouping: single_alert  # beta-only
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
    incident:  # beta-only
      exclude_from_correlation: true
```

With the `alert.techniques` above, the alert's `tactics` are `InitialAccess`, `Execution`, `Persistence`, `PrivilegeEscalation`, and `DefenseEvasion` (from T1078.004's Stealth stage). T1059 is listed under `Execution`, and T1078 under the other four.

**Complete block.** Every key this spec defines, each set once: every `alert` key, both `schedule` keys, all seventeen entity kinds with every field, all sixteen actions with every target field, `scope`, `incident`, `exclusions`, and the [shared keys](index.md#shared-platform-block). Beta-only keys are marked in comments. It shows the shape, not a rule to deploy: a real rule's query returns only the columns its mappings name, and the rule picks only the actions it needs (it would not allow and block the same file).

```yaml
configurations:
  microsoft_defender:
    enabled: true
    name: Encoded PowerShell with follow-on activity
    schema: platform::microsoft_defender::1.0
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

When this block is deployed to tenant `contoso`, the exclusion (scoped to `fabrikam`) is skipped and the query is sent unchanged. Its create body is [rule-microsoft-defender-complete.create.api.json](../../fixtures/platforms/microsoft-defender/rule-microsoft-defender-complete.create.api.json), shown in full, with the `PATCH` and `POST` requests, in [RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md#62-update-and-create-for-the-complete-block).

Fixtures:

- [fixtures/platforms/microsoft-defender.yaml](../../fixtures/platforms/microsoft-defender.yaml): the first example, plus a `processes` mapping and a `block_files` action.
- [fixtures/platforms/microsoft-defender-complete.yaml](../../fixtures/platforms/microsoft-defender-complete.yaml): the complete block. A test fails when a key of the field tables is missing from it.
- [fixtures/platforms/microsoft-defender/](../../fixtures/platforms/microsoft-defender/): the create, update, and disable bodies, the complete block's create body, and the beta property snapshot.
- Invalid: [rule-microsoft-defender-lookback-nrt.yaml](../../fixtures/invalid/rule-microsoft-defender-lookback-nrt.yaml) (`microsoft_defender_lookback`), [rule-microsoft-defender-entity-field.yaml](../../fixtures/invalid/rule-microsoft-defender-entity-field.yaml) (`microsoft_defender_entity_mapping`), [rule-microsoft-defender-action-target.yaml](../../fixtures/invalid/rule-microsoft-defender-action-target.yaml) (`microsoft_defender_action_target`), [rule-microsoft-defender-unknown-key.yaml](../../fixtures/invalid/rule-microsoft-defender-unknown-key.yaml) (`unknown_field`).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-11-25 | Tenant setup (`tenant_id`, `client_id`, `client_secret`, `ssl`; unknown keys fail), the app registration's Graph permissions, sign-in, and the tenant check; errors and retries (`PATCH` and `POST` never resent after a transient answer); the plan, dry run, and `--json` rows; a minimal example. Written down from the deployer RFC 0021 describes; no block or request change. Schema id unchanged. |
| 1.0 | 2026-11-25 | `platform::microsoft_defender::1.0`: Microsoft Defender custom detection rules on the Microsoft Graph beta custom detection contract ([RFC 0021](../../rfcs/0021-defender-graph-beta-detection-rules.md)). Every writable beta property is modelled, or listed as not modelled with its reason, and checked against a snapshot of the docs. The keys: `schedule` (an ISO 8601 frequency, and a beta lookback), `alert` (tactics derived from techniques, custom details, beta event grouping), `entities` (seventeen entity kinds), `actions` (sixteen automated actions), `scope.device_groups`, and beta `incident`. `status` follows the deployment status. Constraints are those the Graph docs state, plus marked opentide shape rules. The Defender rule id is `metadata.uuid`; no deployment state. |
