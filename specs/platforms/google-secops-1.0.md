---
spec: platform-google-secops
version: "1.3"
schema_id: platform::google_secops::1.0
status: normative
supersedes: null
---

# Google Security Operations (`platform::google_secops::1.0`)

## Summary

`configurations.google_secops` is one Google Security Operations (Google SecOps, formerly Chronicle) **custom detection rule**, written in [YARA-L 2.0](../languages/yara-l-1.0.md). The block carries the rule's sections as keys ([`YaraLSections`](../languages/yara-l-1.0.md#yaralsections)): `events`, `outcome`, and `condition` (and `setup`, `export`) as YARA-L text, and `match` and `options` as YAML objects. Deploy assembles the whole rule from them, `rule <name> {`, a generated `meta:` section, then each section under its label, and manages it through the Chronicle API v1: `rules` for the text and `rules/{rule}/deployment` for its run state.

Google assigns each rule an id (`ru_<uuid>`) at create time. That id is kept in [deployment state](../deployment-state.md), never on the rule. Like Elastic and Graylog, Google SecOps has a tenant-side check: `verifyRuleText` compiles a rule without creating it, so `google_secops` is in the `--live` allowlist. The analysis engine also checks YARA-L offline.

Shared fields are defined in [platforms](index.md#shared-platform-block). The design and its alternatives are in [RFC 0019](../../rfcs/0019-google-secops-yara-l.md).

## Requirements

Static validation (`opentide validate`) and registry load:

- `status`, `events`, and `condition` MUST be present; `match` MUST be present when `events` has two or more event variables.
- The section keys MUST form [`YaraLSections`](../languages/yara-l-1.0.md#yaralsections) and MUST be checked against the [YARA-L language](../languages/yara-l-1.0.md) under the `rule` profile, together, as the rule deploy [assembles](#assembled-rule). Its errors fail static validation; its warnings do not.
- A block MUST satisfy every [constraint](#constraints), reported with its code.
- Unknown keys MUST fail, at the block root and inside `schedule`, `match`, and `options`. A `query` key is unknown: the rule is written as sections, not one text.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)).

Deploy:

- Google SecOps is state-backed. Deploy MUST follow the [deploy decisions](../deployment-state.md#deploy-decisions) of deployment state and store the rule id under `platforms.google_secops.<tenant>`, matching `^ru_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.
- Deploy MUST NOT find a rule by listing (`rules.list`), by name, or by a meta value. The `opentide_uuid` meta is for analysts and audits.
- Deploy MUST call `verifyRuleText` with the assembled text before every create and every text update, and MUST NOT create or update a rule that does not verify (`google_secops_verify_failed`).
- Deploy MUST NOT call `rules.create` unless the returned id can be kept (`deployment_state_ignored`, `deployment_state_unpersisted`), and MUST fail the rule with `google_secops_create_no_id` when the response `name` does not end in a rule id.
- An update MUST send the text only when it differs from the remote text. Every text change is a new rule revision, which Google re-initialises for about an hour and whose detections are counted afresh; an unchanged rule keeps its revision.
- Under `DISABLEMENT`, deploy MUST disable a bound rule even when its verify or text update fails: the failure is reported and the rule still stops running.
- Deploy MUST NOT resend `POST rules` after a 5xx or no answer ([Errors](#errors)).
- Deploy MUST NOT delete detections. A `DELETION` archives the rule, or deletes it without `force` when the tenant asks ([Deletion](#deletion)).
- Deploy MUST NOT write to the rule file.

Query validation:

- `opentide validate query --platform google_secops --live` MUST compile each rule's assembled text with `verifyRuleText` and report Google's diagnostics. It MUST NOT create, update, or run a rule.
- Without `--live`, `validate query` checks YARA-L offline, as `opentide validate` does: a block's sections, or a `.yaral` or `.yl2` file.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `setup` | string | optional | null | YARA-L `setup` section text |
| `events` | string | yes | — | YARA-L `events` section text |
| `match` | [YaraLMatch](../languages/yara-l-1.0.md#yaralmatch) | conditional | null | `group_by`, `window`, and `type` (`hop`, `tumbling`, `sliding` with `pivot` and `direction`). Required with two or more event variables. |
| `outcome` | string | optional | null | YARA-L `outcome` section text |
| `condition` | string | yes | — | YARA-L `condition` section text |
| `options` | [YaraLOptions](../languages/yara-l-1.0.md#yaraloptions) | optional | null | `allow_zero_values`, `suppression_window` |
| `export` | string | optional | null | YARA-L `export` section text |
| `severity` | string | optional | [derived](#severity) | `Info`, `Low`, `Medium`, `High`, or `Critical`. Written as meta `severity`. |
| `priority` | string | optional | `severity` | Same values. Written as meta `priority`. |
| `alerting` | boolean | optional | [by strategy](#deploy) | Whether detections become alerts (`RuleDeployment.alerting`) |
| `run_frequency` | string | optional | not sent: Google's default for a new rule, an existing rule keeps its own | `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE`, or `DAILY` |
| `schedule` | [GoogleSecopsSchedule](#schedule-googlesecopsschedule) | optional | null | Schedule customizations, for `LIVE_CUSTOMIZABLE` and `HOURLY_CUSTOMIZABLE` only |
| `meta` | map[string, string] | optional | null | Extra meta keys, written after the [derived meta](#meta) in the order given |

The shared `name` is the YARA-L rule name, which Google shows as the rule's display name and a composite rule matches with `detection.detection.rule_name`. Empty means the [derived name](#rule-name).

### `schedule` (GoogleSecopsSchedule)

| Field | Type | Default | Sent as |
|-------|------|---------|---------|
| `ensure_enrichment_completeness` | boolean | Google's | `scheduleCustomizations.ensureEnrichmentCompleteness` |
| `late_arriving_data_adjustment` | duration (`30m`, `2h`) | Google's | `scheduleCustomizations.lateArrivingDataAdjustment`, in seconds (`"1800s"`) |

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `google_secops_rule_name` | A non-empty `name` is a YARA-L identifier, `[A-Za-z_][A-Za-z0-9_]*`, and not a [keyword](../languages/yara-l-1.0.md#lexical-structure). |
| `google_secops_severity` | `severity` and `priority` are each `Info`, `Low`, `Medium`, `High`, or `Critical`. |
| `google_secops_run_frequency` | `run_frequency` is `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE`, or `DAILY`. Google's legacy `HOURLY` is refused. |
| `google_secops_schedule` | `schedule` is set only with `run_frequency` `LIVE_CUSTOMIZABLE` or `HOURLY_CUSTOMIZABLE`, and `late_arriving_data_adjustment` is a positive duration with unit `s`, `m`, `h`, or `d`. |
| `google_secops_meta_key` | Each `meta` key is an identifier, not a keyword, and not a [derived key](#meta); each value is a string. |
| `google_secops_name_duplicate` | Workspace check: no two enabled `google_secops` blocks resolve to one rule name, compared case-insensitively. A composite rule that names one would match both, and Google's own `content_manager` treats names as case-insensitively unique. |

The [YARA-L codes](../languages/yara-l-1.0.md#diagnostics) apply to the sections.

| Code | `field_path` |
|------|--------------|
| `google_secops_rule_name` | `name` |
| `google_secops_severity` | `severity` or `priority` |
| `google_secops_run_frequency` | `run_frequency` |
| `google_secops_schedule` | `schedule`, or `schedule.late_arriving_data_adjustment` |
| `google_secops_meta_key` | `meta.<key>` |
| `google_secops_name_duplicate` | the block |
| `yaral_*` | the section key (`events`, `condition`, …), with the range inside its text; `match.<field>` and `options.<field>` for the YAML sections |

Paths are under `configurations.google_secops`.

### Advisories

Advisories are [warnings](../validation.md#platform-advisories): validation reports them under their code and never rejects the rule.

| Code | When | Why |
|------|------|-----|
| `google_secops_risk_score_missing` | `outcome` assigns no `$risk_score`. | Google gives every detection of the rule the instance's default score (40 for an alert and 15 otherwise, unless the instance's settings change them), whatever the rule detects. |
| `google_secops_rule_id_literal` | `events` or `condition` compares `detection.detection.rule_id` with a literal `ru_…` id. | The id differs per tenant and changes when a rule is recreated. Match the producer with `detection.detection.rule_name`, which opentide derives the same way in every tenant. |
| `google_secops_live_frequency_unavailable` | `run_frequency` is `LIVE` and the rule has two or more event variables. | Google allows `LIVE` for single-event rules only, so `verifyRuleText` does not list it and deploy refuses the rule with `google_secops_run_frequency_not_allowed`. Use `LIVE_CUSTOMIZABLE`. Google also counts a single event variable with `match` and a count or outcome condition as multi-event; the advisory does not try to decide that, and deploy still refuses. |

### Rule name

The shared `name` when set. Otherwise the opentide rule `name`, lower-cased, with every run of characters outside `[a-z0-9]` replaced by one `_`, and `_` trimmed at both ends. A result that starts with a digit, or is a YARA-L keyword ([yara-l-1.0](../languages/yara-l-1.0.md#lexical-structure), case-insensitive), gets the prefix `r_`: a rule named `Any` is `r_any`. An empty result is `opentide_` followed by `metadata.uuid` with `-` replaced by `_`.

`Office application spawns encoded PowerShell` → `office_application_spawns_encoded_powershell`.

### Meta

Deploy writes these keys, in this order, then the block `meta` keys in the order given:

| Key | Value | When |
|-----|-------|------|
| `author` | `metadata.author`, then the block `contributors`, de-duplicated, joined with `", "` | always |
| `description` | The opentide `description`, whitespace runs collapsed to one space, trimmed | always |
| `severity` | [Severity](#severity) | always |
| `priority` | `priority`, else the severity | always |
| `technique` | ATT&CK technique ids, sorted, comma-joined without spaces | when there is at least one |
| `opentide_uuid` | `metadata.uuid` | always |
| `opentide_version` | `metadata.version` | always |

The techniques are the rule's `techniques` plus those inherited through `detection_model`, the union [elastic-1.0](elastic-1.0.md#attck) uses. `technique` is the key Google's MITRE ATT&CK coverage page reads, as "a valid MITRE ATT&CK technique ID or multiple IDs as a comma-separated string" ([MITRE dashboard](https://cloud.google.com/chronicle/docs/detection/mitre-dashboard)); the matrix places each technique under its tactics itself. Deploy writes no `tactic`: Google documents no list form for it, and its community rules carry one value at most. A block that wants one writes it in `meta`.

Each value is written as a YARA-L double-quoted string: `\` becomes `\\`, `"` becomes `\"`, and every other control character, line breaks included, becomes a space. Google reads `author` and `severity` from the meta into `Rule.author` and `Rule.severity.displayName`, verbatim. Every other key, `priority` included, is a rule label on the detection. Google does not document how the meta `severity` string maps to a detection's severity; opentide writes Google's community spelling (`Info`, `Low`, `Medium`, `High`, `Critical`) and expresses alert weight through `$risk_score`, which Google does document.

### Severity

The block `severity`, else `response.alert_severity`:

| `response.alert_severity` | meta `severity` |
|---------------------------|-----------------|
| `Informational` | `Info` |
| `Low` | `Low` |
| `Medium` | `Medium` |
| `High` | `High` |
| `Critical` | `Critical` |
| missing | `Medium` |

The alert's risk score is not derived: it is the `$risk_score` line of `outcome` ([advisory](#advisories)).

### Assembled rule

```
rule <rule name> {
  meta:
    <key> = "<value>"
    ...

  setup:
    <setup line>

  events:
    <events line>
    ...

  match:
    <group_by> over|by <window> [before|after <pivot>]

  outcome:
    <outcome line>

  condition:
    <condition line>

  options:
    <key> = <value>

  export:
    <export line>
}
```

Each section present in the block is written in this order, as its label indented two spaces and its content indented four, with one blank line before it. A text section is its YARA-L text with line endings normalised to `\n`, leading and trailing blank lines removed, and each non-blank line indented by four spaces; blank lines stay empty. `match` and `options` are rendered from their YAML ([YaraLMatch](../languages/yara-l-1.0.md#yaralmatch), [YaraLOptions](../languages/yara-l-1.0.md#yaraloptions)). The text ends with `}` and one newline. Nothing else is added.

Line `n` of a section text (after its leading blank lines) is line `L + n` of the assembled text, where `L` is the line of that section's label, and its column is four more. The engine and the live validator use this to put a finding on its line in the YAML.

### Tenant setup

```toml
[platform]
enabled = true
identifier = "google_secops"
name = "Google Security Operations"
subschema = "Google SecOps SIEM"
description = "YARA-L 2.0 detection rules for Google SecOps SIEM."
flags = []

[[tenants]]
name = "secops-eu"
description = "Google SecOps, EU multi-region"
strategies = ["PREVIEW", "RELEASE"]
[tenants.setup]
ssl = true
project = "acme-secops"
location = "eu"
instance = "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"
credentials = "$GOOGLE_SECOPS_CREDENTIALS"
deletion = "archive"
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `project` | string | yes | — | The Google Cloud project bound to the SecOps instance, id or number |
| `location` | string | yes | — | The instance's region: `us`, `eu`, `europe`, or a Google Cloud region such as `europe-west2` |
| `instance` | string | yes | — | The SecOps customer id (a UUID) |
| `endpoint` | string | no | `https://<location>-chronicle.googleapis.com` | The regional service endpoint. Google also serves each region as `https://chronicle.<location>.rep.googleapis.com`. |
| `credentials` | string | no | Application Default Credentials | A `$ENV` reference to a service-account key, as a JSON document or a path to one. Without it, the client uses Application Default Credentials (workload identity, `gcloud auth`). |
| `data_access_scope` | string | no | none | A data access scope (Data RBAC), as its id or its full resource name (`projects/…/dataAccessScopes/<id>`, used as given). Sent as `scope` on create; an existing rule whose `scope` differs is updated alone (`updateMask=scope`), so a changed or removed scope reaches every rule. Without it a rule is global. |
| `deletion` | string | no | `archive` | `archive` or `delete` ([Deletion](#deletion)) |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

The instance resource is `projects/<project>/locations/<location>/instances/<instance>`. Requests carry an OAuth 2.0 access token for the scope `https://www.googleapis.com/auth/cloud-platform`, applied as google-auth applies it: user credentials from Application Default Credentials also send their quota project (`x-goog-user-project`), without which Google refuses them. A token that cannot be obtained stops the tenant before any rule call, as `google_secops_tenant_unauthorized`; no request was sent, so it is never an unanswered create. The principal needs these permissions on the instance: `chronicle.rules.verifyRuleText`, `chronicle.rules.create`, `chronicle.rules.get`, `chronicle.rules.update`, `chronicle.rules.delete`, `chronicle.ruleDeployments.get`, `chronicle.ruleDeployments.update`, and, for `opentide query`, `chronicle.events.udmSearch`.

A tenant with an unknown setup key, a literal `credentials` value, or a `deletion` other than `archive` and `delete` fails configuration load.

### Deploy

Paths are relative to `<endpoint>/v1/<instance resource>`. The rule resource is `rules/<id>` with the id from deployment state.

| Call | Request |
|------|---------|
| verify | `POST :verifyRuleText` with `{"ruleText": <assembled>}` |
| create | `POST rules` with `{"text": <assembled>}`, plus `scope` |
| get | `GET rules/<id>?view=FULL` |
| update text | `PATCH rules/<id>?updateMask=text` with `{"text": <assembled>, "etag": <etag from get>}` |
| update scope | `PATCH rules/<id>?updateMask=scope` with `{"scope": <scope>, "etag": <etag>}`, the etag of the latest get or update answer (a text update changes it); an empty `scope` makes the rule global |
| get deployment | `GET rules/<id>/deployment` |
| update deployment | `PATCH rules/<id>/deployment?updateMask=<fields>` with those fields |
| delete | `DELETE rules/<id>` (never with `force=true`) |

`verify` succeeds when the response has `success: true` and no diagnostic with `severity: ERROR`. A failure answers HTTP 200 with `compilationDiagnostics` and no `success`. Its diagnostics fail the rule with `google_secops_verify_failed`, each at its [mapped position](#assembled-rule).

**Run state by strategy.**

| Block status strategy | `enabled` | `alerting` | `runFrequency` |
|-----------------------|-----------|------------|----------------|
| `PREVIEW` | `true` | block `alerting`, else `false` | block `run_frequency`; not sent when the block names none |
| `RELEASE`, `UNIVERSAL` | `true` | block `alerting`, else `true` | as above |
| `DISABLEMENT` | `false` | `false` | not sent |

A preview rule runs and records detections without raising alerts, so a staging rule is measured against live data before it pages anyone. Without a block `run_frequency`, deploy leaves the frequency to Google: a new rule gets Google's default for its shape, and an existing one keeps what it has. Google cannot revert a rule moved off a legacy schedule, so deploy never sets one unasked. A `run_frequency` that verify's `allowedRunFrequencies` does not list fails the rule with `google_secops_run_frequency_not_allowed` before any write.

`runFrequency` is sent with `scheduleCustomizations` when `schedule` is set, and alone, which clears the customizations, when the block names a `run_frequency` but no `schedule` and the remote rule has some. Deploy compares the schedule as Google stores it: `ensureEnrichmentCompleteness` absent is `false`, and `lateArrivingDataAdjustment` is compared in seconds (`"1800s"` and `"1800.000s"` are equal), so an unchanged schedule is not sent again.

| Situation | Calls |
|-----------|-------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL`, no binding | verify, create, record the id at once, update deployment with `enabled,alerting`, plus `runFrequency` when the block names one |
| same, binding present | get and get deployment. When `archived` is `true`, update deployment with `archived` (`false`) alone first. When the remote text differs, verify and update text; when the remote `scope` differs, update scope. Update deployment with the run-state fields that differ |
| `DISABLEMENT`, binding present | get and get deployment. An archived rule is left as it is: no call. Otherwise the text is updated as above, so a disabled rule still matches its file, and the deployment is updated with `enabled,alerting` (both `false`) when either is `true`; a failed verify or text update is reported and the rule is disabled all the same. |
| `DELETION`, binding present | [Deletion](#deletion) |
| `DISABLEMENT` or `DELETION`, no binding | `external_id_missing` (warning), no call |

A create whose deployment update then fails keeps its binding: the rule exists. The failure is `google_secops_deployment_failed`, and the next deploy repairs the run state.

**Rule health.** The answers deploy already reads say whether Google runs the rule. `executionState` `LIMITED` or `PAUSED` on the deployment is the warning `google_secops_rule_execution_limited`, and `compilationState` `FAILED` on the rule (after a compiler change on Google's side) is the warning `google_secops_rule_compilation_failed`. Neither stops the deploy.

#### Deletion

| `deletion` | Calls | Binding |
|------------|-------|---------|
| `archive` (default) | get deployment; when `archived` is already `true`, nothing. Otherwise update deployment with `enabled,alerting` (`false`) when either is `true`, then with `archived` (`true`) | kept. A later deploy with another strategy unarchives the same rule. |
| `delete` | `DELETE rules/<id>` | removed. When Google refuses the delete (any 4xx but 401, 403, 404, and 429: Google does not document which status a rule with detections or retrohunts gets), deploy archives instead, keeps the binding, and warns `google_secops_delete_refused` with Google's message. |

opentide never sends `force=true`: that deletes the rule's detections, which are the audit trail of what it found.

#### Errors

| Situation | Behaviour |
|-----------|-----------|
| `get`, `get deployment`, `update text`, `update scope`, or `update deployment` answers 404 | Create the rule again and replace the binding, with the `google_secops_rule_recreated` warning. Under `DISABLEMENT` or `DELETION`, create nothing, remove the binding, and warn `google_secops_rule_missing`. |
| `DELETE` answers 404 | Success. The binding is removed. |
| `update text` or `update scope` answers 409 (`ABORTED`, etag mismatch) | `google_secops_rule_conflict`: the rule changed between get and update. No retry in the same run. |
| A create answers 2xx without a rule id in `name`, or with a body that is not JSON | `google_secops_create_no_id` |
| A create gets no answer (timeout, reset) or a 5xx | `google_secops_create_unconfirmed`. Deploy does not resend it: the rule may exist, and the operator binds or removes it. |
| 401 or 403 | `google_secops_tenant_unauthorized`: the tenant stops. |
| 429 (`RESOURCE_EXHAUSTED`), or 503 on any call but create | Wait `Retry-After` (at most 300 seconds), else the `RetryInfo.retryDelay` in `error.details`, else 5, 15, then 60 seconds; resend at most three times, then fail the rule. A 429 was not executed, so a create is resent after one too. |
| Any other error | The rule fails with Google's `error.status` and `error.message`. |

### Not managed

Deploy manages custom rules (`ru_…`) and their deployment, and nothing else in the instance. These stay in the console or in other tools, and deploy never reads, changes, or removes them: curated rules and rule sets (`ur_…`), rule exclusions (findings refinements), reference lists and data tables (a rule that names a missing one fails `verifyRuleText`), retrohunts, rule tests, saved searches and dashboards, GoogleSQL rules, and alert and case handling in SOAR. [RFC 0019](../../rfcs/0019-google-secops-yara-l.md#resolved-questions) lists the ones planned as follow-ups.

### Query validation

| Check | Google SecOps |
|-------|---------------|
| `opentide validate` (offline) | yes: the constraints and the YARA-L language, `rule` profile |
| `opentide validate query` (offline) | YARA-L: a block's sections, and a `.yaral` or `.yl2` file |
| `opentide validate query --live` | yes: `verifyRuleText` on the assembled text |
| `opentide query` | yes: a YARA-L search through `udmSearch` (v1, `queryDialect=YL2`) |

**Live.** Each rule's assembled text is sent to `verifyRuleText`.

| Response | Result |
|----------|--------|
| `success: true`, no `ERROR` diagnostic | valid. `WARNING` diagnostics are reported as `google_secops_compile_warning`. |
| `ERROR` diagnostics | invalid: each one is `google_secops_compile_error` with Google's `message` and `uri` |
| a block `run_frequency` outside `allowedRunFrequencies` | invalid: `google_secops_run_frequency_not_allowed` |
| HTTP 401 or 403 | the tenant fails |

A diagnostic's `position` (1-based lines and columns, end inclusive) is mapped into the section key it falls in ([Assembled rule](#assembled-rule)). A position inside the generated header or meta, or no position, is reported on the block. `verifyRuleText` resolves the tenant's reference lists and data tables, which the offline check cannot.

**Query.** `opentide query --platform google_secops` sends a [`YaraLSearch`](../languages/yara-l-1.0.md#text-forms) to `GET <endpoint>/v1/<instance resource>:udmSearch` with `query`, `queryDialect=YL2`, `timeRange.startTime`, `timeRange.endTime`, and `limit` (at most 10,000; Google coerces more to 10,000). The method is read-only and saves nothing. It returns matched `events` for a filter search and `stats` for a search with `match` or `outcome`; `moreDataAvailable` or `stats.tooManyResults` is reported as a warning that the result is truncated. `opentide query --rule` is not supported for `google_secops`: a rule runs in the detection engine, and a retrohunt writes detections.

## Relationships

- [platforms](index.md): shared fields, capability matrix, external ids
- [yara-l-1.0](../languages/yara-l-1.0.md): `YaraLSections`, `YaraLMatch`, `YaraLOptions`, the YARA-L language, the `rule` and `search` profiles
- [deployment-state.md](../deployment-state.md): the rule id
- [deployment.md](../deployment.md): status strategies
- [elastic-1.0](elastic-1.0.md#attck): the ATT&CK technique union
- [rule-1.0.md](../objects/rule-1.0.md): `response.alert_severity`, `techniques`, `detection_model`, `description`
- [validation.md](../validation.md): static validation, advisories, query validation
- [RFC 0019](../../rfcs/0019-google-secops-yara-l.md): design, research, and alternatives

## Defaults & overrides

| Field | Default |
|-------|---------|
| Rule name | Shared `name`, else [derived](#rule-name) |
| `severity` | [Severity](#severity), else `Medium` |
| `priority` | `severity` |
| `alerting` | `false` under `PREVIEW`, `true` under `RELEASE` and `UNIVERSAL` |
| `run_frequency` | Not sent: Google's default for a new rule, the current one for an existing rule |
| `endpoint` | `https://<location>-chronicle.googleapis.com` |
| `deletion` | `archive` |

## Examples

A single-event rule:

```yaml
configurations:
  google_secops:
    enabled: true
    schema: platform::google_secops::1.0
    status: STAGING
    run_frequency: LIVE
    meta:
      data_source: Microsoft Sysmon
    events: |
      $e.metadata.event_type = "PROCESS_LAUNCH"
      $e.principal.process.file.full_path = /\\(winword|excel|powerpnt)\.exe$/ nocase
      $e.target.process.file.full_path = /\\powershell\.exe$/ nocase
      $e.target.process.command_line = /\s-e(nc|ncodedcommand)?\s/ nocase
    outcome: |
      $risk_score = 70
      $host = $e.principal.hostname
      $command_line = $e.target.process.command_line
    condition: |
      $e
```

A multi-event rule with a window, aggregations, and suppression:

```yaml
configurations:
  google_secops:
    enabled: true
    schema: platform::google_secops::1.0
    status: PRODUCTION
    name: password_spray_then_success
    severity: High
    run_frequency: LIVE_CUSTOMIZABLE
    schedule:
      ensure_enrichment_completeness: true
    events: |
      $fail.metadata.event_type = "USER_LOGIN"
      $fail.security_result.action = "BLOCK"
      $fail.principal.ip = $ip
      $fail.target.user.userid = $user

      $success.metadata.event_type = "USER_LOGIN"
      $success.security_result.action = "ALLOW"
      $success.principal.ip = $ip
      $success.target.user.userid = $user

      $fail.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds
    match:
      group_by: [$user, $ip]
      window: 30m
    outcome: |
      $risk_score = max(80)
      $risk_entity_to_score = $user
      $failed_attempts = count_distinct($fail.metadata.id)
      $target_hosts = array_distinct($success.target.hostname)
    condition: |
      #fail >= 10 and $success
    options:
      suppression_window: 1h
```

`condition` is a block scalar on purpose: `condition: #fail >= 10 and $success` as a plain scalar is a YAML comment, loads as null, and fails with `yaral_section_empty`.

Fixtures:

- block: [fixtures/platforms/google-secops.yaml](../../fixtures/platforms/google-secops.yaml);
- rules: [fixtures/valid/rule-google-secops-process-1.0.yaml](../../fixtures/valid/rule-google-secops-process-1.0.yaml) and [fixtures/valid/rule-google-secops-spray-1.0.yaml](../../fixtures/valid/rule-google-secops-spray-1.0.yaml);
- the tenant they deploy to: [fixtures/platforms/google-secops/tenant.toml](../../fixtures/platforms/google-secops/tenant.toml);
- for each rule, the assembled `.yaral` text and the request bodies deploy sends, under [fixtures/platforms/google-secops/](../../fixtures/platforms/google-secops/).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.2 | 2026-11-12 | From the conformance review against Google's API reference and detection pages: `DISABLEMENT` disables a rule even when its verify or text update fails; a create is never resent after a 5xx (`google_secops_create_unconfirmed`), a 2xx create without JSON is `google_secops_create_no_id`; 429 backs off with `Retry-After`, then `RetryInfo`, then 5, 15, 60 seconds; credentials are applied with their quota project, and a token failure stops the tenant; no `runFrequency` is sent unless the block names one; the schedule is compared as Google stores it, and cleared when removed; an archived rule is unarchived before its text is updated; the rule `scope` is compared and updated on its own, and `data_access_scope` takes an id or a full name; a refused delete is any 4xx but 401, 403, 404, 429; rule health warnings `google_secops_rule_execution_limited` and `google_secops_rule_compilation_failed`; a Not managed list; the regional `rep` endpoint; the reason an unchanged text is not resent (revisions, not the detection limit); the `$risk_score` default is the instance's. Schema id unchanged. (Settled in review: the scope update carries the etag of the latest answer and its 409 is a conflict; a 404 on any rule or deployment call follows the 404 row; `DISABLEMENT` and the archive path read the deployment first and send nothing to an archived rule, and only the fields that differ otherwise.) |
| 1.3 | 2026-11-12 | A derived rule name that is a YARA-L keyword gets the prefix `r_`, as one that starts with a digit does: `rule any {` does not compile. |
| 1.1 | 2026-11-12 | The derived meta no longer has `tactic`: Google documents a comma-separated list for `technique` only, and its coverage matrix derives tactics from techniques. `tactic` is no longer a reserved meta key, so a block may set one in `meta`. Schema id unchanged. |
| 1.0 | 2026-11-11 | Initial field contract ([RFC 0019](../../rfcs/0019-google-secops-yara-l.md)): YARA-L sections as keys (`events`, `outcome`, `condition`, `setup`, `export` as text; `match` and `options` as YAML objects) assembled into a rule with derived name and meta; severity, priority, alerting, run frequency, schedule customizations; Chronicle API v1 deploy with the rule id in deployment state; archive by default on `DELETION`, never a forced delete; live validation with `verifyRuleText`; `opentide query` through `udmSearch`. |
