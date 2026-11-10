# RFC 0016: Bitdefender GravityZone detection platform

- **RFC:** 0016
- **Title:** Bitdefender GravityZone detection platform
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-09
- **Accepted:** 2026-11-10, with the normative text in [specs/platforms/bitdefender-1.0.md](../specs/platforms/bitdefender-1.0.md)
- **Issue:** [opentidehq/specifications#75](https://github.com/opentidehq/specifications/issues/75)
- **Related:** [RFC 0015](0015-yara-language.md), the YARA language its `yara` kind embeds
- **Implementation:** opentidehq/opentide (the `bitdefender` platform); opentidehq/language-server (the GravityZone criteria catalogue and `bitdefender_*` codes)

## Summary

Add a tenth detection platform, `bitdefender` (display name **Bitdefender GravityZone**, schema `platform::bitdefender::1.0`). Its block is one GravityZone **custom detection rule** of one of two kinds:

- `detection`: a Basic rule, made of criteria on a process, file, connection, registry, or XDR event;
- `yara`: a YARA detection rule, a [`YaraSignature`](../specs/languages/yara-1.0.md#yarasignature) plus `on_access`.

Exclusion rules are out of scope. An exclusion suppresses detections and detects nothing, so it is not an opentide rule. Deploy creates, updates, and deletes detection rules (`type: 1`) only.

Deploy goes through the GravityZone Public API (JSON-RPC 2.0, Incidents API) with `createCustomRule`, `updateCustomRule`, and `deleteCustomRule`. Every update sends the whole payload. GravityZone assigns each rule a 24-hex id, which is kept in [deployment state](../specs/deployment-state.md), as for every platform with vendor-assigned ids.

The change is additive. It adds `configurations.bitdefender` and a deployment-state platform, and changes no existing block.

## Motivation

Bitdefender GravityZone is a common EDR/XDR, and opentide cannot reach it. Teams keep GravityZone custom rules in the console, outside their detection catalogue, without objectives, review, or lifecycle. Since GravityZone v6.74 (June 2026), the Public API can create, update, and delete custom detection rules, Basic and YARA. A detection-as-code platform is possible for the first time.

## Research

### GravityZone Public API

The sources are Bitdefender's own GravityZone help centre, fetched 2026-11-09. Cloud pages are `77209-…`, partner (MSP) pages `77211-…`, and on-premises pages `77212-…`. Bitdefender's own client code confirms the shapes: [`bitdefender/n8n-nodes-gravityzone`](https://github.com/bitdefender/n8n-nodes-gravityzone) (`nodes/GravityZone/actions/incidents/*CustomRule*.operation.ts`) and the FortiSOAR connector [`fortinet-fortisoar/connector-bitdefender`](https://github.com/fortinet-fortisoar/connector-bitdefender).

#### Transport and authentication

| Item | Fact | Source |
|------|------|--------|
| Protocol | JSON-RPC 2.0 over HTTPS `POST`, `Content-Type: application/json`, a string `id` on every request. No batch requests and no notifications. | [Public API](https://www.bitdefender.com/business/support/en/77209-125277-public-api.html) |
| URL | `<Access URL>/v1.0/jsonrpc/<api>`. The Access URL is shown under *My Account > Control Center API*, e.g. `https://cloud.gravityzone.bitdefender.com/api`. | same |
| Cloud instances | `cloudgz.gravityzone.bitdefender.com` (instance 1, EU), `cloud.gravityzone.bitdefender.com` (instance 2), `cloudap.gravityzone.bitdefender.com` (instance 3) | [instance 1](https://www.bitdefender.com/business/support/en/77209-1603894-gravityzone-cloud-instance-1.html), [2](https://www.bitdefender.com/business/support/en/77209-1603895-gravityzone-cloud-instance-2.html), [3](https://www.bitdefender.com/business/support/en/77209-1603896-gravityzone-cloud-instance-3.html) |
| On-premises | `https://<host>/api/v1.0/jsonrpc/`, **with no Incidents API**. Custom rules exist only in the on-premises console UI. | [on-prem Public API](https://www.bitdefender.com/business/support/en/77212-125277-public-api.html) |
| Personal API key | HTTP Basic: the key is the user name and the password is empty. | [Public API](https://www.bitdefender.com/business/support/en/77209-125277-public-api.html) |
| Service API key | `X-API-Key: <key>`. Cloud only, expires within one year, and is scoped to Targets. | [Service API keys](https://www.bitdefender.com/business/support/en/77209-1658556-service-api-keys.html) |
| Permission | The key needs the **Incidents** API. Without it the call fails with `-32001` and *"API Key is not allowed to access the selected API: Incidents"*. `general.getApiKeyDetails` returns `enabledApis`. | [getApiKeyDetails](https://www.bitdefender.com/business/support/en/77209-140282-getapikeydetails.html) |
| Errors | `-32600`, `-32601`, `-32602` (invalid params), `-32000` (server), `-32001` (authorization), `-32002` (resource not found), `-32003` (too many requests: HTTP 429 with `Retry-After`). Details are in `error.data.details`. A failed call with a missing parameter is **HTTP 200** with an `error` member. | [Public API](https://www.bitdefender.com/business/support/en/77209-125277-public-api.html) |
| Rate limits | 10 requests/s per key by default. **`createCustomRule` and `deleteCustomRule`: 5 requests per minute per key, no burst.** `updateCustomRule` and `getCustomRulesList` use the default. | [API rate limits](https://www.bitdefender.com/business/support/en/77209-394430-api-rate-limits.html) |

#### Custom rule methods (Incidents API, `v1.0` only)

| Method | Purpose | Notes |
|--------|---------|-------|
| `createCustomRule` | Create a detection or exclusion rule | Returns the new id (24 hex, e.g. `6372b7a3897aaa77ee021642`) **only with `returnRuleId: true`**, else `true` |
| `updateCustomRule` | Update by `ruleId` | Takes no `subtype`: *"Once a YARA rule is created, it cannot be converted into a basic rule."* Returns `true`. |
| `deleteCustomRule` | Delete by `ruleId` | `type` defaults to `2` (exclusion), so a detection rule needs `type: 1` |
| `getCustomRulesList` | Page through rules (`perPage` ≤ 100) | `type` defaults to `2`. It has no filter by id, name, or tag. |
| `startYaraScan` | On-demand scan with a YARA rule on the rule's own targets | Out of scope ([Unresolved questions](#unresolved-questions)) |

Sources: [Incidents](https://www.bitdefender.com/business/support/en/77209-135326-incidents.html), [createCustomRule](https://www.bitdefender.com/business/support/en/77209-135332-createcustomrule.html) (partner: [77211](https://www.bitdefender.com/business/support/en/77211-135332-createcustomrule.html)), [updateCustomRule](https://www.bitdefender.com/business/support/en/77209-1471075-updatecustomrule.html), [getCustomRulesList](https://www.bitdefender.com/business/support/en/77209-135333-getcustomruleslist.html), [deleteCustomRule](https://www.bitdefender.com/business/support/en/77209-135334-deletecustomrule.html), [startYaraScan](https://www.bitdefender.com/business/support/en/77209-1554402-startyarascan.html), [v6.74 release notes](https://www.bitdefender.com/en-us/blog/businessinsights/whats-new-in-gravityzone-june-2026).

`createCustomRule` parameters:

| Parameter | Values |
|-----------|--------|
| `type` | `1` detection, `2` exclusion (default). An exclusion takes `subtype: 0`. |
| `subtype` | `0` Basic (default), `1` YARA. A `2` Advanced (Lucene-like `advancedQuery`) appears only on unlisted `noindex` pages and is not used here. |
| `name` | Required, at most 128 characters, does not start with whitespace, no `<`, `>`, `'`, `"`, **unique in the company** |
| `description` | At most 1024 characters, same character rules |
| `tags` | Strings of 2–128 characters, same character rules, unique in the array |
| `settings.status` | `1` active (default) / `0` inactive. On a YARA rule, `1`/`0` turns **on-access scanning** on or off. |
| `settings.severity` | `1` Low, `2` Medium, `3` High. Required on detection rules, not allowed on exclusions. |
| `settings.target` | Basic rules: `process`, `file`, `connection`, `registry`, `user connection`, `email`, `application`, `key vault`, `role`, `policy`, `sharing link`, `url`, `ssh key`, `launch template`, `service principal`, `user group`, `automation account`, `automation account hook`, `certificate authority`, `api`, `bucket`, `jira project`, `confluence page`; exclusions also `flow`, `bitbucket repository` |
| `settings.criteriaList` | Basic rules: `[{field, relation, value}]`. `relation` is `is`, `contains` (wildcards), or `any` (array value). Criteria are **AND**ed. There is no OR across criteria and no NOT. |
| `settings.filters` | Basic rules, at most one: `[{field: "detection", value: <alert name>}]` |
| `settings.yaraQuery` | YARA rules: the YARA text, kept as sent. ASCII only, at most 30,000 characters, no `include`, one or more rules. |
| `settings.automaticActions` | `[{type, enabled, settings?}]`: `1` isolate, `2` collect investigation package, `3` add to Sandbox, `4` kill process (`includeParent`, `includeChildren`; Basic only), `5` antimalware scan (`settings.type` `1` quick, `2` full), `6` quarantine (`includeParent`, `includeChildren`), `7` risk scan. EDR detection and YARA rules only. *"Bitdefender EDR subscriptions and GravityZone EDR Cloud licenses do not support automatic actions."* |
| `targets` | Cloud: `endpointTags: [{tagId, companyId}]`. Partner: `companiesIds: [...]` or `endpointTags`, not both. Omitted means the whole company. |
| `companyId` | Partner only: the company that owns the rule |
| `returnRuleId` | `true` returns the id |

GravityZone has no ATT&CK field on a custom rule; free-form `tags` are the only labels. Rules are not policy objects: a rule targets the company, endpoint tags, or companies. The policy only has to enable the EDR sensor (`incidentsSensor`) and, for YARA on-access, on-access scanning ([getPolicyDetails](https://www.bitdefender.com/business/support/en/77209-135304-getpolicydetails.html)).

The **criteria catalogue** (fields per target, enum values, incompatible pairs, EDR-only and XDR-only fields) is [Detection and exclusion criteria for Basic rules](https://www.bitdefender.com/business/support/en/77209-1486297-detection-and-exclusion-criteria.html). The EDR targets:

| Target | Fields (API names) |
|--------|--------------------|
| `process` | `Process.Name`, `.Path`, `.FullPathName`, `.CommandLine`, `.Parent.Name`, `.Parent.Path`, `.Parent.FullPathName`, `.Parent.CommandLine`, `.User`, `.MD5`, `.SHA2` |
| `file` | `File.Name`, `.Path`, `.FullPathName`, `.Operation` (`rename`, `copy`, `create` EDR-only; `shared`, `downloaded`, `uploaded` XDR-only; `read`, `write`, `move`), `.CreatedBy.{Name,Path,FullPathName,CommandLine,User}`, `.CertificateSigner`, `.CertificateIssuer`, `.CertificateSignedStatus` (`is_signed`, `is_unsigned`), and the XDR fields `.MD5`, `.SHA2`, `.Url`, `.SourceIP`, `.DestinationIP` |
| `connection` | `Connection.SourceIP`, `.DestinationIP`, `.SourcePort`, `.DestinationPort`, `.Process.{Name,Path,FullPathName,CommandLine,User}`, `.URL`, `.Domain`, `.Protocol` (`http/https`, `smb`), `.HTTPUser`, `.HTTPDownloadedFile`, `.HTTPUploadedFile`, `.FTPUser`, `.SSHUser`, `.TelnetUser`, `.SMBDomain`, `.SMBSharePath`, `.SMBUser`, `.WMIExecQuery`, `.FileRemotePath`, `.FileRemoteOperation` (`create`, `rem_delete`, `read`, `write`, `move`) |
| `registry` | `Registry.Key` (hive as `HKLM`, `HKCU`, `HKU`, `HKCR`, `HKCC`, `HKLU`), `.Value`, `.Data`, `.DataType` (`string`, `expandablestring`, `dword`, `qword`, `binary`, `none`, `link`, `resource_list`, `full_resource_descriptor`, `resource_requirements_list`), `.Operation` (`key_created`, `key_deleted`, `key_renamed`, `value_created`, `value_deleted`, `value_written`), `.CreatedBy.{Name,Path,FullPathName,CommandLine}` |

YARA constraints ([YARA detection rules](https://www.bitdefender.com/business/support/en/77209-1118491-yara-detection-rules.html)):

- At most 50 YARA rules per company.
- BEST in Local Scan mode on x64 Windows, Linux, and macOS (not Linux ARM64).
- On-access scanning covers files up to 50 MB.
- An active EDR licence, not "EDR (Report only)".
- *"A single YARA rule … can contain multiple individual YARA rules."*

**Engine: libyara.** BEST's open-source notices for [Windows](https://www.bitdefender.com/business/support/en/77209-521335-open-source-software-used-by-best-for-windows.html) and [Linux](https://www.bitdefender.com/business/support/en/77209-521336-open-source-software-used-by-best-for-linux.html) list *YARA* (BSD-3-Clause) with a link to `yara.readthedocs.io`, libyara's documentation. Neither mentions YARA-X. The YARA rules page also links its *Writing YARA rules* and `include` references to libyara's documentation. The libyara version is not published, and the [macOS notice](https://www.bitdefender.com/business/support/en/77209-521337-open-source-software-used-by-best-for-macos.html) does not list YARA.

**Modules: no public source.** No Bitdefender page lists or excludes modules, and no example uses `import`. The documented syntax limits are ASCII, 30,000 characters, and no `include`. Imports are not among them. By maintainer decision (2026-11-10), the modules of the Bitdefender profile ([yara-1.0](../specs/languages/yara-1.0.md#platform-profiles)) are assumed to compile.

## Detailed design

### 1. Block (`platform::bitdefender::1.0`)

#### 1.1 Shape

The block root holds the rule's identity, labels, scope, and response. Below it sits **exactly one kind object**: `detection` or `yara`. The kind decides the GravityZone `type` and `subtype`, and which root keys apply.

```yaml
configurations:
  bitdefender:
    enabled: true
    schema: platform::bitdefender::1.0
    status: STAGING                   # shared; required
    name: ""                          # shared; empty → the opentide rule name
    severity: High                    # Low | Medium | High; default from response.alert_severity
    tags: [office, initial-access]    # added to the derived tags
    targets:                          # default: tenant targets, else the whole company
      endpoint_tags: [tier0-servers]  # tenant aliases; or companies: [acme] for a partner tenant
    actions:                          # automatic actions; detection and yara only
      kill_process: {include_children: true}
      collect_investigation_package: true
    detection:                        # exactly one of detection | yara
      target: process
      alert: null                     # optional: GravityZone alert name (filters[detection])
      criteria:
        - field: Process.Parent.Name
          any: [winword.exe, excel.exe, powerpnt.exe]
        - field: Process.Name
          is: powershell.exe
        - field: Process.CommandLine
          contains: "*-enc*"
```

```yaml
configurations:
  bitdefender:
    enabled: true
    schema: platform::bitdefender::1.0
    status: PRODUCTION
    actions:
      quarantine: true
      antimalware_scan: full
    yara:
      on_access: true                 # settings.status; default true
      signature: |
        import "pe"

        rule APT_Loader_Stage1 : loader {
          meta:
            description = "Stage-1 loader with an encrypted config blob"
          strings:
            $cfg = { 4D 5A 90 00 [4-16] 43 46 47 21 }
            $mutex = "Global\\qx-7731" ascii wide
          condition:
            pe.is_pe and filesize < 2MB and all of them
        }
```

#### 1.2 Block fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `severity` | string | optional | [derived](#14-derived-fields) | `Low`, `Medium`, or `High`. |
| `tags` | list[string] | optional | null | Extra GravityZone tags. Deploy adds the [derived tags](#14-derived-fields). |
| `targets` | [BitdefenderTargets](#targets) | optional | tenant `targets` | Endpoint tags or companies the rule applies to. |
| `actions` | [BitdefenderActions](#actions) | optional | null | Automatic actions. |
| `detection` | [BitdefenderDetection](#detection) | conditional | — | A Basic detection rule (`type: 1`, `subtype: 0`) |
| `yara` | [BitdefenderYara](#yara) | conditional | — | A YARA detection rule (`type: 1`, `subtype: 1`) |

The shared `name` is the GravityZone rule name; empty means the opentide rule `name`. `status` is required, as on `elastic` and `sysdig`.

##### `detection`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `target` | string | yes | — | A GravityZone target from [§3.1](#custom-rule-methods-incidents-api-v10-only), written as the API spells it (`process`, `user connection`). The exclusion-only targets `flow` and `bitbucket repository` are not allowed. |
| `criteria` | list[Criterion] | yes | — | At least one. All criteria must match (AND). |
| `alert` | string | optional | null | The GravityZone alert (detection) name; sent as `filters: [{field: "detection", value: <alert>}]`. |

`criteria[]` (Criterion) has `field` and **exactly one** relation key:

| Field | Type | Description |
|-------|------|-------------|
| `field` | string | API field name (`Process.CommandLine`) from the [criteria catalogue](#15-criteria-catalogue) for the `target` |
| `is` | string or integer | Exact match. Sent as `relation: "is"`. |
| `contains` | string | Substring with `*` and `?` wildcards. Sent as `relation: "contains"`. Not allowed on enum fields. |
| `any` | list[string or integer], non-empty | Any of the values. Sent as `relation: "any"`. |

Writing the relation as the key (`contains: "*-enc*"`) keeps one criterion on one line, and makes a missing or doubled relation a shape error.

##### `yara`

`BitdefenderYara` is a [`YaraSignature`](../specs/languages/yara-1.0.md#yarasignature) plus:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `on_access` | boolean | optional | `true` | On-access scanning with this rule (`settings.status`). With `false`, the rule exists for on-demand scans only. |

##### `targets`

| Field | Type | Description |
|-------|------|-------------|
| `endpoint_tags` | list[string] | Aliases of the tenant's `endpoint_tags` table. Each resolves to `{tagId, companyId}`. |
| `companies` | list[string] | Partner tenants: aliases of the tenant's `companies` table. Each resolves to a company id. |

At most one of the two is set. Rule files carry aliases, not GravityZone ids, because ids differ per tenant. An alias the tenant does not define fails that rule at deploy (`bitdefender_target_unknown`).

##### `actions`

A map. Each key appears at most once, and `true` enables the action with its defaults.

| Key | GravityZone `type` | Value | Allowed with |
|-----|--------------------|-------|--------------|
| `isolate` | 1 | `true` | detection, yara |
| `collect_investigation_package` | 2 | `true` | detection, yara |
| `sandbox` | 3 | `true` | detection with a process/file target or a `*.CreatedBy.*` criterion; yara |
| `kill_process` | 4 | `true` or `{include_parent: bool, include_children: bool}` (default `false`, `false`) | detection with a process/file target or a `*.CreatedBy.*` criterion |
| `antimalware_scan` | 5 | `quick` or `full` | detection, yara |
| `quarantine` | 6 | `true` or `{include_parent: bool, include_children: bool}` | as `sandbox` |
| `risk_scan` | 7 | `true` | detection, yara |

#### 1.3 Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `bitdefender_rule_kind` | Exactly one of `detection` and `yara` is set. Any other kind key (`exclusion` included) is an unknown key. |
| `bitdefender_target` | `target` is a GravityZone detection target. The exclusion-only targets `flow` and `bitbucket repository` are refused. |
| `bitdefender_criterion_shape` | A criterion has `field` and exactly one of `is`, `contains`, `any`. `any` is a non-empty list. `is` and `contains` are scalars. |
| `bitdefender_criterion_field` | `field` belongs to the `target` in the [catalogue](#15-criteria-catalogue). |
| `bitdefender_criterion_relation` | Enum fields (`*.Operation`, `*.DataType`, `*.Protocol`, `*.CertificateSignedStatus`, …) take `is` or `any` only. `contains` is not allowed on `*.MD5` and `*.SHA2`. |
| `bitdefender_criterion_value` | An enum field's value is one of its values. A port is an integer 0–65535. An IP field holds an IPv4/IPv6 address or CIDR. |
| `bitdefender_criteria_combination` | The catalogue's pairing rules: EDR-only and XDR-only fields or values are not mixed; `File.Certificate*` needs `File.Name` or `File.FullPathName`; `Connection.Protocol` needs `Connection.Domain`; the catalogue's incompatible `Connection.*` pairs are not combined; an XDR detection rule uses `alert` or an operation criterion, not both. |
| `bitdefender_action_scope` | Each action is allowed for the kind and target ([actions](#actions)). |
| `bitdefender_targets_shape` | At most one of `targets.endpoint_tags` and `targets.companies`; each list non-empty. |
| `bitdefender_severity` | `severity` is `Low`, `Medium`, or `High`. |
| `bitdefender_yara_ascii`, `bitdefender_yara_size` | [YARA profile](../specs/languages/yara-1.0.md#platform-profiles) |
| `bitdefender_name_duplicate` | Workspace check: two enabled blocks resolve to the same GravityZone name (after [text normalisation](#14-derived-fields)). GravityZone refuses a second rule with one name in a company. |

The YARA `signature` text is also checked against [yara-1.0](../specs/languages/yara-1.0.md#diagnostics) under the Bitdefender profile.

Advisories (warnings, [validation.md](../specs/validation.md#platform-advisories)):

| Code | When |
|------|------|
| `bitdefender_registry_full_hive` | A `Registry.Key` value starts with a full hive name (`HKEY_LOCAL_MACHINE\…`). GravityZone accepts it, and the rule never triggers. |
| `bitdefender_contains_no_wildcard` | A `contains` value has no `*` or `?`. GravityZone matches it as written. The author most likely meant `*value*`. |
| `bitdefender_severity_collapsed` | `response.alert_severity` is `Critical` or `Informational` and `severity` is not set. GravityZone has three levels, so the value is mapped to `High` or `Low`. |

#### 1.4 Derived fields

| GravityZone field | Derivation |
|-------------------|------------|
| `name` | Shared `name`, else the opentide rule `name`, [normalised](#text-normalisation), at most 128 characters |
| `description` | opentide `description`, whitespace collapsed, normalised, at most 1024 characters (ellipsis when cut) |
| `settings.severity` | `severity`, else from `response.alert_severity`: `Critical` → 3, `High` → 3, `Medium` → 2, `Low` → 1, `Informational` → 1; missing → 2 |
| `tags` | The union, without duplicates, in this order: the block `tags`; each ATT&CK technique id of the rule (`techniques` plus those inherited through `detection_model`, the union [elastic-1.0](../specs/platforms/elastic-1.0.md#attck) uses); `opentide`; `opentide:<metadata.uuid>`; the tenant `tags`. Each tag is normalised. A tag that ends up shorter than 2 characters is dropped. |
| `settings.status` | `1`, or `0` under `DISABLEMENT` |

The `opentide:<uuid>` tag is for analysts and audits. Deploy never uses it to find a rule ([deployment-state](../specs/deployment-state.md): no rediscovery by listing).

##### Text normalisation

GravityZone refuses `<`, `>`, `'`, `"` and leading whitespace in names, descriptions, and tags. Deploy replaces `<` → `‹`, `>` → `›`, `'` → `’`, `"` → `”`, and strips leading whitespace, so a description can quote a command line without failing the rule.

#### 1.5 Criteria catalogue

The catalogue is data, not spec prose: the language server's `catalogs/bitdefender/criteria.toml`. It is generated from Bitdefender's criteria page by a sync script and pinned in the spec by its source page and date. The catalogue covers every target, its fields, each field's kind (string, integer, IP, enum with values, hash), its availability (EDR, XDR sensor, both), and the pairing rules. For a target the catalogue does not cover, an unknown field is a warning, not an error (as Falco treats an uncovered source).

#### 1.6 Tenant setup

```toml
[platform]
enabled = true
identifier = "bitdefender"
name = "Bitdefender GravityZone"
subschema = "Bitdefender GravityZone"
description = "Custom detection and YARA detection rules for GravityZone EDR/XDR."
flags = []

[[tenants]]
name = "gravityzone-eu"
strategies = ["RELEASE"]
[tenants.setup]
ssl = true
url = "https://cloudgz.gravityzone.bitdefender.com/api"
api_key = "$GRAVITYZONE_API_KEY"
key_type = "personal"
automatic_actions = true
tags = ["managed-by-opentide"]
targets = { endpoint_tags = ["tier0-servers"] }

[tenants.setup.endpoint_tags]
tier0-servers = { tag_id = "5b680f6fb1a43d860a7b23c8", company_id = "61827b8036492c2fc0718722" }

[tenants.setup.companies]
acme = "61827b8036492c2fc0718722"
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | The Control Center API Access URL, ending in `/api` (cloud instance 1, 2, 3, or the partner console's) |
| `api_key` | string | yes | — | MUST be a `$ENV` reference. Needs the Incidents API. |
| `key_type` | string | no | `personal` | `personal` (HTTP Basic, key as user, empty password) or `service` (`X-API-Key`) |
| `company_id` | string | no | the key's company | Partner tenants: the company that owns created rules (`companyId`). 24 hex. |
| `automatic_actions` | bool | no | `true` | `false` for EDR subscriptions without automatic actions. Deploy then sends no actions and reports `bitdefender_actions_unsupported` (warning) for a block that sets them. |
| `targets` | table | no | none | Default `targets` for blocks that set none |
| `endpoint_tags` | table | no | `{}` | Alias → `{tag_id, company_id}` (24 hex each) |
| `companies` | table | no | `{}` | Alias → company id (24 hex) |
| `tags` | list[string] | no | `[]` | Tags added to every rule on this tenant |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification) |

A tenant with an unknown setup key, a literal `api_key`, or an id that is not 24 hex fails configuration load. On-premises GravityZone has no Incidents API: an on-premises URL deploys nothing and fails the tenant with `bitdefender_incidents_api_unavailable` on the first `-32601` (method not found).

#### 1.7 Deploy

Bitdefender is **state-backed**, like Defender for Endpoint, SentinelOne, CrowdStrike, and Sysdig. GravityZone assigns the rule id, and nothing on the rule can carry it. The id lives in deployment state, never in the rule file:

- **Where.** `platforms.bitdefender.<tenant>` in `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`). The tenant key is the configured tenant `name`, whitespace-stripped. One binding per tenant.
- **Shape.** The 24-hex string `createCustomRule` returns, stored lower-case. It matches `^[0-9a-f]{24}$`; anything else fails `external_id_shape` on write and `deployment_state_shape` on read.
- **Decisions.** Deploy MUST follow the [deploy decisions](../specs/deployment-state.md#deploy-decisions) of deployment state (table below). It MUST NOT find a rule by listing (`getCustomRulesList`), by name, or by the `opentide:<uuid>` tag.
- **No orphan creates.** Deploy MUST NOT call `createCustomRule` unless the returned id can be kept. It refuses with `deployment_state_ignored` when the state directory is gitignored, and with `deployment_state_unpersisted` when the run cannot persist state. Generated CI follows the deployment-state [CI requirements](../specs/deployment-state.md#continuous-integration) as for every state-backed platform.
- **The id is the create's only output.** `createCustomRule` is always sent with `returnRuleId: true`. A create answered with anything but a 24-hex string fails the rule with `bitdefender_create_no_id`. GravityZone may have created a rule that opentide holds no handle on, and deploy MUST NOT look it up to recover the id. The failure names the rule `name`, so the operator can find and remove the rule in the console.
- **Writes and reads.** The binding is written as soon as the create returns, before any later call for that rule. It is removed only after a successful `deleteCustomRule`, after a `-32002` on delete, or by the `DISABLEMENT`-on-missing path below. Status and reporting (`opentide deploy plan`, the status interfaces) read the id from the shard only.
- **No legacy keys.** `rule_id`, `rule_id_bundle`, and `rule_id::<tenant>` on a `bitdefender` block fail `external_id_in_rule`, as on every block. Bitdefender never had a legacy key, so `migrate-state` has nothing to move for it.

A create sends (detection kind; `id` is a fresh UUID per request):

```json
{
  "jsonrpc": "2.0",
  "id": "4d7c3c1e-6f0a-4c2e-9a51-3d1f0b9e2a77",
  "method": "createCustomRule",
  "params": {
    "type": 1,
    "subtype": 0,
    "name": "Office application spawns encoded PowerShell",
    "description": "Detects an Office application starting PowerShell with an encoded command.",
    "tags": ["office", "initial-access", "T1059.001", "T1566.001", "opentide", "opentide:00000000-0000-4000-8003-000000000030", "managed-by-opentide"],
    "settings": {
      "status": 1,
      "severity": 3,
      "target": "process",
      "criteriaList": [
        {"field": "Process.Parent.Name", "relation": "any", "value": ["winword.exe", "excel.exe", "powerpnt.exe"]},
        {"field": "Process.Name", "relation": "is", "value": "powershell.exe"},
        {"field": "Process.CommandLine", "relation": "contains", "value": "*-enc*"}
      ],
      "automaticActions": [
        {"type": 1, "enabled": false},
        {"type": 2, "enabled": true},
        {"type": 3, "enabled": false},
        {"type": 4, "enabled": true, "settings": {"includeParent": false, "includeChildren": true}},
        {"type": 5, "enabled": false},
        {"type": 6, "enabled": false},
        {"type": 7, "enabled": false}
      ]
    },
    "targets": {"endpointTags": [{"tagId": "5b680f6fb1a43d860a7b23c8", "companyId": "61827b8036492c2fc0718722"}]},
    "returnRuleId": true
  }
}
```

Settings by kind:

| Kind | `type` / `subtype` | `settings` keys |
|------|--------------------|-----------------|
| `detection` | 1 / 0 | `status`, `severity`, `target`, `criteriaList`, `filters` (when `alert` is set), `automaticActions` |
| `yara` | 1 / 1 | `status` (from `on_access`, or `0` under `DISABLEMENT`), `severity`, `yaraQuery` (the `signature`), `automaticActions` |

**Every update sends the whole payload.** `updateCustomRule` keeps the stored value of any optional parameter it is not sent, and `settings` is mandatory. Deploy therefore never sends a partial update: what the block says is what the rule holds after the call, whatever the console changed in between.

**Automatic actions are sent in full.** Every action type the kind allows is sent, each `enabled: true` or `false`: seven types for `detection`, six for `yara` (no kill process). An update therefore turns off an action removed from the block. With tenant `automatic_actions = false`, the key is omitted.

| Block status strategy | Binding | GravityZone calls |
|-----------------------|---------|-------------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `createCustomRule` with `returnRuleId: true`; the returned id is recorded |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `updateCustomRule` with the **whole payload**: `ruleId`, `type`, `name`, `description`, `tags`, the full `settings` (every action type included), and `targets` |
| `DISABLEMENT` | present | `updateCustomRule` as above with `settings.status: 0` (Basic: inactive; YARA: on-access off) |
| `DELETION` | present | `deleteCustomRule` with `ruleId` and `type: 1` (the API defaults to exclusion), then the binding is removed |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

Failure handling:

- **Rule gone.** `updateCustomRule` answers `-32002`. Deploy creates the rule again and replaces the binding, with a `bitdefender_rule_recreated` warning. Under `DISABLEMENT` it creates nothing, removes the binding, and warns `bitdefender_rule_missing`. A `DELETION` answered with `-32002` succeeds and removes the binding.
- **Name taken.** A create refused because the name exists in the company fails the rule with `bitdefender_name_conflict`. Deploy MUST NOT adopt the existing rule.
- **Kind changed.** The kind is fixed once bound: GravityZone cannot turn a YARA rule into a Basic rule, and `updateCustomRule` takes no `subtype`. Changing it means `DELETION` and a new deploy. An update refused for a type mismatch fails the rule with `bitdefender_kind_changed`.
- **Rate limits.** The client MUST space `createCustomRule` and `deleteCustomRule` at most 5 per rolling minute per API key, across all rules of a run. It MUST wait out `-32003` or HTTP 429 (`Retry-After`) and retry the same request. A rate-limited request was not executed, so retrying a create is safe.
- **Unconfirmed create.** A `createCustomRule` with no answer (timeout, connection reset) MUST NOT be retried blindly. Deploy retries it once. A `bitdefender_name_conflict` on that retry means the first create may have succeeded with an unknown id, and is reported as `bitdefender_create_unconfirmed`. The operator resolves it. Deploy never lists rules to find the id.
- **Errors in HTTP 200.** A response is a failure when it has an `error` member, whatever the HTTP status. `-32001`, HTTP 401, and HTTP 403 stop the tenant (`bitdefender_tenant_unauthorized`). Every other error fails the rule with its code and `error.data.details`.

Deploy MUST NOT call `getCustomRulesList` on the deploy path. It MUST NOT write to the rule file.

#### 1.8 Query validation

| Check | Bitdefender |
|-------|-------------|
| `opentide validate` (offline) | yes: block constraints, the criteria catalogue, and the YARA engine for `yara.signature` |
| `opentide validate query --live` | no (`supported: false`): GravityZone has no API dry run; "Check rule" is console-only |
| `opentide query` | no |


## Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| O1 | `bitdefender` models (block, kinds, criterion, actions, targets) and tenant setup models | opentide | 2–3 |
| O2 | JSON-RPC client on `TenantSession`: envelope, error mapping, auth modes, create/delete rate limiter, `Retry-After` | opentide | 2–3 |
| O3 | Compiler: derived fields, normalisation, settings by kind, full actions, targets resolution; `api_body` golden tests against the fixtures | opentide | 2–3 |
| O4 | Deployer on deployment state: `bitdefender` in `STATE_PLATFORMS` (not `INTEGER_ID_PLATFORMS` or `MIGRATED_PLATFORMS`), a 24-hex rule in `normalise_external_id`; create, whole-payload update, disable, delete, recreate, name conflict, `bitdefender_create_no_id`, unconfirmed create | opentide | 3 |
| O5 | Wiring (about 25 registrations), bundled TOML, template, diagnostics pages, docs, MCP | opentide | 2–3 |
| O6 | Tests: model, compile, deployer (fake JSON-RPC server), setup, e2e | opentide | 4–5 |
| L8 | GravityZone criteria catalogue, sync script, `bitdefender.rs` constraint codes, completion and hover | language-server | 4–5 |
| E1 | `OFFLINE_QUERY_LANGUAGES["bitdefender"] = ("yara",)` once the YARA engine ships ([RFC 0015](0015-yara-language.md)) | opentide | <1 |

About 20–25 person-days. Until the YARA engine ships, a `yara` block validates structurally only.

## Drawbacks

- **Rate limits make the first deploy slow.** At 5 creates per minute per key, a 300-rule catalogue takes about an hour to create the first time. Updates are not limited that way. CI jobs need a timeout to match, or several API keys.
- **On-premises GravityZone is not covered.** It has no Incidents API.
- **YARA rules per company are capped at 50.** A large YARA catalogue has to pack several YARA rules into one `signature`.
- **The criteria catalogue is copied from a web page.** When Bitdefender adds fields, the sync script has to run, and until then a new field is an error.

## Alternatives

- **Bitdefender identity by name or by the `opentide:<uuid>` tag.** Rejected. [Deployment state](../specs/deployment-state.md) forbids rediscovery by listing, and `getCustomRulesList` has no filter, so every deploy would page through every rule.
- **Partial updates** (send only what changed). Rejected. GravityZone keeps unsent optional values, so a partial update cannot remove a value, and the stored rule would drift from the block.
- **GravityZone exclusion rules** (`type: 2`), as a third kind or as tunings inside a detection block. Rejected. An exclusion suppresses incidents and detects nothing: it has no objective, threat, or ATT&CK mapping to carry, and a tuning would need a second remote id per tenant. Exclusions stay in the console.
- **Advanced rules** (`subtype: 2`, `advancedQuery`). Deferred. They appear only on unlisted pages. A third kind (`advanced`) is an additive change once Bitdefender publishes them.
- **Decomposed YARA, like HarfangLab's.** Rejected: it cannot express several rules, private helpers, or condition-only rules ([RFC 0015](0015-yara-language.md)).

## Unresolved questions

- The exact error GravityZone returns for a duplicate name, and whether uniqueness spans detection and exclusion rules. Deploy maps the refusal to `bitdefender_name_conflict` by its `error.data.details`. Implementation confirms the code on a tenant.
- Resolving endpoint-tag aliases by name through `getEndpointTags`, instead of a tenant table of ids.
- Whether `startYaraScan` belongs in opentide, as a hunt or an `opentide scan` command. It is not a detection.
- A validate-time check of the 50-YARA-rule cap per company.

## References

- The GravityZone Public API pages in [Research](#gravityzone-public-api); [n8n-nodes-gravityzone](https://github.com/bitdefender/n8n-nodes-gravityzone); [connector-bitdefender](https://github.com/fortinet-fortisoar/connector-bitdefender)
- [RFC 0010](0010-deployment-external-ids.md): deployment external ids; [RFC 0014](0014-sysdig-falco-platform.md): the state-backed platform pattern; [RFC 0015](0015-yara-language.md): the YARA language
