# RFC 0015: Bitdefender GravityZone platform, and one YARA language for Bitdefender and HarfangLab

- **RFC:** 0015
- **Title:** Bitdefender GravityZone detection platform, and a shared YARA language for Bitdefender and HarfangLab
- **Author:** opentide maintainers
- **Status:** proposed
- **Created:** 2026-11-09
- **Issue:** a spec-change issue in opentidehq/specifications, to be opened with this RFC's PR. It answers the YARA half of [opentidehq/specifications#68](https://github.com/opentidehq/specifications/issues/68); the Sigma half of #68 stays open.
- **Implementation:** opentidehq/opentide (new issue: `bitdefender` platform and HarfangLab YARA rework); [opentidehq/language-server#165](https://github.com/opentidehq/language-server/issues/165) (YARA engine), widened to whole YARA rule texts and to `configurations.bitdefender`

> **Review gate.** This RFC is proposed for review only. The normative files it names in [§8](#8-spec-changes-on-acceptance) (`specs/languages/yara-1.0.md`, `specs/platforms/bitdefender-1.0.md`, and the edits to five existing specs, fixtures, `SPECS.md`, and `CHANGELOG.md`) land in the same PR once a maintainer accepts it. That PR follows this text exactly, apart from changes made in review.

## Summary

This RFC adds a tenth detection platform, `bitdefender` (display name **Bitdefender GravityZone**, schema `platform::bitdefender::1.0`). Its block is one GravityZone **custom detection rule** of one of two kinds:

- `detection`: a Basic rule, made of criteria on a process, file, connection, registry, or XDR event;
- `yara`: a YARA detection rule.

GravityZone exclusion rules are out of scope. An exclusion suppresses detections and detects nothing, so it is not an opentide rule. Deploy creates, updates, and deletes detection rules (`type: 1`) only.

Deploy goes through the GravityZone Public API (JSON-RPC 2.0, Incidents API) with `createCustomRule`, `updateCustomRule`, and `deleteCustomRule`. GravityZone assigns each rule a 24-hex id, which is kept in [deployment state](../specs/deployment-state.md).

The RFC also defines **YARA once**, as a shared language spec, `specs/languages/yara-1.0.md`. It covers:

- one `YaraSignature` object: the whole YARA text, written out in the block and deployed verbatim;
- the dialect: what libyara 4.5 compiles, and where YARA-X disagrees;
- a per-platform profile.

Bitdefender (`configurations.bitdefender.yara`) and HarfangLab (`configurations.harfanglab.yara`) both carry a `YaraSignature`. Each block writes its YARA text out in full: what you see in the block is what that tenant gets.

For HarfangLab, this RFC:

- adds `yara.signature` beside the decomposed `strings` and `condition` form;
- fixes the YARA identity: HarfangLab assigns the YaraFile id, so it now lives in deployment state;
- makes `DISABLEMENT` work for YARA;
- reads HarfangLab's per-file compile status instead of trusting HTTP 200;
- makes a HarfangLab block one kind: a Sigma rule or a YARA file, never both.

The analysis engine (language-server) gains a YARA language and a Bitdefender criteria catalogue. With them, `opentide validate` and editors check YARA rules, decomposed YARA fragments, and GravityZone criteria offline, with diagnostics, highlighting, hover, completion, and go-to-definition.

The change is additive for rule files. It adds `configurations.bitdefender`, new optional keys on `configurations.harfanglab.yara`, and two deployment-state platforms. No `schema_id` changes. One HarfangLab rule changes: a block with both `sigma` and `yara` no longer validates. Today such a block deploys only its Sigma rule, so splitting it in two changes nothing on any tenant. Existing HarfangLab YARA rules need a one-time adoption into deployment state ([§7.6](#76-migration)).

## Motivation

- **Bitdefender GravityZone is a common EDR/XDR, and opentide cannot reach it.** Teams keep GravityZone custom rules in the console, outside their detection catalogue, without objectives, review, or lifecycle. Since GravityZone v6.74 (June 2026), the Public API can create, update, and delete custom detection rules, Basic and YARA. A detection-as-code platform is possible for the first time.
- **YARA is the second rule language two EDRs accept, and opentide has no spec for it.** HarfangLab's block has decomposed `strings` and `condition` fields, so it can express only one rule, always with a `strings:` section. It has no private or global helper rules, no tags, and no condition-only rule (`pe.imphash() == "…"`). Nothing compiles the YARA text before it reaches the tenant ([specifications#68](https://github.com/opentidehq/specifications/issues/68), [language-server#165](https://github.com/opentidehq/language-server/issues/165)). Adding Bitdefender with its own YARA field would create a second, different YARA contract.
- **HarfangLab YARA deploy has defects the spec currently codifies.** The spec says a YARA rule is deleted by `metadata.uuid`, but HarfangLab assigns its own YaraFile id, so delete targets an id the tenant never had. YARA ignores `DISABLEMENT`. A rule with both `sigma` and `yara` never deploys its YARA half. A YaraFile that fails to compile comes back as HTTP 200 and is reported as deployed. [§3.2](#32-harfanglab-yara) has the evidence.
- **One YARA contract for every EDR.** A detection engineer who writes YARA for a malware family wants it on every EDR that runs YARA. With one `YaraSignature` shape and one language spec, YARA is written and checked the same way for HarfangLab and Bitdefender. Each platform block still carries its own text, so a block never deploys text written somewhere else.

## Research

### 3.1 Bitdefender GravityZone Public API

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

Bitdefender does not document the YARA engine version or its modules.

### 3.2 HarfangLab YARA

HarfangLab publishes no public API reference. The facts below come from third-party clients that call the API: OpenCTI's HarfangLab connectors (`stream/harfanglab`, `stream/harfanglab-intel`), [demisto/content `HarfangLabEDR`](https://github.com/demisto/content/tree/master/Packs/HarfangLabEDR), SEKOIA's and Netskope's HarfangLab integrations, and HarfangLab's own published rules ([HarfangLab/iocs](https://github.com/HarfangLab/iocs)).

| Finding | Status | opentide today |
|---------|--------|----------------|
| A **YaraFile** is a whole YARA source text (`content`) that may hold several rules (`rule_names` is a list; HarfangLab's own `hl_public_reports_master.yar` holds 39). Each file compiles as one YARA namespace, and alerts name `{namespace: "<file name>", rulename}`. | confirmed | One rule per file, decomposed fields |
| `POST /api/data/threat_intelligence/YaraFile/` with `source_id`, `name`, `content`, `hl_status`, `enabled` answers `{"status": [{id, filename, content, status, code}]}`. A rejected file is **HTTP 200** with `status: false`. | confirmed | Any 200/201 is success |
| HarfangLab assigns the YaraFile `id` (`status[0].id`). Update is `PATCH …/YaraFile/{id}`, delete is `DELETE …/YaraFile/{id}`. Clients find files by `name__exact` within `source_id`, and names may repeat. | confirmed | Deletes `YaraFile/{metadata.uuid}`, an id the tenant never had; updates by re-`POST` with an undocumented `overwrite: true` |
| `enabled` is a YaraFile field | confirmed | Never sent, so `DISABLEMENT` has no effect |
| `hl_status` ∈ `stable`, `testing`, `experimental` | confirmed | Sent |
| `global_state`, `rule_confidence_override`, `rule_level_override` on a YaraFile | **unverified** (confirmed only on IOC and Sigma rules) | Sent |
| HarfangLab's own rules set meta `context` to `"file"`, `"memory"`, or `"file,memory"` and never set `os`, `arch`, `score`, or `id` | confirmed | Rewrites `file` to `file.pe`, `file.elf`, or `file.macho`; these values appear in no vendor material |
| Engine version (libyara or YARA-X) and modules | **not published** | `imports` takes any string |
| A rule with both `sigma` and `yara` is classed as Sigma and skipped on a `YARA` tenant | confirmed (`deployer.py:318-335`) | YARA half never deploys |

### 3.3 YARA engines

Two reference compilers exist, both BSD-3-Clause:

- **libyara 4.5** (VirusTotal YARA, C; Python `yara-python`). Every EDR that shipped YARA before 2025 embeds libyara. This includes HarfangLab (YARA since 2020) and Bitdefender (YARA GA November 2024, seven months before YARA-X 1.0).
- **YARA-X 1.x** (Rust). Faster, with better diagnostics and a formatter. It is stricter than libyara in documented places ([*Differences with YARA*](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)): escape sequences in strings, regexp syntax, duplicate rule names, `base64` modifier lengths, and some module fields. Some modules are missing or differ, such as `cuckoo` and `magic`.

Neither vendor names its engine. Two consequences follow:

- The **contract is libyara 4.5**, the engine both vendors most plausibly run.
- **YARA-X is a second opinion.** A rule only YARA-X rejects is a warning, so authors who later move to a YARA-X engine see the problem early.

## Detailed design

### 4. Spec layout

| Path | Change |
|------|--------|
| `specs/languages/yara-1.0.md` | **New.** `spec: language-yara`, version `1.0`, no `schema_id`. The `YaraSignature` object, the dialect, diagnostics codes, platform profiles. |
| `specs/platforms/bitdefender-1.0.md` | **New.** `platform::bitdefender::1.0`, version `1.0`. |
| `specs/platforms/harfanglab-1.0.md` | 1.1 → **1.2**. `yara.signature`, optional `strings`, YaraFile identity in deployment state, `DISABLEMENT`, status parsing, one kind per block. `schema_id` unchanged. |
| `specs/platforms/index.md` | 1.4 → **1.5**. Tenth platform; capability matrix; static-validation bar; external ids; HarfangLab YARA becomes state-backed. |
| `specs/deployment-state.md` | 1.3 → **1.4**. `bitdefender` (`^[0-9a-f]{24}$`) and `harfanglab` (YaraFile id, verbatim) join the shard's platform set. |
| `specs/validation.md` | 1.5 → **1.6**. New advisory codes. |
| `specs/objects/rule-1.0.md`, `rule-1.1.md` | History row: `configurations.bitdefender` (`BitdefenderConfig`). Additive; `schema_id` unchanged. |
| `SPECS.md`, `CHANGELOG.md`, `rfcs/README.md`, `llms.txt` | Index rows |
| `fixtures/` | [§9](#9-fixtures) |

YARA gets a language spec, not a section inside one platform spec as Falco has in [sysdig-1.0](../specs/platforms/sysdig-1.0.md#falco-language). Two platforms carry it, and a third (any EDR that adds YARA) would otherwise copy it.

### 5. The YARA language (`specs/languages/yara-1.0.md`)

#### 5.1 `YaraSignature`

A `YaraSignature` is a YAML object that a platform's `yara` block embeds. Its one shared field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature` | string | yes | The YARA signature, as a `.yar` file holds it: `import` statements, then one or more YARA rules. It may include `private` and `global` rules, rule tags, and comments. |

Requirements:

- **Verbatim.** Deploy MUST send `signature` unchanged apart from line endings normalised to `\n` and a trailing newline. It MUST NOT add, remove, or reorder rules or meta. What the author reviewed is what the tenant compiles. Platform-specific meta that a vendor needs (HarfangLab `context`) is written by the author, and the profile checks it.
- `signature` MUST contain at least one rule that is neither `private` nor `global`.
- `include` MUST NOT appear (`yara_include`). Neither vendor resolves includes: the API takes one text with no file system behind it.
- Rule names MUST be unique within `signature` (`yara_duplicate_rule`).
- **Literal.** `signature` MUST be written out in the block as its own string. A YAML alias (`signature: *name`) that reuses text from elsewhere in the file fails static validation with `yara_signature_alias`. A block that deploys YARA shows that YARA. A rule that targets two platforms writes the text in each block.

The key is `signature`: a YARA text is the signature the EDR scans files and memory with, the term detection engineers use and the one HarfangLab uses for its YARA *signatures engine*. One `signature` may hold several YARA rules, as one `.yar` file does. Other names were rejected:

- `source` collides with HarfangLab's *YaraSource*, the rule feed the tenant's `source_id` names, and with Sysdig's `source`, a Falco event source.
- `rules` collides with the opentide rule itself, and with the planned rename of `configurations` to `rule`.
- `query` (Bitdefender's `yaraQuery`) is wrong because YARA is not a query language.
- `content` (HarfangLab's field) is generic, and opentide already says "detection content" for whole rules.

#### 5.2 Dialect

The language is **YARA as libyara 4.5 compiles it**: rules, `import`, `private`, `global`, rule tags, meta (string, integer, boolean), text, hex, and regular-expression strings with their modifiers (`nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64`, `base64wide`), and the full condition language:

- `and`, `or`, `not`;
- arithmetic and bitwise operators;
- `contains`, `icontains`, `startswith`, `istartswith`, `endswith`, `iendswith`, `iequals`, `matches`;
- `#`, `@`, `!`;
- `at`, `in`, `filesize`, `entrypoint`, `int*`/`uint*` readers;
- `of`, `for … of`, `for … in`, and module fields and functions.

The engine reports:

- an **error** for what libyara 4.5 refuses to compile;
- a **warning** (`yara_x_incompatible`) for what libyara compiles and YARA-X 1.x refuses. Examples: a stray `{` or an unknown escape such as `\R` in a regexp, `@a[-1]`, `base64` on fewer than 3 characters, `entrypoint`, and a repeated `global` or `private`;
- a **warning** for libyara's own compile warnings (`yara_slow_pattern`, and others).

Syntax that only YARA-X accepts is an error under this contract, because libyara refuses it. Examples are `.len()`, octal and hex jump bounds, and boolean expressions inside `of` tuples. The engine names the YARA-X feature in the message. Each platform profile has a `dialect` (`libyara4` for both platforms today), so a later spec revision can move one platform to `yara_x` without changing the language.

The [diagnostics table](#53-diagnostics) is the contract. Each code maps to the libyara source and a test in the language server's `docs/YARA.md`, as `docs/FALCO.md` does for Falco.

A rule with no `strings:` section is valid (answers specifications#68 question 3). `strings` is optional wherever a platform decomposes the rule.

**Modules** (answers specifications#68 question 2): the engine knows `pe`, `elf`, `math`, `hash`, `time`, `dotnet`, `macho`, `magic`, `cuckoo`, `console`, `string`, `lnk`, and `dex`, with their fields and functions, so it can type-check them. Each platform profile names the modules confirmed on its agents. Importing any other known module is a warning. Neither vendor publishes this list, so today each profile's confirmed set is the conservative `pe`, `elf`, `math`, `hash`, `time` ([Unresolved questions](#unresolved-questions)).

#### 5.3 Diagnostics

Errors (static validation rejects the rule):

| Code | Condition |
|------|-----------|
| `yara_parse_error` | Syntax error |
| `yara_include` | An `include` directive |
| `yara_duplicate_rule` | Two YARA rules with one name in a `signature` |
| `yara_duplicate_string` | Two strings with one identifier in a rule (anonymous `$` excepted) |
| `yara_undefined_string` | A `$id`, `#id`, `@id`, `!id`, or `$prefix*` in a condition matching no string of the rule |
| `yara_unreferenced_string` | A string never used in the condition, while the condition does not use `them` (libyara refuses it) |
| `yara_undefined_identifier` | A bare identifier that is no rule defined earlier in `signature` and no module |
| `yara_unknown_module` | `import` of a module libyara does not ship |
| `yara_module_not_imported` | `pe.…` (any module) used without its `import` |
| `yara_unknown_module_member` | A field or function the module does not have, or the wrong arguments |
| `yara_type` | An operator or function applied to the wrong type (`filesize contains "a"`) |
| `yara_regexp` | An invalid regular expression |
| `yara_hex_string` | An invalid hex string (odd nibbles, a bad jump `[a-b]`, unbalanced alternatives) |
| `yara_string_modifier` | A modifier combination libyara refuses (`base64` with `nocase`, `xor` on a hex string), or an `xor`/`base64` argument out of range |
| `yara_number_out_of_range` | An integer literal, size suffix, jump bound, or string index out of libyara's range |
| `yara_duplicate_tag` | A rule tag repeated on one rule |
| `yara_rule_identifier_conflict` | A rule named like an imported module or a keyword |
| `yara_empty_signature` | No YARA rule, or only `private` or `global` rules |
| `yara_signature_alias` | `signature` is a YAML alias instead of its own text |

Warnings (reported, never rejecting):

| Code | Condition |
|------|-----------|
| `yara_x_incompatible` | libyara compiles it and YARA-X 1.x does not (the YARA-X message is quoted) |
| `yara_slow_pattern` | libyara's slow-scanning warnings: a short or all-wildcard atom, a regexp with no fixed atom, a potentially slow loop |
| `yara_entrypoint_deprecated` | `entrypoint`, deprecated in libyara (use `pe.entry_point`/`elf.entry_point`) and refused by YARA-X |
| `yara_suspicious_expression` | An invariant or unsatisfiable condition, a non-boolean condition, or an integer compared with a boolean |
| `yara_module_unconfirmed` | A known module outside the platform profile's confirmed set |
| `yara_meta_missing` | A meta key the platform profile recommends is missing on a non-private rule |

#### 5.4 Platform profiles

| | `bitdefender` | `harfanglab` |
|---|---|---|
| Characters | ASCII only (`bitdefender_yara_ascii`, error) | UTF-8 |
| Size | ≤ 30,000 characters (`bitdefender_yara_size`, error) | no documented limit |
| YARA rules per `signature` | one or more | one or more |
| Confirmed modules | `pe`, `elf`, `math`, `hash`, `time` | `pe`, `elf`, `math`, `hash`, `time` |
| Recommended meta | none | `context` on every non-private rule, valued `file`, `memory`, or `file,memory` (`yara_meta_missing`; another value is `harfanglab_yara_context`, warning) |

### 6. Bitdefender block (`platform::bitdefender::1.0`)

#### 6.1 Shape

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

#### 6.2 Block fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `severity` | string | optional | [derived](#64-derived-fields) | `Low`, `Medium`, or `High`. |
| `tags` | list[string] | optional | null | Extra GravityZone tags. Deploy adds the [derived tags](#64-derived-fields). |
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
| `field` | string | API field name (`Process.CommandLine`) from the [criteria catalogue](#65-criteria-catalogue) for the `target` |
| `is` | string or integer | Exact match. Sent as `relation: "is"`. |
| `contains` | string | Substring with `*` and `?` wildcards. Sent as `relation: "contains"`. Not allowed on enum fields. |
| `any` | list[string or integer], non-empty | Any of the values. Sent as `relation: "any"`. |

Writing the relation as the key (`contains: "*-enc*"`) keeps one criterion on one line, and makes a missing or doubled relation a shape error.

##### `yara`

`BitdefenderYara` is a [`YaraSignature`](#51-yarasignature) plus:

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

#### 6.3 Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `bitdefender_rule_kind` | Exactly one of `detection` and `yara` is set. Any other kind key (`exclusion` included) is an unknown key. |
| `bitdefender_target` | `target` is a GravityZone detection target. The exclusion-only targets `flow` and `bitbucket repository` are refused. |
| `bitdefender_criterion_shape` | A criterion has `field` and exactly one of `is`, `contains`, `any`. `any` is a non-empty list. `is` and `contains` are scalars. |
| `bitdefender_criterion_field` | `field` belongs to the `target` in the [catalogue](#65-criteria-catalogue). |
| `bitdefender_criterion_relation` | Enum fields (`*.Operation`, `*.DataType`, `*.Protocol`, `*.CertificateSignedStatus`, …) take `is` or `any` only. `contains` is not allowed on `*.MD5` and `*.SHA2`. |
| `bitdefender_criterion_value` | An enum field's value is one of its values. A port is an integer 0–65535. An IP field holds an IPv4/IPv6 address or CIDR. |
| `bitdefender_criteria_combination` | The catalogue's pairing rules: EDR-only and XDR-only fields or values are not mixed; `File.Certificate*` needs `File.Name` or `File.FullPathName`; `Connection.Protocol` needs `Connection.Domain`; the catalogue's incompatible `Connection.*` pairs are not combined; an XDR detection rule uses `alert` or an operation criterion, not both. |
| `bitdefender_action_scope` | Each action is allowed for the kind and target ([actions](#actions)). |
| `bitdefender_targets_shape` | At most one of `targets.endpoint_tags` and `targets.companies`; each list non-empty. |
| `bitdefender_severity` | `severity` is `Low`, `Medium`, or `High`. |
| `bitdefender_yara_ascii`, `bitdefender_yara_size` | [YARA profile](#54-platform-profiles) |
| `bitdefender_name_duplicate` | Workspace check: two enabled blocks resolve to the same GravityZone name (after [text normalisation](#64-derived-fields)). GravityZone refuses a second rule with one name in a company. |

The YARA `signature` text is also checked against [§5.3](#53-diagnostics) under the Bitdefender profile.

Advisories (warnings, [validation.md](../specs/validation.md#platform-advisories)):

| Code | When |
|------|------|
| `bitdefender_registry_full_hive` | A `Registry.Key` value starts with a full hive name (`HKEY_LOCAL_MACHINE\…`). GravityZone accepts it, and the rule never triggers. |
| `bitdefender_contains_no_wildcard` | A `contains` value has no `*` or `?`. GravityZone matches it as written. The author most likely meant `*value*`. |
| `bitdefender_severity_collapsed` | `response.alert_severity` is `Critical` or `Informational` and `severity` is not set. GravityZone has three levels, so the value is mapped to `High` or `Low`. |

#### 6.4 Derived fields

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

#### 6.5 Criteria catalogue

The catalogue is data, not spec prose: the language server's `catalogs/bitdefender/criteria.toml`. It is generated from Bitdefender's criteria page by a sync script and pinned in the spec by its source page and date. The catalogue covers every target, its fields, each field's kind (string, integer, IP, enum with values, hash), its availability (EDR, XDR sensor, both), and the pairing rules. For a target the catalogue does not cover, an unknown field is a warning, not an error (as Falco treats an uncovered source).

#### 6.6 Tenant setup

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

#### 6.7 Deploy

Bitdefender is **state-backed**: the rule id lives under `platforms.bitdefender.<tenant>` in `.opentide/states/deployment/<uuid>.json`, and matches `^[0-9a-f]{24}$`.

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

**Automatic actions are sent in full.** Every action type the kind allows is sent, each `enabled: true` or `false`: seven types for `detection`, six for `yara` (no kill process). An update therefore turns off an action removed from the block. With tenant `automatic_actions = false`, the key is omitted.

| Block status strategy | Binding | GravityZone calls |
|-----------------------|---------|-------------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `createCustomRule` with `returnRuleId: true`; the returned id is recorded |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `updateCustomRule` with `ruleId`, `type`, `name`, `description`, `tags`, the full `settings`, and `targets` |
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

#### 6.8 Query validation

| Check | Bitdefender |
|-------|-------------|
| `opentide validate` (offline) | yes: block constraints, the criteria catalogue, and the YARA engine for `yara.signature` |
| `opentide validate query --live` | no (`supported: false`): GravityZone has no API dry run; "Check rule" is console-only |
| `opentide query` | no |

### 7. HarfangLab (`harfanglab-1.0.md`, 1.1 → 1.2)

#### 7.1 `yara.signature`

`HarfangLabYara` takes **either** form:

| Form | Keys | Deploy |
|------|------|--------|
| Signature (new, preferred) | `signature` ([`YaraSignature`](#51-yarasignature)), plus the YaraFile settings below | `content` is `signature`, verbatim |
| Decomposed (existing) | `meta`, `strings` (now optional), `condition`, `imports` | `content` is the one rule assembled as today. Without `strings`, the `strings:` section is omitted. |

New HarfangLab constraints (errors):

| Code | Constraint |
|------|------------|
| `harfanglab_rule_kind` | `sigma` and `yara` are both set. A block is one Sigma rule or one YARA file. |
| `harfanglab_yara_form` | `signature` is set together with any of `meta`, `strings`, `condition`, `imports`. |
| `harfanglab_yara_section_header` | Decomposed form: `strings` or `condition` already contains a `strings:`, `condition:`, or `rule` header. Deploy adds the header, so the rule would have two. |
| `harfanglab_yara_import` | Decomposed form: an `imports` entry is not a YARA module. |

The decomposed rule name is fixed so it always compiles. Today a Tide name that lowercases to a keyword (`Condition` → `rule condition {`) or keeps a non-ASCII letter (Python's `isalnum()` is Unicode-aware) produces a rule libyara refuses. Deploy now:

- keeps ASCII letters, digits, and `_` only;
- prefixes `rule_` when the name starts with a digit or is a YARA keyword;
- cuts the name at 128 characters.

An empty `strings` omits the `strings:` header, which today is emitted and refused.

The decomposed form stays valid and is not deprecated by this RFC. Its `file` → `file.pe`/`file.elf`/`file.macho` rewrite is kept as specified (see [Unresolved questions](#unresolved-questions)). The `signature` form does no rewriting: the author writes `context` in each rule's meta, and the [HarfangLab profile](#54-platform-profiles) checks it.

The language server checks both forms. A decomposed block is analysed as the rule deploy assembles, with each diagnostic mapped back to `strings` or `condition`.

#### 7.2 YaraFile settings

| Field | Type | Default | YaraFile field |
|-------|------|---------|----------------|
| `file_name` | string | the rule `name` slug + `.yar` | `name`; also the YARA namespace alerts show |

`maturity` and `action` keep their meaning. `maturity` maps to `hl_status` (confirmed). `action` maps to `global_state`, which is sent on a YaraFile only once the [verification gate](#pre-acceptance-verification) confirms the field, and so are `rule_confidence_override` and `rule_level_override`. `overwrite` is no longer sent.

#### 7.3 Identity and deploy

HarfangLab YARA becomes **state-backed**: the YaraFile id is recorded under `platforms.harfanglab.<tenant>` and stored verbatim (non-empty, no surrounding whitespace, as CrowdStrike's). Sigma is unchanged and stays addressed by `metadata.uuid`. A block is one kind ([§7.4](#74-one-kind-per-block)), so a HarfangLab binding is always a YaraFile.

| Block status strategy | Binding | HarfangLab calls |
|-----------------------|---------|------------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/data/threat_intelligence/YaraFile/` with `source_id`, `name`, `content`, `enabled: true`, `hl_status`; record `status[0].id` |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `PATCH …/YaraFile/{id}/` with the same fields |
| `DISABLEMENT` | present | `PATCH …/YaraFile/{id}/` with `enabled: false` |
| `DELETION` | present | `DELETE …/YaraFile/{id}/`, then the binding is removed |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no call |

- **Compile status.** Deploy MUST read the `status` list of a `POST` or `PATCH` answer. An empty list, or an entry with `status: false`, fails the rule with `harfanglab_yara_rejected`, quoting `code` and `content`. HTTP 200 alone is not success.
- **Missing file.** A `404` on `PATCH` recreates the file, with a `harfanglab_yara_recreated` warning (`DISABLEMENT`: forget, with `harfanglab_yara_missing`). A `404` on `DELETE` succeeds.

#### 7.4 One kind per block

A HarfangLab block carries **either** `sigma` (a detection) **or** `yara`, as a Bitdefender block carries exactly one of `detection` and `yara`. Both together fail static validation with `harfanglab_rule_kind`. The rule "when both are present, deploy MUST publish `sigma` and MUST NOT publish `yara`" is removed, because both can no longer be present. A block with neither still validates, and deploy still fails it, as today.

A detection and a YARA file for the same threat are two opentide rules, each with its own `metadata.uuid`, review, status, and deployment history.

The tenant `type` stays a filter, now compared case-insensitively: a `sigma` block deploys only to `Sigma` tenants, and a `yara` block only to `YARA` tenants.

An existing block with both keys fails `opentide validate` after the upgrade, and its author splits it into two rules. Today only the Sigma half ever reached a tenant. Keeping the `sigma` in the original rule (same uuid) leaves every tenant unchanged. The YARA half becomes a new rule and deploys for the first time.

#### 7.5 What does not change

- Sigma deploy, identity, and fields; the Sigma dialect questions in specifications#68.
- Every existing decomposed `yara` block validates as before, with two exceptions:
  - a block that also has `sigma` ([§7.4](#74-one-kind-per-block));
  - a block whose YARA does not compile. Today it reaches the tenant and fails silently there; now `opentide validate` reports it.

#### 7.6 Migration

Existing HarfangLab YARA rules have no binding. The first deploy after the upgrade would create a second YaraFile beside the one opentide created before. `opentide deploy migrate-state --adopt harfanglab` binds them once, explicitly:

1. Per YARA tenant, it lists YaraFiles of the tenant's `source_id` and matches each enabled `harfanglab.yara` rule by `name__exact` against the rule `name`, as the old deployer named files.
2. One match is bound. No match is reported as `harfanglab_adopt_none` (the next deploy creates the file). Several matches are reported as `harfanglab_adopt_ambiguous` and left unbound.
3. It writes shards only, and prints every decision.

This is the one place that matches remote objects by name. It is an operator-run migration, never part of deploy, the same exception [RFC 0010](0010-deployment-external-ids.md) made for `migrate-state`. Deploy refuses to create a HarfangLab YARA file on a tenant whose YARA rules were never adopted, until `--adopt harfanglab` has run once or `--no-adopt` is passed (`harfanglab_adoption_pending`).

### 8. Spec changes on acceptance

On acceptance, the same PR adds or changes:

1. `specs/languages/yara-1.0.md`: [§5](#5-the-yara-language-specslanguagesyara-10md) as normative text, in the fixed section order (Summary, Requirements, Definition, Relationships, Defaults & overrides, Examples, History).
2. `specs/platforms/bitdefender-1.0.md`: [§6](#6-bitdefender-block-platformbitdefender10).
3. `specs/platforms/harfanglab-1.0.md` 1.2: [§7](#7-harfanglab-harfanglab-10md-11--12). This includes correcting the claim that YARA is deleted by `metadata.uuid`, and replacing "deploy MUST publish `sigma`" with `harfanglab_rule_kind`.
4. `specs/platforms/index.md` 1.5:
   - ten platforms;
   - capability row `bitdefender | Bitdefender GravityZone | yes* | no‡ | GravityZone criteria or YARA`;
   - static-validation bar `bitdefender | status, exactly one of detection, yara`, and `harfanglab | at most one of sigma, yara`;
   - external-ids rows: `bitdefender` (shard) and `harfanglab` (Sigma by `metadata.uuid`, YARA by shard).
5. `specs/deployment-state.md` 1.4:
   - state-backed platforms table;
   - the Bitdefender id pattern;
   - `harfanglab` YaraFile ids;
   - "Deploying a rule to HarfangLab MUST NOT create a shard" becomes "… with a Sigma block only".
6. `specs/validation.md` 1.6: advisories `bitdefender_registry_full_hive`, `bitdefender_contains_no_wildcard`, `bitdefender_severity_collapsed`, `harfanglab_yara_context`, and the shared YARA warnings.
7. `specs/objects/rule-1.0.md`, `rule-1.1.md`: `configurations.bitdefender` row and history.
8. `SPECS.md` (three rows, one new), `CHANGELOG.md` (one section per spec), `rfcs/README.md` (status `accepted`), `llms.txt`.
9. `scripts/`: `test_platform_bitdefender.py` and `test_language_yara.py`, which prove the fixtures below. `scripts/validate.py` lists the new fixtures.

### 9. Fixtures

| Path | Proves |
|------|--------|
| `fixtures/platforms/bitdefender.yaml` | Minimal block per kind |
| `fixtures/valid/rule-bitdefender-detection-1.0.yaml` | Process rule, `any`/`is`/`contains`, actions, endpoint-tag targets |
| `fixtures/valid/rule-bitdefender-yara-1.0.yaml` | Several YARA rules in one `signature`, a private helper rule, `pe` import, `on_access: false` |
| `fixtures/platforms/bitdefender/*.api.json` | The JSON-RPC bodies deploy sends for each valid fixture (create, update, disable) |
| `fixtures/platforms/harfanglab-yara-signature.yaml` | `harfanglab.yara.signature` |
| `fixtures/platforms/harfanglab/*.api.json` | YaraFile `POST` and `PATCH` bodies |
| `fixtures/invalid/rule-bitdefender-two-kinds.yaml` | `bitdefender_rule_kind` |
| `fixtures/invalid/rule-bitdefender-criterion-field.yaml` | `bitdefender_criterion_field` (`Process.Hash` on `process`) |
| `fixtures/invalid/rule-bitdefender-exclusion.yaml` | An `exclusion` key: unknown key, `bitdefender_rule_kind` |
| `fixtures/invalid/rule-bitdefender-kill-on-yara.yaml` | `bitdefender_action_scope` |
| `fixtures/invalid/rule-bitdefender-yara-include.yaml` | `yara_include` |
| `fixtures/invalid/rule-harfanglab-yara-both-forms.yaml` | `harfanglab_yara_form` |
| `fixtures/invalid/rule-harfanglab-sigma-and-yara.yaml` | `harfanglab_rule_kind` |
| `fixtures/invalid/rule-yara-signature-alias.yaml` | `yara_signature_alias` |
| `fixtures/deployment/valid/<uuid>.json` | A shard with a `bitdefender` and a `harfanglab` binding |
| `fixtures/deployment/invalid/bitdefender-bad-id.json` | A Bitdefender id that is not 24 hex |

### 10. Analysis engine (language-server)

The plan widens [language-server#165](https://github.com/opentidehq/language-server/issues/165) from decomposed HarfangLab fragments to whole YARA signatures and adds Bitdefender. It follows the Falco addition (RFC 0014 §6) and its proven shape.

**Parser choice.** Two parsers, each with one job, as Falco has with tree-sitter and the libsinsp port:

- **The verdict parser is VirusTotal's `yara-x-parser`** (1.23, BSD-3-Clause, already allowed by `about.toml`). It is a pure-Rust PEG parser (logos + rowan) with a lossless CST, byte spans, and recovery after errors. Its dependencies are pure Rust. A probe built it in 17 s into a 1.5 MB binary, and it reported every syntax error of a broken rule.
- **A small tree-sitter grammar** (`grammars/tree-sitter-opentide-yara`, about 450 lines of `grammar.js`) for highlighting and the corpus gate. An agreement test runs it against `yara-x-parser`.
- The existing third-party `tree-sitter-yara` is not usable. Its licence headers disagree, and its hex support is incomplete.

The **full `yara-x` compiler stays out of the shipped engine**, and runs only as an oracle:

- It pulls in wasmtime: 298 crates and a 10 MB binary.
- It needs JavaScript bindings on wasm targets, which breaks the WASI build.
- It reports only the first error.
- Its current release does not resolve cleanly from a fresh `Cargo.lock`.

| Work package | Content |
|--------------|---------|
| **Toolchain spike** | Every recent `yara-x-*` crate needs Rust 1.95. Bump `rust-toolchain.toml` and opentide's `analysis/Cargo.toml` from 1.85, and prove `yara-x-parser` and `yara-x-fmt` build for native, `wasm32-unknown-unknown`, and `wasm32-wasip1`, and pass cargo-about. |
| **Grammar** | `grammars/tree-sitter-opentide-yara`: rules, modifiers, tags, meta, text/hex/regexp strings and modifiers, the full condition language. `testdata/corpus/yara/`, the corpus gate, and a tree-sitter ↔ `yara-x-parser` agreement test. |
| **Crate** | `crates/opentide-yara` (I/O-free, an estimated 4–6k lines): `yara-x-parser` CST → symbol table (rules, strings, tags, imports) → a semantic pass for every [§5.3](#53-diagnostics) code under a `Dialect { Libyara4, YaraX }`. It includes hex-string and regexp checks with libyara's rules, YARA's types and function overloads, and modifier combinations. |
| **Module catalogue** | `catalogs/yara/modules.toml`: fields, functions, overloads, constants, and types of the 13 modules (`pe` alone has about 145 fields and 34 functions). It is generated by a small Rust tool outside the workspace that walks YARA-X's `mods::module_definition()` reflection, and is marked per dialect from libyara's module sources. Also `language.toml` (keywords, modifiers and their legal combinations, built-ins) and a BSD-3 `NOTICE`. It feeds hover, completion, signature help, and `yara_unknown_module_member`. |
| **Bitdefender catalogue** | `catalogs/bitdefender/criteria.toml` from the criteria page (`scripts/sync_bitdefender_criteria.py`). `crates/opentide-tide/src/bitdefender.rs` holds the `bitdefender_*` constraint codes, so editors and `opentide validate` agree (as `sysdig.rs` does). Completion and hover for `target`, `field`, and enum values. |
| **Injection** | `LanguageId::Yara` (`yara`, `.yar`, `.yara`). New paths: `configurations.bitdefender.yara.signature`, `configurations.harfanglab.yara.signature` (an alias there is `yara_signature_alias`, not analysed), and a two-scalar injection for decomposed `harfanglab.yara.strings` + `.condition` with `imports` (one synthetic rule, offsets mapped back to each scalar). Platform profile chosen by the path. |
| **Editor features** | Semantic highlighting (`highlights/queries/yara/highlights.scm` through HighlightSpec, no new capture). Hover on modules, members, keywords, modifiers, and `$` ids (showing the definition). Completion: modules after `import "` and in `yara.imports`, members after `pe.`, ids after `$ # @ !`, modifiers, and meta keys from the profile. Signature help for module overloads. Document symbols and folding per rule. These are **new LSP capabilities**: today definition, references, and folding exist for Tide YAML only, and there is no rename or formatting. Go-to-definition and find-references for strings and rules, rename of string ids (across the two YAML scalars of a decomposed block), and formatting of `.yar`/`.yara` files with `yara-x-fmt`. |
| **Upstream conformance** | `scripts/sync_yarax_conformance.py` vendors YARA-X's own suites (BSD-3) into `testdata/conformance/yara-x/`: about 167 compiler error cases, 55 warning cases, 71 parser cases, and 586 `rule_true!`/`rule_false!` cases. libyara's `tests/test-rules.c` (BSD-3) covers the libyara dialect. |
| **Oracle** | `scripts/oracles/yara/oracle.py` compiles every case with `yara-python` 4.5.4 (libyara) and the `yara-x` wheel, records a verdict per dialect, and keeps the differences in `[[yara]]` entries of `testdata/oracles/exceptions.toml`, with a job in `oracle.yml`. The engine's error set MUST equal libyara's verdicts, and `yara_x_incompatible` MUST equal the cases where only YARA-X refuses. Neither package ships or becomes a Cargo dependency. `license-scan.sh` gets a narrow pattern (`yara_python`, `libyara`), because `yara-x-parser` itself ships. |
| **External corpus** | `testdata/conformance/external/yara/`, pinned, each file with a `.broken.` twin: ReversingLabs and InQuest rules (MIT), a Neo23x0/signature-base subset (DRL-1.1, already used for SigmaHQ conversions; THOR/LOKI external variables declared or excluded), and HarfangLab/iocs if its licence allows. Yara-Rules/rules (GPL-2.0) and Elastic `protections-artifacts` (ELv2) are fetched in CI at a pinned commit and never vendored. |
| **Fuzzing** | `fuzz/fuzz_targets/yara.rs`, the `fuzz.yml` matrix, and regressions in `fuzz_regressions.rs` |
| **Packaging** | Helix, Neovim, Zed, `packages/lsp-client`, the wasm smoke test, and a follow-up in the VS Code repository. The `.yar` association can clash with VirusTotal's YARA-X extension, so opentide claims `.yar` only inside a Tide workspace. |
| **Docs** | `docs/YARA.md`: each diagnostic code mapped to the libyara source and its test, as `docs/FALCO.md` does. Plus sections in `LANGUAGE.md` and `ARCHITECTURE.md` (injection table) and the `add-language` skill. |

opentide then:

- bumps `analysis/Cargo.toml` to the release;
- sets `OFFLINE_QUERY_LANGUAGES["bitdefender"] = ("yara",)` and `["harfanglab"] = ("yara",)`;
- adds `.yar`/`.yara` to `QUERY_FILE_SUFFIXES`;
- adds the advisory codes to `analysis.py`, `lint.py`, and `explain.py`;
- sets `_DEFAULT_QUERY_LANGUAGE` in the MCP tools.

### 11. Engineering plan

Sizing uses the Sysdig addition as the baseline: about 2,700 lines of Python in opentide (1,250 in the package, 1,400 in tests), about 25 registrations in about 20 files, about 17 doc edits, and 5,600 lines of Rust plus a grammar and catalogues in the language server.

| # | Work package | Repo | Estimate (person-days) | Depends on |
|---|--------------|------|------------------------|------------|
| S1 | Land the accepted RFC: two new specs, five spec edits, fixtures, fixture checker tests | specifications | 3–4 | acceptance |
| L0 | Toolchain spike: Rust 1.95, `yara-x-parser`/`-fmt` on native + both wasm targets, cargo-about | language-server | 2 | — (can start now) |
| L1 | Plumbing: `LanguageId::Yara`, codes, ~25 `match` sites, fuzz target | language-server | 2 | L0 |
| L2 | Tree-sitter grammar (~450 lines), corpus, `highlights.scm`, tmLanguage, agreement test | language-server | 5–7 | L1 |
| L3 | `opentide-yara` engine: semantic pass, every §5.3 code, both dialects, profiles | language-server | 15–20 | L1 |
| L4 | Module catalogue generator, `modules.toml`, `language.toml`, NOTICE | language-server | 4–5 | L0 |
| L5 | Editor features: hover, completion, signature help, symbols, folding, definition, references, rename, formatting (new LSP capabilities, stdio e2e tests) | language-server | 8–10 | L3, L4 |
| L6 | Tide injection: `yara.signature` paths, composed two-scalar HarfangLab injection with segment map, `harfanglab_*` codes | language-server | 5–7 | L3, S1 |
| L7 | Upstream conformance (~880 YARA-X cases), external corpus with twins, oracle with both engines | language-server | 9–12 | L3 |
| L8 | Bitdefender criteria catalogue, sync script, `bitdefender.rs` constraint codes, completion and hover | language-server | 4–5 | S1 |
| L9 | Packaging, `docs/YARA.md`, release 0.13.0 | language-server | 4–5 | L2, L5–L8 |
| O1 | `bitdefender` models (block, kinds, criterion, actions, targets) and tenant setup models | opentide | 2–3 | S1 |
| O2 | JSON-RPC client on `TenantSession`: envelope, error mapping, auth modes, create/delete rate limiter, `Retry-After` | opentide | 2–3 | — |
| O3 | Compiler: derived fields, normalisation, settings by kind, full actions, targets resolution; `api_body` golden tests against fixtures | opentide | 2–3 | O1 |
| O4 | Deployer: deployment-state shard (24-hex), create/update/disable/delete, recreate, name conflict, unconfirmed create | opentide | 3 | O2, O3 |
| O5 | Wiring (~25 registrations), bundled TOML, template, diagnostics pages, docs, MCP | opentide | 2–3 | O1 |
| O6 | Tests: model, compile, deployer (fake JSON-RPC server), setup, e2e | opentide | 4–5 | O1–O4 |
| H1 | HarfangLab: `yara.signature`, optional `strings`, YaraFile state backing, PATCH/DELETE by id, `enabled`, `status[]` parsing, one kind per block (`harfanglab_rule_kind`) | opentide | 4–5 | S1 |
| H2 | `migrate-state --adopt harfanglab`, `harfanglab_adoption_pending` | opentide | 2 | H1 |
| H3 | HarfangLab YARA tests (none exist today): golden content, payloads, state, adoption | opentide | 2–3 | H1, H2 |
| E1 | Engine bump (with Rust 1.95) and YARA wiring in `validate`, `lint`, `explain`, MCP | opentide | 1–2 | L6, L8, L9 |
| V1 | Live verification on a GravityZone cloud tenant and a HarfangLab console ([gate](#pre-acceptance-verification)) | — | 2 | tenant access |

**Total:** about 87–113 person-days: language server 58–75, opentide 24–32, specifications 3–4, live verification 2.

The critical path is L0 → L1 → L3 → L7 → L9 → E1: 33–43 days, about 7–9 weeks, with the engine's work packages staffed in parallel where their dependencies allow. The opentide Bitdefender deployer (O1–O6) and the HarfangLab rework (H1–H3) run in parallel with it, and can ship first. Until E1 lands, Bitdefender YARA blocks validate structurally only.

Milestones:

| Milestone | Content |
|-----------|---------|
| M1 | Spec landed; Bitdefender `detection` deploy; HarfangLab identity, `DISABLEMENT`, and compile-status fixes |
| M2 | Bitdefender `yara` deploy; `harfanglab.yara.signature`; adoption |
| M3 | Engine 0.13: YARA syntax and semantic checks, injection, Bitdefender criteria checks, in `opentide validate` and editors |
| M4 | Oracle and conformance green, rename and formatting |

## Drawbacks

- **Rate limits make the first deploy slow.** At 5 creates per minute per key, a 300-rule catalogue takes about an hour to create the first time. Updates are not limited that way. CI jobs need a timeout to match, or several API keys.
- **On-premises GravityZone is not covered.** It has no Incidents API. Its customers keep custom rules in the console.
- **YARA rules per company are capped at 50.** A large YARA catalogue has to pack several rules into one block's `signature`.
- **The HarfangLab rework is a behaviour change for existing users.** YaraFile ids join deployment state, an adoption step runs once, and a block with both `sigma` and `yara` must be split into two rules.
- **Neither vendor names its YARA engine.** The libyara 4.5 contract is the most plausible choice. A vendor on YARA-X would reject some rules the engine accepts, though each such rule carries a `yara_x_incompatible` warning.
- **The criteria catalogue is copied from a web page.** When Bitdefender adds fields, the sync script has to run, and until then a new field is an error.
- **The engine follows YARA-X's release train.** The `yara-x-*` crates need Rust 1.95 today and raise their minimum about every two months, which moves the language server's and opentide's toolchain with them. Two parsers (tree-sitter and `yara-x-parser`) can disagree, and the agreement test has to keep them aligned.

## Alternatives

- **YARA at the rule root** (`detection.yara`, shared by every platform). Rejected for now. It hides what each platform deploys behind a shared field. It also needs `rule::1.2`, while the rule document shape is being rethought in [RFC 0012](0012-rule-document-shape.md) and [specifications#24](https://github.com/opentidehq/specifications/issues/24). The `YaraSignature` object moves there unchanged if that redesign wants it.
- **YAML anchors to share one text between blocks** (`signature: &yara |` … `signature: *yara`). Rejected. Someone reading the second block would not see the YARA it deploys. Every block carries its text literally, and an alias fails with `yara_signature_alias`.
- **Sigma and YARA in one HarfangLab block, each deployed to its tenant type.** Proposed in an earlier draft of this RFC and rejected. A block is one detection or one YARA file, as on Bitdefender. Two kinds under one uuid would share one status and one deployment history, and could not be disabled separately.
- **Decomposed YARA for Bitdefender, like HarfangLab's.** Rejected. It cannot express several rules, private helpers, or condition-only rules, and both vendors accept a whole YARA text.
- **Deploy-time meta injection** (opentide writes `id`, `score`, `context` into the signature). Rejected. It needs a YARA rewriter in the deploy path and breaks "what was reviewed is what is deployed". Bitdefender stores the text as sent and shows it in the console.
- **Bitdefender identity by name or by the `opentide:<uuid>` tag.** Rejected. [Deployment state](../specs/deployment-state.md) forbids rediscovery by listing, and `getCustomRulesList` has no filter, so every deploy would page through every rule.
- **GravityZone exclusion rules** (`type: 2`), as a third kind or as tunings inside a detection block. Rejected. An exclusion suppresses incidents and detects nothing, so it is not a detection rule and has no objective, threat, or ATT&CK mapping to carry. A tuning would also need a second remote id per tenant, which a shard binding cannot hold. Exclusions stay in the GravityZone console, where they are managed today. Deploy never creates, updates, or deletes one.
- **Advanced rules (`subtype: 2`, `advancedQuery`).** Deferred. They appear only on unlisted pages. When Bitdefender publishes them, a fourth kind (`advanced`) is an additive change.
- **The full YARA-X compiler in-process** (`yara_x::Compiler` as the checker). Rejected:
  - It would make YARA-X the contract.
  - It reports one error per compile.
  - It brings wasmtime and breaks the WASI build.
  - #165 keeps oracle engines out of `Cargo.lock`.

  Only its parser and formatter ship. The compiler is the oracle's second opinion. A later opt-in `yara-compiler` feature for native and Python builds stays possible.
- **The third-party `tree-sitter-yara` grammar.** Rejected: its licence headers disagree, and it cannot express nibble wildcards or multi-byte alternatives.

## Unresolved questions

### Pre-acceptance verification

These need a live GravityZone cloud tenant and a HarfangLab console (V1). Answers change spec text, not shape:

1. **GravityZone `updateCustomRule`.** Does a full `settings` replace the stored one, including `automaticActions`? What does an update with a different `type` return?
2. **GravityZone errors.** What error does `createCustomRule` return for a duplicate name? Is name uniqueness per type, so that a console exclusion can block a detection rule's name?
3. **GravityZone YARA.** Do `import "pe"` and the other confirmed modules compile? Is the engine libyara (check a YARA-X-only incompatibility)?
4. **HarfangLab YaraFile fields.** Does a YaraFile accept `global_state`, `rule_confidence_override`, and `rule_level_override` (`/api/schema` on a console)? Does `PATCH` accept `content`?
5. **HarfangLab `context` values.** Are `file.pe`, `file.elf`, `file.macho`, `process`, and `thread` valid, or only `file` and `memory`? The decomposed-form rewrite is kept or dropped on this answer.
6. **HarfangLab Sigma identity.** Does it honour the Sigma `id`? Out of scope here, but the same check covers it, and it is filed against specifications#68.

### Open design points

- Should endpoint tag aliases resolve through the Network API (`getEndpointTags`) by tag name, instead of a tenant table of ids?
- Whether `startYaraScan` belongs in opentide as a hunt (`response.procedure`) or an `opentide scan` command. It is not a detection and is out of scope here.
- A validate-time quota check for the 50-YARA-rule cap per company, which needs to know which blocks reach which tenant.
- Whether to version the per-platform confirmed module sets in the language spec, or in the platform specs.

## References

- [opentidehq/specifications#68](https://github.com/opentidehq/specifications/issues/68): HarfangLab Sigma and YARA dialects (this RFC answers the YARA half)
- [opentidehq/language-server#165](https://github.com/opentidehq/language-server/issues/165): YARA engine, module catalogue, yara-x oracle
- [RFC 0010](0010-deployment-external-ids.md): deployment external ids; [RFC 0014](0014-sysdig-falco-platform.md): the Falco language, the engine pattern this follows
- Bitdefender GravityZone Public API pages listed in [§3.1](#31-bitdefender-gravityzone-public-api); [n8n-nodes-gravityzone](https://github.com/bitdefender/n8n-nodes-gravityzone); [connector-bitdefender](https://github.com/fortinet-fortisoar/connector-bitdefender)
- HarfangLab: [HarfangLab/iocs](https://github.com/HarfangLab/iocs); OpenCTI HarfangLab connectors; [demisto/content HarfangLabEDR](https://github.com/demisto/content/tree/master/Packs/HarfangLabEDR); [YARA signatures engine](https://harfanglab.io/edr/signatures-engine-yara/)
- YARA: [libyara 4.5](https://github.com/VirusTotal/yara) (`libyara/grammar.y`, `lexer.l`); [YARA-X](https://github.com/VirusTotal/yara-x) and [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)
