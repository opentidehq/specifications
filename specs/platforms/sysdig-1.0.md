---
spec: platform-sysdig
version: "1.0"
schema_id: platform::sysdig::1.0
status: normative
supersedes: null
---

# Sysdig Secure (`platform::sysdig::1.0`)

## Summary

`configurations.sysdig` is a Falco rule. Sysdig Secure's runtime threat detection runs Falco, so one block serves two deliveries, chosen per tenant:

- **`api`**: the rule is created in Sysdig Secure as a custom Falco rule (`/api/secure/rules`) and added to Sysdig runtime policies by name (`/api/v2/policies`).
- **`file`**: the rule is written as a Falco rules file, one file per rule, into a directory that Falco (open source) or a GitOps pipeline loads.

The detection text is a Falco **condition** ([Falco language](#falco-language)). The author writes the condition, its exceptions, and the macros and lists only this rule uses. Deploy derives the Falco `rule` name, `desc`, `priority`, MITRE `tags`, and a default `output` from the opentide rule, so those are not retyped.

A block either defines a new Falco rule (`condition`) or tunes an existing one (`append_to_rule`): a Falco default rule, or a rule Sysdig manages.

Sysdig assigns every rule an integer id at create time. For `api` tenants that id is kept in deployment state ([deployment-state.md](../deployment-state.md)); a `file` tenant needs no id, because the file is named by `metadata.uuid`.

Shared fields are defined in [platforms](index.md#shared-platform-block). The design and its alternatives are in [RFC 0014](../../rfcs/0014-sysdig-falco-platform.md).

## Requirements

Static validation (`opentide validate`) and registry load:

- A block MUST set exactly one of a **new rule** or a **tuning**: without `append_to_rule`, `condition` is required and MUST be a non-blank string; with `append_to_rule`, at least one of `condition` and `exceptions` MUST be present.
- A block MUST satisfy every [constraint](#constraints). A violation MUST be reported with its constraint code.
- Unknown keys MUST fail, at the block root and inside every object in the field tables.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) at the block root MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)). Registry load drops those keys and passes every other key to the model.
- Field names in `condition`, `macros[].condition`, `output`, and `exceptions[].fields` name Falco fields. Static validation MUST NOT reject a rule for a field it does not know: plugins add fields, and the set depends on the Falco or Sysdig agent version. The analysis engine reports an unknown field as a warning ([Falco language](#falco-language)).
- `condition` and `macros[].condition` SHOULD be checked offline by the analysis engine, as the KQL, SPL, and Lucene blocks are. A Falco syntax error is an error.

Deploy:

- Deploy MUST expand the block's own `macros` and `lists` into the condition before it sends or writes the rule ([Expansion](#expansion)). It MUST NOT create, update, or delete a Falco macro or list on a tenant, and MUST NOT write a `- macro:` or `- list:` item to a rules file.
- `api` requests MUST carry `Authorization: Bearer <api_token>`. Deploy MUST NOT call the Sysdig Public (Next-Gen) API for rules: it has no custom Falco rule or policy write.
- An `api` tenant is state-backed. Deploy MUST follow the [deploy decisions](../deployment-state.md#deploy-decisions) of deployment state, storing the Sysdig rule id under `platforms.sysdig.<tenant>`. Deploy MUST NOT find a rule by listing remote rules or matching names.
- A `file` tenant MUST NOT create a deployment-state shard.
- Deploy MUST NOT create or delete a Sysdig policy. A named policy that does not exist fails the rule with `sysdig_policy_missing`.
- Deploy MUST NOT remove a rule from a policy the block or the tenant does not name.
- Deploy MUST NOT write to the rule file.

Query validation:

- `opentide validate query --platform sysdig` MUST report `supported: false`. Sysdig Secure has no dry-run or preview for a rule, and Falco OSS has no API. The offline engine check is part of `opentide validate` ([Query validation](#query-validation)).

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `condition` | string | conditional | — | Falco condition. Required for a new rule. With `append_to_rule`, the text appended to the tuned rule's condition, usually starting with `and not`. Multiline in YAML; deploy joins lines with single spaces. |
| `append_to_rule` | string | optional | null | Name of an existing Falco or Sysdig rule this block tunes. Turns the block into a [tuning](#tuning-an-existing-rule). |
| `source` | string | optional | `syscall` | Falco event source: `syscall`, `k8s_audit`, `aws_cloudtrail`, `gcp_auditlog`, `azure_platformlogs`, `okta`, `github`, or the source name of another plugin. Matches `^[a-z][a-z0-9_]*$`. |
| `output` | string | optional | [derived](#output) | Falco output template, with `%field` references. |
| `priority` | string | optional | [derived](#priority) | Falco priority: `EMERGENCY`, `ALERT`, `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`, `INFORMATIONAL`, or `DEBUG`. Compared case-insensitively; `INFO` is accepted for `INFORMATIONAL`. |
| `tags` | list[string] | optional | null | Extra Falco tags. Deploy adds the [derived tags](#tags). |
| `exceptions` | list[SysdigException] | optional | null | Falco exceptions ([`exceptions[]`](#exceptions-sysdigexception)). |
| `macros` | list[SysdigMacro] | optional | null | Macros only this rule uses, expanded at deploy ([`macros[]`](#macros-sysdigmacro)). |
| `lists` | list[SysdigList] | optional | null | Lists only this rule uses, expanded at deploy ([`lists[]`](#lists-sysdiglist)). |
| `policies` | list[string] | optional | tenant `policies` | Names of Sysdig runtime policies the rule joins. `api` delivery only; a `file` tenant ignores it. |
| `required_engine_version` | string | optional | null | Falco engine version the rule needs (`0.39.0`). `file` delivery writes it as a `- required_engine_version:` item. |
| `required_plugin_versions` | list[SysdigPluginVersion] | optional | null | Plugins the rule needs. `file` delivery writes them as a `- required_plugin_versions:` item. A block with a `source` other than `syscall` SHOULD set it for `file` tenants. |

The shared `name` is the Falco rule name. Empty means the opentide rule `name`. It is ignored with `append_to_rule`, which names the rule instead.

### `exceptions[]` (SysdigException)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Exception name, unique in the block. |
| `fields` | string or list[string] | yes | — | One Falco field (the single-field form) or a list of fields (the tuple form). |
| `comps` | string or list[string] | optional | see below | Comparison operators. Tuple form: a list aligned with `fields`; default `=` for each field. Single-field form: one of `in`, `pmatch`, or `intersects`; default `in`. |
| `values` | list | optional | `[]` | Tuple form: a list of rows, each a list aligned with `fields`. Where the aligned comparison is `in`, `pmatch`, or `intersects`, the item is a list. Single-field form: a flat list of values. |

Allowed comparison operators: `=`, `!=`, `<`, `<=`, `>`, `>=`, `contains`, `icontains`, `bcontains`, `startswith`, `bstartswith`, `endswith`, `glob`, `iglob`, `in`, `intersects`, `pmatch`, and `regex`.

Values are sent and written as the block gives them. Deploy does not expand lists inside `values`.

### `macros[]` (SysdigMacro)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Macro name, matching `^[A-Za-z_][A-Za-z0-9_]*$`. |
| `condition` | string | yes | — | Falco condition. It may reference other macros and lists of this block. |

### `lists[]` (SysdigList)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | List name, matching `^[A-Za-z_][A-Za-z0-9_]*$`. |
| `items` | list[string or number] | yes | — | List items. An item may name another list of this block. |

### `required_plugin_versions[]` (SysdigPluginVersion)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Plugin name (`k8saudit`, `cloudtrail`). |
| `version` | string | yes | — | Minimum plugin version, semver. |

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `sysdig_rule_shape` | Without `append_to_rule`, `condition` is a non-blank string. With `append_to_rule`, `append_to_rule` is a non-blank string and at least one of `condition` and `exceptions` is present and non-empty. |
| `sysdig_tuning_keys` | With `append_to_rule`, `output`, `priority`, `policies`, `source`, and `name` MUST NOT be set. A tuning inherits them from the tuned rule. |
| `sysdig_priority` | `priority` is one of the eight Falco priorities or `INFO`, compared case-insensitively. |
| `sysdig_source` | `source` matches `^[a-z][a-z0-9_]*$`. |
| `sysdig_exception_shape` | An exception has a non-empty `name`, unique in the block. Tuple form: `fields` is a non-empty list of distinct strings, `comps` (when set) is a list of the same length, every row of `values` is a list of the same length, and an item whose comparison is `in`, `pmatch`, or `intersects` is a list. Single-field form: `comps` (when set) is `in`, `pmatch`, or `intersects`, and `values` is a flat list. Every comparison is one of the [allowed operators](#exceptions-sysdigexception). |
| `sysdig_definition_name` | Every macro and list `name` matches `^[A-Za-z_][A-Za-z0-9_]*$` and is not a Falco operator or keyword (`and`, `or`, `not`, `in`, `exists`, `val`, and the operators). |
| `sysdig_definition_duplicate` | A name is defined at most once across the block's `macros` and `lists`. |
| `sysdig_definition_cycle` | Expanding the block's macros and lists terminates: no macro or list reaches itself through other block definitions. |

### Falco language

The condition is a Falco filter expression. The analysis engine ([language-server](https://github.com/opentidehq/language-server)) parses it with its Falco grammar and checks it offline:

- syntax: boolean operators `and`, `or`, `not`; comparisons with the [allowed operators](#exceptions-sysdigexception) plus `exists`; value lists `( … )`; quoted strings; field arguments (`proc.aname[2]`, `evt.arg.flags`, `fd.name`); and the transformers `tolower`, `toupper`, `b64`, `basename`, `len`, and `val()`. A syntax error is an error;
- fields: each field is known for the block's `source`. An unknown field is a warning, because plugins add fields;
- references: a bare name is a macro of the block, a list of the block inside a value list, or a macro or list of the Falco default rules (`falcosecurity/rules`, `falco_rules.yaml`). Any other name is a warning: on a Sysdig tenant it may be a macro Sysdig manages;
- the output template's `%field` references follow the same field check.

Editors get the same diagnostics, plus highlighting, hover, and completion, through the language server.

### Expansion

Before a rule is sent or written, deploy replaces every reference to the block's own macros and lists with its definition:

1. A bare name in the condition that is a block **macro** becomes the macro's condition, expanded, in parentheses: `(…)`.
2. A bare name inside a value list (the parenthesised list after `in`, `intersects`, or `pmatch`) that is a block **list** becomes the list's items, expanded, joined by `, `. An item is written as Falco reads it: an item containing a space, comma, parenthesis, or quote is double-quoted.
3. Expansion recurses through block definitions, and stops at names the block does not define. Those are left as written and resolve on the tenant.
4. Quoted strings, field names, and field arguments are never expanded.

Each rule therefore owns exactly one remote object. Falco macros and lists are global to a ruleset: two rules that defined the same name would overwrite each other on the tenant, so a block's definitions never leave it.

### Output

When `output` is omitted, deploy writes the rule name, then the fields for the `source`:

| `source` | Default output after the rule name |
|----------|------------------------------------|
| `syscall` | ` \| evt_type=%evt.type user=%user.name user_uid=%user.uid process=%proc.name proc_exepath=%proc.exepath parent=%proc.pname command=%proc.cmdline terminal=%proc.tty container_id=%container.id container_name=%container.name image=%container.image.repository` |
| `k8s_audit` | ` \| user=%ka.user.name verb=%ka.verb uri=%ka.uri resource=%ka.target.resource namespace=%ka.target.namespace name=%ka.target.name response=%ka.response.code` |
| `aws_cloudtrail` | ` \| user=%ct.user region=%ct.region event=%ct.name source_ip=%ct.srcip account=%ct.user.accountid` |
| any other | nothing: the output is the rule name |

Deploy joins the lines of an authored `output` with single spaces.

### Priority

When `priority` is omitted, it is derived from `response.alert_severity`:

| `response.alert_severity` | Falco priority | Sysdig API `priority` |
|---------------------------|----------------|-----------------------|
| `Critical` | `CRITICAL` | `critical` |
| `High` | `ERROR` | `error` |
| `Medium` | `WARNING` | `warning` |
| `Low` | `NOTICE` | `notice` |
| `Informational` | `INFORMATIONAL` | `info` |

When `response` is missing, deploy uses `WARNING`. An authored priority is sent to the API in lower case, with `INFORMATIONAL` as `info`.

### Tags

Deploy writes the union of, in this order and without duplicates:

1. The block `tags`.
2. Each ATT&CK technique id of the rule (`T1059.004`): the rule's `techniques` plus the techniques inherited through `detection_model`, the same union Elastic uses ([elastic-1.0](elastic-1.0.md#attck)). Then a `mitre_<tactic>` tag for each tactic of those techniques, from the tactic table of [elastic-1.0](elastic-1.0.md#attck), lower-cased with spaces and hyphens as underscores (`mitre_execution`, `mitre_privilege_escalation`). This is the Falco default rules' convention. A technique that is not Enterprise ATT&CK adds its id and no tactic.
3. A maturity tag from the block's status strategy: `maturity_stable` for `RELEASE`, `maturity_incubating` for `PREVIEW`, otherwise `maturity_sandbox`.
4. The tenant `tags`.

A tuning gets no derived tags: Falco does not append tags to an existing rule.

### Tenant setup

```toml
[platform]
enabled = true
identifier = "sysdig"
name = "Sysdig Secure"
subschema = "Sysdig Secure"
description = "Falco rules for Sysdig Secure runtime detection, or as Falco rules files."
flags = []

[[tenants]]
name = "sysdig-prod"
description = "Sysdig Secure SaaS, EU region"
deployment = "PRODUCTION"
[tenants.setup]
ssl = true
delivery = "api"
url = "https://eu1.app.sysdig.com"
api_token = "$SYSDIG_SECURE_API_TOKEN"
policies = ["opentide managed detections"]

[[tenants]]
name = "falco-gitops"
description = "Falco rules files picked up by the Helm chart"
deployment = "STAGING"
[tenants.setup]
ssl = true
delivery = "file"
rules_dir = "deploy/falco/rules.d"
```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `delivery` | string | no | `api` | `api` or `file`. |
| `url` | string | for `api` | — | Sysdig Secure base URL for the account's region: `https://secure.sysdig.com` (US East), `https://us2.app.sysdig.com`, `https://us4.app.sysdig.com`, `https://eu1.app.sysdig.com`, `https://app.au1.sysdig.com`, `https://app.me2.sysdig.com`, or an on-premises URL. |
| `api_token` | string | for `api` | — | Sysdig Secure API token. MUST be a `$ENV` reference. |
| `policies` | list[string] | no | `[]` | Policies every new rule joins when its block sets no `policies`. |
| `rules_dir` | string | for `file` | — | Directory that receives the rules files. A relative path resolves against the workspace root. |
| `tags` | list[string] | no | `[]` | Tags added to every rule deployed to this tenant. |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification). |

A tenant whose `delivery` is `api` without `url` or `api_token`, or `file` without `rules_dir`, fails configuration load.

### Deploy: `api`

A new rule is sent as:

```json
{
  "name": "<Falco rule name>",
  "description": "<opentide rule description, whitespace collapsed>",
  "tags": ["<derived tags>"],
  "details": {
    "ruleType": "FALCO",
    "append": false,
    "source": "syscall",
    "condition": {"condition": "<expanded condition>", "components": []},
    "output": "<output>",
    "priority": "warning",
    "exceptions": [{"name": "…", "fields": ["…"], "comps": ["…"], "values": [["…"]]}]
  }
}
```

A tuning is sent with `"name": "<append_to_rule>"`, `"append": true`, an empty `description` and `tags`, and only `condition` and `exceptions` in `details`. `exceptions` is omitted when the block has none.

| Block status strategy | Binding in deployment state | Sysdig result |
|-----------------------|-----------------------------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/secure/rules`; the returned `id` is recorded. Then the rule name is added to each named policy that lacks it. |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `GET /api/secure/rules/{id}` for its `version`, then `PUT /api/secure/rules/{id}` with that `version`. A renamed rule is renamed in each named policy. Then the rule name is added to each named policy that lacks it. |
| `DISABLEMENT` | present | The rule is updated as above, then removed from each named policy. Sysdig has no disabled flag on a rule: a rule in no policy does not alert. A tuning is deleted instead, and its binding removed. |
| `DELETION` | present | The rule is removed from each named policy, then `DELETE /api/secure/rules/{id}`, then the binding is removed. |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no request. |

A tuning never joins a policy: the tuned rule's policies apply.

A policy is found by name in `GET /api/v2/policies`. It is updated with `PUT /api/v2/policies/{id}`, sending the policy as read with the changed `ruleNames`. When the bound rule no longer exists (`404` on `GET`), deploy creates it again under the same rules as a create and replaces the binding, with a `sysdig_rule_recreated` warning.

### Deploy: `file`

Each rule is written to `<rules_dir>/<metadata.uuid>.yaml`, UTF-8, with LF line endings, replacing the file when it exists:

```yaml
# Generated by opentide from rule <metadata.uuid>. Do not edit: changes are overwritten.
- required_engine_version: 0.39.0
- required_plugin_versions:
    - name: k8saudit
      version: 0.7.0
- rule: <Falco rule name>
  desc: <description>
  condition: <expanded condition>
  output: <output>
  priority: <PRIORITY>
  source: <source>
  enabled: true
  tags: [<derived tags>]
  exceptions: [...]
```

The `required_*` items are written only when set. A tuning is written as:

```yaml
- rule: <append_to_rule>
  condition: <condition>
  exceptions: [...]
  override:
    condition: append
    exceptions: append
```

with `override` naming exactly the keys present. The `override` syntax needs Falco 0.36 or later.

| Block status strategy | File result |
|-----------------------|-------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | Written with `enabled: true`. |
| `DISABLEMENT` | Written with `enabled: false`. A tuning's file is deleted. |
| `DELETION` | The file is deleted. A missing file is not an error. |

Falco loads a rules directory in file-name order. Because every rule carries its own definitions ([Expansion](#expansion)), the order does not change any rule. A tuning's file still has to load after the file that defines the tuned rule: the Falco default rules load first when they are listed first in `rules_files`.

### Query validation

| Check | Sysdig |
|-------|--------|
| `opentide validate` (offline, analysis engine) | yes: the Falco condition, block macros, exceptions' fields, and `output` fields ([Falco language](#falco-language)) |
| `opentide validate query --live` | no (`supported: false`) |
| `opentide query` | no |

## Relationships

- [platforms](index.md) — shared fields, capability matrix, external ids
- [deployment-state.md](../deployment-state.md) — the Sysdig rule id of an `api` tenant
- [deployment.md](../deployment.md) — status strategies
- [rule-1.0.md](../objects/rule-1.0.md) — `response.alert_severity`, `detection_model`, `description`
- [validation.md](../validation.md) — static validation and query validation
- [RFC 0014](../../rfcs/0014-sysdig-falco-platform.md) — design, research, and alternatives

## Defaults & overrides

| Field | Default |
|-------|---------|
| Falco rule name | Shared `name`, else the opentide rule `name` |
| `desc` | opentide rule `description`, whitespace collapsed |
| `source` | `syscall` |
| `output` | [Output](#output) |
| `priority` | [Priority](#priority), else `WARNING` |
| `policies` | tenant `policies` |
| Tenant `delivery` | `api` |

## Examples

A new rule, converted from the Falco default rule *Terminal shell in container* (`falcosecurity/rules`, Apache-2.0). `spawned_process`, `container`, `shell_procs`, and `container_entrypoint` are default macros the tenant already has; `allowed_debug_images` is this rule's own list, expanded at deploy:

```yaml
configurations:
  sysdig:
    enabled: true
    schema: platform::sysdig::1.0
    status: STAGING
    condition: >
      spawned_process
      and container
      and shell_procs
      and proc.tty != 0
      and container_entrypoint
      and not container.image.repository in (allowed_debug_images)
    exceptions:
      - name: known_shell_parents
        fields: [proc.pname, container.image.repository]
        comps: ['=', startswith]
        values:
          - [kubectl, registry.example.com/ops/]
    lists:
      - name: allowed_debug_images
        items: [busybox, registry.example.com/ops/toolbox]
    tags: [container, shell]
```

A tuning of the same default rule:

```yaml
configurations:
  sysdig:
    enabled: true
    schema: platform::sysdig::1.0
    status: PRODUCTION
    append_to_rule: Terminal shell in container
    condition: and not proc.pname in (ci_runners)
    lists:
      - name: ci_runners
        items: [gitlab-runner, buildkite-agent]
```

Fixtures: [fixtures/platforms/sysdig.yaml](../../fixtures/platforms/sysdig.yaml), [fixtures/valid/rule-sysdig-1.0.yaml](../../fixtures/valid/rule-sysdig-1.0.yaml), [fixtures/valid/rule-sysdig-tuning-1.0.yaml](../../fixtures/valid/rule-sysdig-tuning-1.0.yaml), and the generated file [fixtures/platforms/sysdig/rule-sysdig-1.0.falco.yaml](../../fixtures/platforms/sysdig/rule-sysdig-1.0.falco.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-02 | Initial field contract ([RFC 0014](../../rfcs/0014-sysdig-falco-platform.md), [specifications#8](https://github.com/opentidehq/specifications/issues/8)). |
