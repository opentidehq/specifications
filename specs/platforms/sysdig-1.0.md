---
spec: platform-sysdig
version: "1.0"
schema_id: platform::sysdig::1.0
status: normative
supersedes: null
---

# Sysdig Secure (`platform::sysdig::1.0`)

## Summary

`configurations.sysdig` is a Falco rule for Sysdig Secure, whose runtime threat detection runs Falco. Deploy creates it through the Sysdig Secure API as a custom Falco rule (`/api/secure/rules`) and adds it to Sysdig runtime policies by name (`/api/v2/policies`), as every opentide platform deploys through its vendor's API.

The detection text is a Falco **condition** ([Falco language](#falco-language)). The author writes the condition, its exceptions, and the macros and lists only this rule uses. Deploy derives the Falco `rule` name, `desc`, `priority`, MITRE `tags`, and a default `output` from the opentide rule, so those are not retyped.

A block either defines a new Falco rule (`condition`) or tunes an existing one (`append_to_rule`): a Falco default rule, or a rule Sysdig manages.

Sysdig assigns every rule an integer id at create time. That id is kept in deployment state ([deployment-state.md](../deployment-state.md)).

Shared fields are defined in [platforms](index.md#shared-platform-block). The design and its alternatives are in [RFC 0014](../../rfcs/0014-sysdig-falco-platform.md).

## Requirements

Static validation (`opentide validate`) and registry load:

- `status` MUST be present, as on `elastic`: it picks the deploy strategy, and Falco has no default for it. A block that omits it fails as a missing required field; implementations MAY report the constraint codes only for blocks that set `status`.
- A block MUST set exactly one of a **new rule** or a **tuning**: without `append_to_rule`, `condition` is required and MUST be a non-blank string; with `append_to_rule`, at least one of `condition` and `exceptions` MUST be present.
- A block MUST satisfy every [constraint](#constraints). A violation MUST be reported with its constraint code.
- Unknown keys MUST fail, at the block root and inside every object in the field tables.
- Legacy external-id keys (`rule_id`, `rule_id_bundle`, `rule_id::<tenant>`) at the block root MUST fail with `external_id_in_rule` ([External rule ids](index.md#external-rule-ids)). Registry load drops those keys and passes every other key to the model.
- Field names in `condition`, `macros[].condition`, `output`, and `exceptions[].fields` name Falco fields. A field the [field catalogue](#compile-checks) does not have for the block's `source` is an error, because Falco refuses to load the rule; a `source` the catalogue does not cover is a warning ([Falco language](#falco-language)).
- `condition` and `macros[].condition` SHOULD be checked offline by the analysis engine, as the KQL, SPL, and Lucene blocks are. A Falco syntax error is an error.

Deploy:

- Deploy MUST expand the block's own `macros` and `lists` into the condition before it sends the rule ([Expansion](#expansion)). It MUST NOT create, update, or delete a Falco macro or list on a tenant.
- Requests MUST carry `Authorization: Bearer <api_token>`. Deploy MUST NOT call the Sysdig Public (Next-Gen) API for rules: it has no custom Falco rule or policy write.
- Sysdig is state-backed. Deploy MUST follow the [deploy decisions](../deployment-state.md#deploy-decisions) of deployment state, storing the Sysdig rule id under `platforms.sysdig.<tenant>`. Deploy MUST NOT find a rule by listing remote rules or matching names.
- Deploy MUST NOT create or delete a Sysdig policy. A named policy that does not exist fails the rule with `sysdig_policy_missing`.
- Deploy MUST NOT remove a rule from a policy the block or the tenant does not name.
- Deploy MUST NOT write to the rule file.

Query validation:

- `opentide validate query --platform sysdig` MUST report `supported: false`. Sysdig Secure has no dry-run or preview for a rule. The offline engine check is part of `opentide validate` ([Query validation](#query-validation)).

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
| `policies` | list[string] | optional | tenant `policies` | Names of Sysdig runtime policies the rule joins. |
| `minimum_engine_version` | integer | optional | null | Minimum Falco engine version the rule needs, as Sysdig counts it (a non-negative integer). Sent as `details.minimumEngineVersion`; omitted when unset. |

The shared `name` is the Falco rule name. Empty means the opentide rule `name`. It is ignored with `append_to_rule`, which names the rule instead.

### `exceptions[]` (SysdigException)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Exception name. Names SHOULD be unique in the block: Falco warns on a repeated name (`LOAD_EXCEPTION_NAME_NOT_UNIQUE`) and the engine reports it as a warning. |
| `fields` | string or list[string] | yes | — | One Falco field (the single-field form) or a list of fields (the tuple form). |
| `comps` | string or list[string] | optional | see below | Comparison operators, leading and trailing blanks ignored. Tuple form: a list aligned with `fields`, each a [Falco operator](#operators) or a [modified operator](#operators); default `=` for each field. Single-field form: `in`, `pmatch`, `intersects`, or a modified operator (`startswith oneof`); default `in`. |
| `values` | list | optional | `[]` | Tuple form: a list of rows, each a list aligned with `fields`. An item is a value or a list of values; a single value under a list comparison (`in`, `pmatch`, `intersects`, or a modified operator) is one value list, or the name of a list. Single-field form: a flat list of values. |

Falco compiles each exception into the condition, `(<condition>) and not (<exception>) …`, before it expands lists, so the [Expansion](#expansion) of the block's lists applies to exception values too.

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

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `sysdig_rule_shape` | Without `append_to_rule`, `condition` is a non-blank string. With `append_to_rule`, `append_to_rule` is a non-blank string and at least one of `condition` and `exceptions` is present and non-empty. |
| `sysdig_tuning_keys` | With `append_to_rule`, `output`, `priority`, `policies`, `source`, and `name` MUST NOT be set. A tuning inherits them from the tuned rule. |
| `sysdig_priority` | `priority` is one of the eight Falco priorities or `INFO`, compared case-insensitively. |
| `sysdig_source` | `source` matches `^[a-z][a-z0-9_]*$`. |
| `sysdig_exception_shape` | The checks Falco's rule loader makes (`validate_exception_info`, `build_rule_exception_infos`). An exception has a non-empty `name`. Tuple form: `fields` is a non-empty list of strings, `comps` (when set) is a list of the same length, each comparison a [Falco operator](#operators) or a modified operator, and every row of `values` is a list of the same length as `fields`. Single-field form: `comps` (when set) is a string, `in`, `pmatch`, `intersects`, or a modified operator, and `values` is a flat list of scalars. |
| `sysdig_definition_name` | Every macro and list `name` matches `^[A-Za-z_][A-Za-z0-9_]*$` and is not a Falco operator or keyword (`and`, `or`, `not`, `in`, `exists`, `val`, and the operators). |
| `sysdig_definition_duplicate` | A name is defined at most once across the block's `macros` and `lists`. |
| `sysdig_definition_order` | Falco's definition-before-use for macros: a macro condition names only block macros defined before it, never itself or a later one. Falco refuses such a macro (`Undefined macro`), and on Sysdig the name would fall through to a tenant macro. A macro may use any block list: Falco resolves every list before it compiles the macros. Lists have no ordering constraint ([Expansion](#expansion)). |
| `sysdig_list_in_value` | A block list name appears in an exception value where Falco's expansion would not produce a value list: inside a longer value, or as a single value under a comparison that is not a list comparison. |

### Falco language

The condition is a Falco filter expression, as libsinsp parses and compiles it (`falcosecurity/libs`, `userspace/libsinsp/filter/parser.h` and the filter compiler), inside Falco's rule loader (`falcosecurity/falco`, `userspace/engine`). This section is the contract; [docs/FALCO.md](https://github.com/opentidehq/language-server/blob/main/docs/FALCO.md) in the language server maps each element to the libsinsp source and the test that proves it.

#### Grammar

| Element | Syntax |
|---------|--------|
| Boolean | `or` binds weaker than `and`; `not` is a prefix, repeatable, and `not(…)` needs no blank. `and(`/`or(` need no blank before a parenthesis. Parentheses group. |
| Check | `<field> <condition>`, `<transformer>(…) <condition>`, a bare identifier (a macro), or `( <expr> )` |
| Field | `<class>.<name>` (`[a-zA-Z][a-zA-Z0-9_]*` parts joined by `.`), with an optional argument `[<arg>]`: a quoted string or bare text without blanks, brackets, or quotes (`proc.aname[2]`, `proc.env[HOME]`, `json.value[/spec/x]`). Dotted arguments are part of the name for fields that take them (`evt.arg.flags`). |
| Values | A bare string (no blanks, `(`, `)`, `,`, `=`, quotes), a single- or double-quoted string with backslash escapes, a decimal number with optional sign, fraction, and exponent, or a hex number (`0x1f`) |
| Value list | `( v1, v2, … )`, possibly empty, or the name of a list |
| Right-hand field | `val(<field>)`, or a transformer, compared against the left-hand field |

#### Operators

| Kind | Operators |
|------|-----------|
| Unary | `exists` |
| Numeric | `<`, `<=`, `>`, `>=` |
| String | `=`, `==`, `!=`, `contains`, `icontains`, `bcontains`, `startswith`, `bstartswith`, `endswith`, `glob`, `iglob`, `regex` |
| List | `in`, `intersects`, `pmatch` |
| Modifier | `oneof`, `anyof`, `allof`, after `=`, `==`, `!=`, `contains`, `icontains`, `bcontains`, `startswith`, `bstartswith`, `endswith`, `glob`, `iglob`, or `regex`, before a value list: `proc.name startswith anyof (ba, zs)` |

Word operators need a blank after them; symbols do not.

#### Transformers

`tolower`, `toupper`, `b64`, `basename`, `len`, `join`, `concat`, and `getopt`, nestable, with the argument kinds and counts libsinsp accepts (`join` and `concat` take several arguments, including value lists), and an optional `[<arg>]` after the closing parenthesis. `val(<field>)` names a field on the right-hand side.

#### Compile checks

The engine reports as an **error** what libsinsp or Falco refuse to load: a syntax error; an unknown field of a known source; a field argument that is missing, not allowed, or of the wrong kind (index or key); an operator the field's type does not accept; a value its type cannot parse (numbers, booleans, IP addresses and CIDR networks, hex strings for `bcontains` and `bstartswith`, regular expressions for `regex`); a transformer applied to a type it does not take, or with the wrong arguments (`getopt` needs a list field); a right-hand field (`val()`) the left-hand field cannot be compared with; an unknown event name in `evt.type`; an empty condition; a tuning condition that does not start with `and` or `or`; and an invalid output template.

It reports as a **warning** what depends on the tenant or agent: a `source` the catalogue does not cover; a tuning of a rule that is not a Falco default rule (Falco refuses it, but Sysdig manages rules of its own); a bare name that is neither a block macro or list nor a Falco default macro or list (a Sysdig-managed macro may define it); a deprecated field; libsinsp's compile warnings; a condition that matches too many event types (`LOAD_NO_EVTTYPE`, which Sysdig also returns on create); syntax that needs a newer libsinsp than older agents ship; and a repeated exception name. A tuning is checked on the combined condition: the tuned default rule's condition, then the appended text and exceptions.

The engine's verdicts are checked against real Falco (`falco --validate`, the `falcosecurity/falco` image) by the language server's Falco oracle. The two intended differences are a macro or list Falco does not define and a tuning of a rule Falco does not ship: Falco refuses both, the engine warns, because a Sysdig tenant may define them.

The field catalogue per `source` is libsinsp's own field tables for `syscall`, and the plugins' field tables for `k8s_audit`, `aws_cloudtrail`, `gcp_auditlog`, `okta`, `github`, `k8smeta`, and the container plugin. Exception `fields` and `output` `%field` references are checked against the same catalogue.

Editors get the same diagnostics, plus highlighting, hover, and completion, through the language server.

### Expansion

Before a rule is sent, deploy replaces the block's own macros and lists with their definitions, by Falco's rule-loader algorithm (`rule_loader_compiler.cpp`), so the condition Sysdig receives parses to the expression Falco would compile had the definitions been loaded on the tenant:

1. **Lists, flattened.** In block order, an item that names an earlier block list is replaced by that list's items. An item that names a later block list, or its own list, stays as written for now.
2. **Lists in the condition and in each macro condition** (Falco's `resolve_list`). For each block list in block order, every occurrence of its name with a delimiter on each side (the start or end of the text, a blank, `(`, `)`, `,`, or `=`) is replaced: the name and the blanks around it become `" " + items + " "`, where items are joined by `, ` and an item that contains a space and does not start with a quote is wrapped in double quotes. When the list is empty, one comma next to it is removed. This applies inside quoted strings as well, as Falco does. Because every list is applied in turn, a name left by step 1 for a later list is expanded when that list's turn comes, so a list may name a later list. A name a list's own items brought back is not expanded again: a list naming itself leaves its own name as a literal value (`sysdig_list_self_reference`).
3. **Lists in exception values.** Falco compiles exceptions into the condition before step 2, so the same pass applies: for each block list in block order, a value, or a member of a value list, equal to its name is replaced by its items (spliced into a value list, or, as a single value under a list comparison, made the value list), and the items just inserted are not scanned again for that list. Any other occurrence of a block list name in a value is `sysdig_list_in_value`.
4. **Macros.** A bare identifier in a condition position (a check, not a value) that names a block macro becomes `(` + the macro's expanded condition + `)`. A macro condition sees every block list and the block macros defined before it.
5. Names the block does not define are left as written and resolve on the tenant: Falco's default macros and lists, or the ones Sysdig manages.

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
3. A maturity tag from the block's status strategy: `maturity_stable` for `RELEASE` and `UNIVERSAL`, `maturity_incubating` for `PREVIEW`, otherwise `maturity_sandbox`.
4. The tenant `tags`.

A tuning gets no derived tags: Falco does not append tags to an existing rule.

### Tenant setup

```toml
[platform]
enabled = true
identifier = "sysdig"
name = "Sysdig Secure"
subschema = "Sysdig Secure"
description = "Falco rules for Sysdig Secure runtime threat detection."
flags = []

[[tenants]]
name = "sysdig-prod"
description = "Sysdig Secure SaaS, EU region"
strategies = ["RELEASE"]
[tenants.setup]
ssl = true
url = "https://eu1.app.sysdig.com"
api_token = "$SYSDIG_SECURE_API_TOKEN"
policies = ["opentide managed detections"]

```

| `tenants.setup` field | Type | Required | Default | Meaning |
|-----------------------|------|----------|---------|---------|
| `url` | string | yes | — | Sysdig Secure base URL for the account's region: `https://secure.sysdig.com` (US East), `https://us2.app.sysdig.com`, `https://us4.app.sysdig.com`, `https://eu1.app.sysdig.com`, `https://app.au1.sysdig.com`, `https://app.me2.sysdig.com`, or an on-premises URL. |
| `api_token` | string | yes | — | Sysdig Secure API token. MUST be a `$ENV` reference. |
| `policies` | list[string] | no | `[]` | Policies every new rule joins when its block sets no `policies`. |
| `tags` | list[string] | no | `[]` | Tags added to every rule deployed to this tenant. |
| `ssl` | bool | yes | — | Shared tenant setup (TLS verification). |

A tenant without `url` or `api_token` fails configuration load, and so does an unknown setup key.

### Deploy

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
    "minimumEngineVersion": 17,
    "exceptions": [{"name": "…", "fields": ["…"], "comps": ["…"], "values": [["…"]]}]
  }
}
```

`minimumEngineVersion` and `exceptions` are omitted when the block does not set them. A tuning is sent with `"name": "<append_to_rule>"`, `"append": true`, an empty `description` and `tags`, and only `ruleType`, `append`, `condition`, `exceptions`, and `minimumEngineVersion` in `details`; Sysdig appends the condition and exceptions to the tuned rule's, as Falco's `override: {condition: append, exceptions: append}` does.

| Block status strategy | Binding in deployment state | Sysdig result |
|-----------------------|-----------------------------|---------------|
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | none | `POST /api/secure/rules`; the returned `id` is recorded. Then the rule name is added to each named policy that lacks it. |
| `PREVIEW`, `RELEASE`, `UNIVERSAL` | present | `GET /api/secure/rules/{id}` for its `version`, then `PUT /api/secure/rules/{id}` with that `version`. A renamed rule is renamed in each named policy. Then the rule name is added to each named policy that lacks it. |
| `DISABLEMENT` | present | The rule is updated as above, then removed from each named policy. Sysdig has no disabled flag on a rule: a rule in no policy does not alert. A tuning is deleted instead, and its binding removed. |
| `DELETION` | present | The rule is removed from each named policy, then `DELETE /api/secure/rules/{id}`, then the binding is removed. |
| `DISABLEMENT`, `DELETION` | none | `external_id_missing` (warning), no request. |

A tuning never joins a policy: the tuned rule's policies apply.

A policy is found by name in `GET /api/v2/policies`. It is updated with `PUT /api/v2/policies/{id}`, sending the policy as read with the changed `ruleNames`. When the bound rule no longer exists (`404` on `GET`), deploy creates it again under the same rules as a create and replaces the binding, with a `sysdig_rule_recreated` warning. For `DISABLEMENT` it creates nothing: it removes the binding, with a `sysdig_rule_missing` warning. A `DELETION` whose rule is already gone (`404` on `DELETE`) succeeds and removes the binding.

A rule is created before its policies are updated. When a named policy is missing (`sysdig_policy_missing`), the rule fails but its binding is kept, so the next deploy updates that rule instead of creating a second one.

### Advisories

Advisories are [warnings](../validation.md#platform-advisories): validation reports them under their code and never rejects the rule.

| Code | When | Why |
|------|------|-----|
| `sysdig_list_self_reference` | A block list names itself among its items. | Falco loads it and keeps the name as a literal value, which the rule almost never means. On Sysdig, the literal then resolves against a tenant list of the same name, if one exists. Deploy sends what Falco would compile: the literal. |

### Query validation

| Check | Sysdig |
|-------|--------|
| `opentide validate` (offline, analysis engine) | yes: the Falco condition, block macros, exceptions' fields, and `output` fields ([Falco language](#falco-language)) |
| `opentide validate query --live` | no (`supported: false`) |
| `opentide query` | no |

## Relationships

- [platforms](index.md) — shared fields, capability matrix, external ids
- [deployment-state.md](../deployment-state.md) — the Sysdig rule id
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

Fixtures: [fixtures/platforms/sysdig.yaml](../../fixtures/platforms/sysdig.yaml), [fixtures/valid/rule-sysdig-1.0.yaml](../../fixtures/valid/rule-sysdig-1.0.yaml), [fixtures/valid/rule-sysdig-tuning-1.0.yaml](../../fixtures/valid/rule-sysdig-tuning-1.0.yaml), and the API bodies deploy sends for them: [fixtures/platforms/sysdig/rule-sysdig-1.0.api.json](../../fixtures/platforms/sysdig/rule-sysdig-1.0.api.json) and [fixtures/platforms/sysdig/rule-sysdig-tuning-1.0.api.json](../../fixtures/platforms/sysdig/rule-sysdig-tuning-1.0.api.json).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-03 | Before merge: configured over the API only (no rules-file delivery; `minimum_engine_version`); the Falco language, exception rules, and list expansion follow libsinsp and Falco's rule loader exactly; `sysdig_definition_order` (macros) and `sysdig_list_in_value` replace `sysdig_definition_cycle`; a list may name a later list, as in Falco, and a list naming itself is the `sysdig_list_self_reference` advisory. |
| 1.0 | 2026-11-02 | Initial field contract ([RFC 0014](../../rfcs/0014-sysdig-falco-platform.md), [specifications#8](https://github.com/opentidehq/specifications/issues/8)). |
