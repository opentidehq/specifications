# RFC 0014: Sysdig Secure and Falco detection platform

- **RFC:** 0014
- **Title:** Sysdig Secure and Falco detection platform
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-02
- **Accepted:** on merge of the specifications PR that adds it, with the normative text in [specs/platforms/sysdig-1.0.md](../specs/platforms/sysdig-1.0.md)
- **Supersedes:** RFC 0004 (reserved by [opentidehq/specifications#8](https://github.com/opentidehq/specifications/issues/8), never in tree)
- **Issue:** [opentidehq/specifications#8](https://github.com/opentidehq/specifications/issues/8)
- **Implementation:** [opentidehq/opentide#143](https://github.com/opentidehq/opentide/issues/143); the Falco language in [opentidehq/language-server](https://github.com/opentidehq/language-server)

> Numbering note: RFC 0004 was reserved for this design in August 2026 and never landed. Since then opentide removed `rule_id_bundle` ([RFC 0010](0010-deployment-external-ids.md)) and gained Elastic as its eighth platform ([RFC 0007](0007-elastic-security-platform.md)). The design below is the revised one, under the next free number, as asked on [opentide#143](https://github.com/opentidehq/opentide/issues/143#issuecomment-6264171063).

## Summary

Add a ninth detection platform, `sysdig` (display name **Sysdig Secure**, schema `platform::sysdig::1.0`). Its block is a Falco rule: a Falco `condition`, its `exceptions`, and the macros and lists only this rule uses. Deploy derives the Falco rule name, `desc`, `priority`, MITRE `tags`, and a default `output` from the opentide rule.

One block serves two deliveries, chosen per tenant: the Sysdig Secure API (`api`) and Falco rules files (`file`), for open-source Falco and for GitOps. The analysis engine gains a Falco language: grammar, field catalog per event source, macro and list resolution, highlighting, hover, and completion, so `opentide validate` and editors check the condition offline.

The change is additive. It adds `configurations.sysdig`, a deployment-state platform key, and no change to existing blocks.

## Motivation

opentide's eight platforms are SIEMs and EDRs. None covers runtime detection for Linux hosts, containers, and Kubernetes, where Falco is the common engine: CNCF graduated, the engine of Sysdig Secure's runtime threat detection, and fed by plugins for Kubernetes audit logs, AWS CloudTrail, GCP audit logs, Okta, and GitHub. Teams that write Falco rules today keep them as raw YAML outside their detection catalogue, without objectives, lifecycle, or review.

Falco rules are already structured YAML. A typed block can carry the author's intent (condition, exceptions, private macros and lists) and leave the metadata to opentide, so a rule's severity, ATT&CK mapping, and lifecycle are written once.

## Research

### Which Sysdig API

| Surface | Verdict |
|---------|---------|
| Secure Public API (`/secure/...`, "Next-Gen") | Rejected. It has vulnerability management and read-only events, but no custom Falco rule or policy write. |
| Secure runtime API: `/api/secure/rules`, `/api/v2/policies` | **Target.** Custom Falco rules (`ruleType: FALCO`, `append`, `source`, `condition`, `output`, `priority`, `exceptions`) and runtime policies (`ruleNames`). |
| `/api/secure/falco/macros`, `/api/secure/falco/lists` | Not used. Macros and lists are global to the account, so two opentide rules defining one name would overwrite each other. See [Expansion](#2-expansion-instead-of-remote-macros-and-lists). |
| Rules files upload (`/api/settings/falco/...`) | Rejected. Legacy; it replaces a whole file and has no per-rule identity. |

The paths and payloads are those of Sysdig's own Terraform provider (`draios/terraform-provider-sysdig`, `sysdig/internal/client/v2/{rules,policies}.go`): `POST /api/secure/rules`, `GET`/`PUT`/`DELETE /api/secure/rules/{id}`, and `GET /api/v2/policies`, `PUT /api/v2/policies/{id}`. An update sends the `version` read from the rule, as the provider does. Authentication is `Authorization: Bearer <api token>`. The provider's `priority` values are `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, and `debug`.

Regions are separate base URLs (`secure.sysdig.com`, `us2.app.sysdig.com`, `us4.app.sysdig.com`, `eu1.app.sysdig.com`, `app.au1.sysdig.com`, `app.me2.sysdig.com`, and on-premises). The tenant's `url` names it; the API is the same.

### Rule identity

Sysdig assigns an integer `id` on create and requires it for update and delete. Rule names are unique among custom rules, but [deployment-state](../specs/deployment-state.md) forbids rediscovering a rule by name. The id therefore lives in a deployment-state shard, as Defender's, SentinelOne's, and CrowdStrike's do. A `file` tenant writes `<rules_dir>/<metadata.uuid>.yaml` and needs no id.

### Policies

A Sysdig rule alerts only when a runtime policy includes it, by name (`ruleNames`). A policy holds many rules and carries its own scope, severity, actions, and notification channels: it is workspace configuration, not part of one detection. Deploy adds the rule to the policies the block or tenant names, and never creates a policy, as Carbon Black Cloud never creates a watchlist. Sysdig's policy severity scale (0–3 high, 4–5 medium, 6 low, 7 info) therefore needs no mapping: severity is the rule's Falco `priority`.

### Falco language

Falco conditions are boolean filter expressions over fields (`proc.name`, `fd.name`, `ka.verb`), with comparison operators, value lists, field arguments (`proc.aname[2]`), and transformers (`tolower(…)`). Bare names are macros, or lists inside a value list. Fields depend on the event source: `syscall` fields come from libsinsp; plugins (`k8saudit`, `cloudtrail`, `okta`, `github`, `gcpaudit`, `k8smeta`, `container`) add their own. The field reference, operators, and exception semantics are from the Falco documentation (`falcosecurity/falco-website`, `content/en/docs/concepts/rules/` and `reference/rules/supported-fields`) and the plugin READMEs (`falcosecurity/plugins`).

## Detailed design

The normative text is [specs/platforms/sysdig-1.0.md](../specs/platforms/sysdig-1.0.md). The decisions:

### 1. One platform, two deliveries

`sysdig` covers Sysdig Secure and open-source Falco. A tenant's `delivery` is `api` (Sysdig Secure) or `file` (one Falco rules file per rule in `rules_dir`). The block is the same for both: only the tenant decides where the rule goes. A separate `falco` platform would duplicate the block and its checks for the same rule language.

### 2. Expansion instead of remote macros and lists

The block's `macros` and `lists` are private to the rule. Deploy expands them into the condition before it sends or writes the rule. Names the block does not define are left as written and resolve on the tenant: the Falco default macros (`spawned_process`, `container`, `open_read`) and the ones Sysdig manages.

Every rule owns exactly one remote object, so:

- two rules cannot overwrite each other's definitions on a tenant;
- the deployment-state shard keeps its one-id-per-tenant shape;
- a rules directory loads the same whatever the file order.

The cost is that a shared definition is repeated in each rule that uses it. A shared macro belongs on the tenant (Sysdig managed, or the Falco default rules), where every rule can reference it.

### 3. New rule or tuning

A block either defines a rule (`condition`) or tunes an existing one (`append_to_rule` plus a `condition` fragment and/or `exceptions`). A tuning is Falco's `override: {condition: append, exceptions: append}` in a file and `details.append: true` on the API. It cannot set `output`, `priority`, `source`, or policies: those stay the tuned rule's. RFC 0004's `override` key with per-key `replace` is dropped. Replacing a managed rule's condition from a detection catalogue hides the change from the rule's owner; a replacement is a new rule.

### 4. Derived fields

- **Name:** the shared `name`, else the opentide rule `name`.
- **desc:** the opentide `description`, whitespace collapsed.
- **priority:** from `response.alert_severity`: Critical → `CRITICAL`, High → `ERROR`, Medium → `WARNING`, Low → `NOTICE`, Informational → `INFORMATIONAL`. Falco's own rules reserve `EMERGENCY` and `ALERT` for host compromise, and so does this map.
- **tags:** the block's tags, technique ids, `mitre_<tactic>` tags, a `maturity_*` tag from the status strategy, and tenant tags. These are the Falco default rules' tag conventions, so opentide rules filter beside them in Falco Sidekick and Sysdig.
- **output:** a default per event source when omitted.
- **enabled:** `false` for `DISABLEMENT` in a file. On the API, Sysdig has no rule-level enable flag, so disablement removes the rule from its policies.

### 5. Validation

`opentide validate query --live` reports `supported: false`: Sysdig has no rule preview, and Falco OSS has no API. The analysis engine checks the condition offline instead: syntax is an error, an unknown field or reference is a warning (plugins add fields, Sysdig manages macros). The engine's macro and list catalogue is the public Falco default rules; its field catalogue is the Falco and plugin field references.

### 6. Engine (language-server)

A tree-sitter grammar for Falco conditions, a field catalogue per source, highlighting through the shared HighlightSpec, hover and completion for fields, macros, lists, and operators, and injection of `configurations.sysdig.condition`, `macros[].condition`, and `output` in Tide YAML. Its external conformance corpus is the public `falcosecurity/rules` and plugin rules, unmodified, with a broken twin each.

## Drawbacks

- Expansion repeats a definition in every rule that uses it and makes the deployed condition longer than the authored one.
- Sysdig's runtime API is not the documented public API. The Terraform provider uses it, which makes it stable in practice, but Sysdig could change it.
- A tuning depends on a rule opentide does not manage. If the tuned rule is renamed or removed, the append fails at deploy (API) or at Falco load (file).

## Alternatives

- **Raw Falco YAML in the block.** Simple, but every rule would retype `desc`, `priority`, and tags, the ATT&CK mapping would drift from opentide's, and nothing could check the rule before deploy.
- **Remote macros and lists, upserted by name.** RFC 0004's design. Rejected for the global-name collisions above, and because deployment state would need several ids per rule.
- **A `falco` platform separate from `sysdig`.** Rejected: same block, same language, and the delivery is a tenant property.
- **`terraform` delivery.** Deferred, as in RFC 0004. The `api` delivery uses the same endpoints.
- **Live validation by create-and-delete.** Rejected: it creates remote state to check syntax, and the offline engine already checks it.

## Unresolved questions

- Sysdig on-premises versions older than the Terraform provider's minimum may reject the `skipPolicyV2Msg` behaviour; deploy does not send that parameter.
- Whether to add `opentide query` for Sysdig through the Secure Events API. Out of scope here.
- A cross-rule lint that suggests moving a macro repeated in many rules to the tenant.
