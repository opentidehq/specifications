# RFC 0008: Detection rule document shape (`rule::2.0`)

- **RFC:** 0008
- **Title:** Detection rule document shape (`rule::2.0`)
- **Author:** OpenTide maintainers
- **Status:** draft
- **Created:** 2026-09-30
- **Issue:** [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- **Implementation:** [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)

## Summary

Give the detection rule (MDR) the same document shape as the other core objects. `name`, `metadata`, and `references` stay on the envelope. Everything that describes the detection moves into a required `rule:` body: narrative, lifecycle, severity, ATT&CK techniques, the objective link, the response block, and one key per platform.

`configurations:` and the legacy `platforms:` dict go away on this revision. Platform blocks (`platform::sentinel::1.0` and the rest) keep their fields. The schema identifier is `rule::2.0`. Documents that still declare `rule::1.0` stay valid and keep today's layout. An implementation that ships `rule::2.0` MUST operate both revisions in one workspace.

This RFC also records that opentide cannot do that yet, and the versioning spec needs a tighter contract so a second rule revision is actually usable.

## Motivation

Threats put their domain fields in `threat:`. Objectives put theirs in `objective:`. Rules do neither. `rule::1.0` ([specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md)) spreads the detection across the document root and then hides every platform block under `configurations`, with a second untyped `platforms` map kept "for backward compatibility":

```yaml
name: Sentinel KQL Rule
metadata:
  schema: rule::1.0
description: Detects credential access via suspicious process creation
status: STAGING
severity: High
techniques: [T1059]
detection_model: 00000000-0000-4000-8002-000000000001
response:
  alert_severity: High
configurations:          # typed wrapper
  sentinel:
    enabled: true
    query: |
      SecurityEvent | take 1
platforms: {}            # legacy twin of the same idea
```

Authors have to know which of those three places a fact lives in. Tooling has to know too: deployers read `.configurations.<platform>`, exporters read a root `description` for rules and a nested `description` for threats and objectives, and the MCP deployment-status tool checks `configurations` and then `platforms`.

The platform payloads are in good shape. Sentinel scheduling, Splunk actions, HarfangLab Sigma/YARA, and the other blocks should stay. The break is the top of the document.

A `rule:` body makes a rule file read like a threat file and an objective file:

| Envelope (every core object) | Body (this object) |
|------------------------------|--------------------|
| `name`, `metadata`, `references` | `threat:` / `objective:` / `rule:` |

Stakeholders: detection authors writing YAML, agents generating rules, and the opentide loader, deployers, documentation renderer, and schema generator.

## Detailed design

### Document shape (`rule::2.0`)

New spec file: `specs/objects/rule-2.0.md`. Schema id: `rule::2.0`.

`rule::1.0` stays a normative spec. Instances that declare it continue to validate against [rule-1.0.md](../specs/objects/rule-1.0.md). Deprecating `rule::1.0` is a later decision, after catalogues can migrate and opentide can load both shapes. Marking it deprecated in the same change that introduces `2.0` would tell authors to stop writing `1.0` before the runtime can read `2.0`.

#### Envelope

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Rule display name. Stays on the envelope, as on threats and objectives, so indexes that read the root `name` keep working. |
| `metadata` | ObjectMetadata | yes | [metadata.md](../specs/metadata.md). `metadata.schema` MUST be `rule::2.0`. |
| `rule` | RuleBody | yes | Detection body. |
| `references` | ObjectReferences | no | Same object as on `rule::1.0`. |

The document root MUST NOT contain `description`, `status`, `severity`, `techniques`, `detection_model`, `response`, `configurations`, or `platforms`. Those keys are how a `rule::1.0` file is recognised; on `2.0` they are invalid.

#### `rule` (RuleBody)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `description` | string | yes | — | Rule narrative. |
| `status` | string | no | `STAGING` | Same deployment-status vocabulary as `rule::1.0`. |
| `severity` | string | no | `Informational` | Rule severity vocabulary. |
| `techniques` | list[string] | no | `[]` | ATT&CK technique IDs. MAY be empty. |
| `detection_model` | string | no | null | Objective UUID this rule implements. |
| `response` | RuleResponse | no | null | Same response, procedure, and search objects as `rule::1.0`. |
| `<platform>` | platform block | no | — | One optional key per platform identifier in [platforms.md](../specs/platforms.md). |

Reserved body keys are `description`, `status`, `severity`, `techniques`, `detection_model`, and `response`. A platform identifier MUST NOT reuse a reserved key.

A platform key's value is the existing platform block for that identifier (`platform::sentinel::1.0`, and so on), including `enabled`, `name`, `schema`, `status`, `flags`, `tenants`, `contributors`, and the platform's own fields. This RFC does not change those fields.

A rule is deployable when at least one platform block has `enabled: true`. A body with no platform keys is valid (a draft in `DESIGN` / `STAGING`). Static validation MUST NOT require a platform block. Deployment MUST.

Adding a new optional platform key (for example `elastic`, once [RFC 0007](0007-elastic-security-platform.md) is in the platform matrix) is a non-breaking edit of `rule::2.0`. It does not allocate `rule::2.1`. The same rule already applies to `configurations.<platform>` on `rule::1.0`.

Platform schema revisions stay on their own axis. `rule::2.0` embeds whatever `schema` the block declares (`platform::sentinel::1.0` today). A future `platform::sentinel::2.0` is selected by that field. It does not bump the rule schema by itself.

#### Example

```yaml
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::2.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: clear
rule:
  description: |
    Detects credential access via suspicious process creation.
  status: STAGING
  severity: High
  techniques: [T1059]
  detection_model: 00000000-0000-4000-8002-000000000001
  response:
    alert_severity: High
  sentinel:
    enabled: true
    schema: platform::sentinel::1.0
    name: Sentinel KQL Rule
    status: STAGING
    query: |
      SecurityEvent
      | where EventID == 4688
      | take 1
    scheduling:
      frequency: PT1H
      lookback: PT2H
    alert:
      title: Sentinel KQL Rule
      suppression: false
references:
  public:
    1: https://example.invalid/writeup
```

#### Vocabulary pins

New section in [schemas/pins/rule.toml](../schemas/pins/rule.toml). `rule::1.0` pins stay on their current paths.

```toml
["rule::2.0"]
"metadata.tlp" = "tlp::1.0"
"rule.severity" = "severity::1.0"
"rule.techniques" = "att&ck::1.0"
"rule.response.alert_severity" = "alert_severity::1.0"
"rule.response.responders" = "responders::1.0"
```

Pin paths follow the document. Moving `severity` under `rule` is a schema-pin change, not a vocabulary change.

#### Fixtures (on acceptance, not in this RFC)

| Fixture | Role |
|---------|------|
| `fixtures/valid/rule-2.0.yaml` | The example above, plus a second platform key left disabled. |
| `fixtures/invalid/rule-2.0-missing-body.yaml` | No `rule` key. |
| `fixtures/invalid/rule-2.0-configurations.yaml` | `configurations:` present. |
| `fixtures/invalid/rule-2.0-root-description.yaml` | `description` on the envelope. |
| `fixtures/valid/rule-1.0.yaml` | Unchanged. Still the `rule::1.0` conformance file. |

### Migration from `rule::1.0` to `rule::2.0`

One registered step. There is no `rule::1.1` in between. The chain implementation already allows a direct major bump (`SchemaVersionChain` walks whatever step is registered from the source).

The migration reads the YAML mapping:

| `rule::1.0` | `rule::2.0` |
|-------------|-------------|
| `name`, `metadata` (except `schema`), `references` | unchanged |
| `description`, `status`, `severity`, `techniques`, `detection_model`, `response` | `rule.<same key>`, copied only when the key is present |
| `configurations.<platform>` | `rule.<platform>` |
| `platforms.<platform>` | `rule.<platform>` when `configurations` has no such key |

Rules:

- Stamp `metadata.schema` to `rule::2.0`.
- Leave `metadata.version`, `created`, and `modified` alone. A structural migration is not a content revision.
- If a platform key appears in both `configurations` and `platforms`, fail. `rule::1.0` already forbids declaring both.
- If a platform key is not a known platform identifier, fail. Today's loader drops unknown `configurations` keys (`load_rule_from_dict` keeps only `PLATFORM_CONFIG_MODELS`). A migration that dropped them would hide content.
- Omit defaults that were omitted in the source. The `2.0` model applies `STAGING`, `Informational`, and `[]` on load.
- Ordinary load MUST NOT run this migration. Loading a `rule::1.0` file validates it as `rule::1.0`. Migration runs only when a caller asks for `rule::2.0` (a migrate command, or `load_object(..., target_schema="rule::2.0")`).

### Can opentide operate both revisions?

Studied against `OpenTideHQ/opentide` at `development` (September 2026). Short answer: the registry can hold two rule models, and the rule pipeline will not honor them. Shipping `rule::2.0` as a second Pydantic class, with no other work, does not satisfy the versioning spec.

#### What already matches the versioning spec

[specs/versioning.md](../specs/versioning.md) requires routing by `metadata.schema`, optional migration, and one generated artifact per identifier. These pieces exist:

| Piece | Where | Behaviour |
|-------|--------|-----------|
| Identifier parse | `opentide.models.version.SchemaVersion` | `rule::1.0`, `rule::2.0`. |
| Linear migration chain | `SchemaVersionChain` | One forward step per source version. A direct `1.0 → 2.0` step is valid. Tests cover a fake family through `2.0` (`tests/test_models/test_schema_revision.py`). |
| Model registry | `register_model` / `resolve_model` | Keyed by full identifier, not by family. |
| Routed load | `opentide.loading.object_loader.load_object` | Resolves `metadata.schema`. Migrates only when `target_schema` differs, then stamps the identifier. |
| Per-identifier JSON Schema | `generate_schema_for_identifier` | Pins `metadata.schema` as `const`. |
| IDE router | `build_opentide_router` | One `if`/`then` branch per registered identifier. |
| Per-revision vocab pins | `apply_vocab_pins` | Pins are looked up by schema id. `threat::1.0` and `threat::2.1` already have different pin sections. |

`validation/session.py` calls `load_object_for_validation`, which uses that router when `metadata.schema` is present. That path can validate a second revision **after** the model is registered.

#### What still assumes a single rule shape

These paths will mis-handle `rule::2.0`, and several of them will also corrupt `rule::1.0` artifacts once `2.0` is registered as the latest rule model.

1. **Bootstrap registers one class per family.** `schema_registry._bootstrap` registers `DetectionRule`, `ThreatVector`, `DetectionObjective`, and `VisibilityConfig`. `ThreatVector_v2_1` (`threat::2.1` in `models/threat.py`) is never registered. A second class that is not passed to `register_model` is invisible to `load_object`, generation, and the router. `rule::2.0` must be registered beside `DetectionRule`, not instead of it.

2. **The rule loader ignores the router.** `loading/rule_loader.py` `load_rule_from_dict` always calls `DetectionRule.from_yaml_dict` and only lifts a root `configurations` object into `RuleConfigurations`. Deploy, MCP, and documentation read `OpenTide.Rules`, which is filled from this loader. A `rule::2.0` file fails validation here (extra `rule` key, missing root `description`, `configurations` absent). `validation/pipeline.py` repeats the mistake: `_MODEL_BY_TYPE["rule"]` is `DetectionRule`, so the two validation entry points disagree.

3. **Deployers type-check the 1.0 class and read `.configurations`.** `BaseRuleDeployer._resolve_rules` keeps an object only when `isinstance(first, DetectionRule)`. Each platform deployer repeats that check and then reads `data.configurations.<platform>` (Sentinel, Defender, Splunk, SentinelOne, CrowdStrike, HarfangLab, Carbon Black). `deployment/planning.py` `mdr_configuration_resolver` is the same chain. A sibling model that is not a `DetectionRule` subclass is skipped or treated as a UUID string. Subclassing `DetectionRule` is the wrong fix: the 1.0 model requires root `description` and declares `configurations`, and `TideModel` uses `extra="forbid"`. Those fields would leak into the 2.0 document.

4. **Latest-revision files clobber the 1.0 artifact names.** `data/configurations/paths.toml` maps the family `rule` to `rule.1.0.schema.json` and `rule.1.0.template.yaml`. `generation/schema_pipeline.py` writes each identifier to its own file, then, when the identifier is `latest_identifier(family)`, copies that schema onto the family filename. After `rule::2.0` is registered it is the latest rule schema, so the copy writes the 2.0 schema into `rule.1.0.schema.json` and replaces the 1.0 artifact. `generation/artifact_gate.py` checksums one schema and one template per family (`schema_map.get(family)`), so CI would not notice the missing `rule.2.0.schema.json` or the overwritten 1.0 file. `generation/pydantic_templates.py` generates a template from `core_object_schemas()`, which is the latest model only, into the 1.0 template filename.

5. **Editors bind a folder to one schema.** `cli/services/setup/vscode.py` maps `objects/rules/**/*.yaml` to `rule.1.0.schema.json`. The comment in that module, and [docs/usage/concepts/schema-revision.md](https://github.com/OpenTideHQ/opentide/blob/development/docs/usage/concepts/schema-revision.md), already say the YAML language server cannot narrow the `oneOf` router. With two revisions in `objects/rules/`, the editor validates every file against whichever schema that single filename happens to hold. CLI validation can still be correct. Editor validation will not be, until routing uses `metadata.schema`.

6. **Readers hard-code 1.0 paths.** `export/revisions_export.py` and `export/table_export.py` use the root `description` for rules and `threat.description` / `objective.description` for the others. `documentation/objects/rule.py` renders `rule.description`, `rule.status`, `rule.techniques`, and `rule.configurations`. `mcp_server/tools.py` `tool_deployment_status` iterates `body["configurations"]` or `body["platforms"]` and will report no platforms for a 2.0 document. `tool_deploy_rule` returns `rule.status` from the loaded model.

7. **A missing schema selects the latest model.** `load_object` rejects a missing `metadata.schema`. `load_object_by_type` does not: it uses `core_object_schemas()`, the latest model per family. Once `rule::2.0` is latest, a legacy call with no schema parses the body as 2.0.

8. **The reserved corpus slice is `rule::1.1`, and it is expected to fail.** `tests/test_cli/e2e/test_schema_compat_e2e.py` is `xfail` until a `rule::1.1` chain exists (`tests/fixtures/tide_corpus/manifest.toml`, slice `future_rule_1_1`). This RFC does not introduce `rule::1.1`. The implementation issue should add a `rule::2.0` corpus slice and leave the 1.1 slice reserved.

#### What the implementation has to grow

Tracked in [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394). Not part of the RFC pull request.

- Register `rule::1.0` and `rule::2.0` together. Register `threat::2.1` as well, or delete the unregistered class; a revision that is not registered is not supported.
- A small rule view both models implement: `name`, `metadata`, `description`, `status`, `severity`, `techniques`, `detection_model`, `response`, and `platform(name) -> block | None`. `rule::1.0` reads platform blocks from `configurations`. `rule::2.0` reads them from `rule`. Deployers, the planner, documentation, and MCP call the view. They stop using `isinstance(..., DetectionRule)` and `.configurations`.
- `load_rule_from_dict` delegates to `load_object`. `validation/pipeline.py` does too.
- An explicit migrate command runs the `1.0 → 2.0` step. Load does not.
- Generate `rule.1.0.schema.json` for `rule::1.0` and `rule.2.0.schema.json` for `rule::2.0`, and the same for templates. The family alias in `paths.toml` MUST NOT receive another revision's bytes.
- When a family has more than one registered revision, editor schema association MUST discriminate on `metadata.schema`. A single glob → single file mapping for `objects/rules/**` is non-conformant in that case.

### Additional spec work

The versioning spec describes routing and says a migration MAY exist. It does not say that deploy, document, export, or the editor have to follow the declared revision. `rule::2.0` is the change that makes those gaps user-visible. Amend [specs/versioning.md](../specs/versioning.md) to **1.1** in the same acceptance PR as `rule-2.0.md`. Proposed requirements, in addition to the current 1.0 text:

- An implementation MUST register a model for every schema identifier it claims to support. An unregistered class MUST NOT be treated as supported.
- Load, validate, deploy, document, and export MUST select the model from `metadata.schema`. A family-keyed map (`"rule" → DetectionRule`) is non-conformant once the family has more than one registered revision.
- A missing `metadata.schema` MUST be an error. It MUST NOT select the latest revision of the family.
- Loading an object MUST validate the declared revision. Upgrading to a newer revision MUST happen only through an explicit migration request.
- When a breaking revision ships with an upgrade path, that path MUST be a registered forward chain. `rule::1.0` → `rule::2.0` is a single step. The migration MUST stamp `metadata.schema` and MUST NOT change `metadata.version`.
- Components that read a field whose path differs across revisions MUST use a reader that understands each registered revision.
- `generate schemas` MUST emit one JSON Schema and one template per registered identifier. A family-level filename (`rule.1.0.schema.json`) MUST contain the schema for that identifier only.
- When two or more revisions of a family are registered, editor validation MUST choose the schema from `metadata.schema`. Binding the whole object folder to one file is non-conformant.
- Vocabulary pins are per revision and use that revision's field paths.
- Platform schema identifiers and the rule schema identifier version independently. An optional new platform key on the current rule revision is non-breaking.

[specs/validation.md](../specs/validation.md) already says schema validation loads each object via `metadata.schema`. Add one sentence: a second code path that validates by object family and ignores `metadata.schema` is non-conformant. That sentences the `pipeline.py` / `session.py` split.

[specs/platforms.md](../specs/platforms.md) keeps the platform-block field tables. It gains a note that `rule::1.0` nests blocks under `configurations.<platform>` and `rule::2.0` nests the same blocks under `rule.<platform>`. The platform schema ids do not change.

[specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md) gains a history row pointing at `rule::2.0` and at this RFC. Its requirements stay in force for `metadata.schema: rule::1.0`.

### Spec changes after acceptance

| Path | Change |
|------|--------|
| `specs/objects/rule-2.0.md` | New normative spec, from the tables in this RFC. |
| `specs/objects/rule-1.0.md` | History row. Status stays `normative`. |
| `specs/versioning.md` | Version 1.1, requirements listed above. |
| `specs/validation.md` | Family-keyed validation path is non-conformant. |
| `specs/platforms.md` | `rule.<platform>` is the `rule::2.0` location of the same blocks. |
| `schemas/pins/rule.toml` | `["rule::2.0"]` section. |
| `fixtures/valid/rule-2.0.yaml` and the invalid fixtures listed above | Conformance. |
| `SPECS.md`, `CHANGELOG.md` | Index and history. |

No vocabulary TOML changes. No platform-block schema changes. No opentide code in the specifications pull request that accepts this RFC; implementation follows in [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394).

## Drawbacks

- Every existing rule file stays on `rule::1.0` until someone migrates it. Tooling carries two shapes for as long as those files exist.
- Deployers in opentide all read `.configurations`. Moving them onto a shared `platform(name)` view touches every platform package, the deployment planner, documentation, exports, and the MCP deployment-status tool. The edits are mechanical and wide.
- `status` and `severity` leave the document root, so `yq '.status'` stops matching `rule::2.0` files. The envelope stays small on purpose: `name` is the only domain field left beside `metadata` and `references`.
- Editor support needs a real schema router. The folder-to-one-file mapping cannot represent coexistence, and the current `opentide.schema.json` router is already known to be unusable by the Red Hat YAML language server.
- Introducing `rule::2.0` as the latest revision without the artifact-alias fix would overwrite `rule.1.0.schema.json`. That fix is a prerequisite for registering the new model, not a follow-up.

## Alternatives

### Rename `configurations` to `platforms` and stop there

Rejected. `platforms` is the legacy untyped map. A rename keeps a wrapper the other objects do not have, and it forces a schema bump anyway because the key changed. The body would still be flat.

### Put platform keys on the envelope, next to `rule:`

```yaml
rule:
  description: ...
sentinel:
  query: ...
```

Rejected. The detection would be split across the envelope and the body. Threats and objectives keep domain fields inside the named block. Platform blocks are domain fields of a rule.

### Keep `configurations` inside `rule:`

```yaml
rule:
  description: ...
  configurations:
    sentinel: ...
```

Rejected. That preserves the wrapper this RFC removes. Authors would still open an extra key that means "the platforms".

### Make `rule::2.0` a subclass of `DetectionRule` so deployers keep working

Rejected as the document design. It would preserve root `description` and `configurations` in the model, which is the layout we are retiring. A shared view (see the implementation section) gives deployers one read API without forcing both documents into one class.

### In-place edit of `rule::1.0`

Rejected. Moving fields and removing `configurations` is a breaking structural change. [specs/versioning.md](../specs/versioning.md) requires a new schema identifier and a new spec file. Existing catalogues keep `rule::1.0`.

### Require a repository-wide migration when `2.0` ships

Rejected. The versioning spec says objects opt in per file. A big-bang rewrite of every rule is how catalogues get stuck. The migrate command is there for authors who want to move a file; load of the old file keeps working.

### Split `objects/rules/` into `1.0/` and `2.0/` directories

Rejected as a spec requirement. The schema id on the document is the discriminator, and rules already share a folder with mixed content versions. Directory splitting would push the version into the path, which drifts from `metadata.schema`. Editor routing has to learn the schema id anyway.

## Unresolved questions

- Should `opentide new` / template generation emit `rule::2.0` as soon as the model is registered, while `rule::1.0` remains normative for existing files? This RFC assumes yes: new files use the latest revision, existing files stay on their declared revision.
- When is `rule::1.0` marked `deprecated`? This RFC leaves it normative until an implementation can load both and a catalogue migration path exists. Deprecation then means "do not author new 1.0 files", and existing 1.0 files remain valid.
- [RFC 0007](0007-elastic-security-platform.md) adds `configurations.elastic` on `rule::1.0` and has not yet landed in [platforms.md](../specs/platforms.md). `rule::2.0` should pick up `rule.elastic` in the same change that adds `elastic` to the platform matrix, as an optional key, without a further rule-schema bump. Confirm that ordering when 0007's spec PR opens.
- The shared rule view is an opentide API. It does not need a name in the spec beyond the requirement that readers honor each revision. If reviewers want the method names frozen, that belongs in the opentide PR, not here.

## References

- [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24) — spec-change issue
- [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394) — implementation gap list
- [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md), [specs/objects/threat-1.0.md](../specs/objects/threat-1.0.md), [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md)
- [specs/versioning.md](../specs/versioning.md), [specs/platforms.md](../specs/platforms.md), [specs/validation.md](../specs/validation.md)
- [RFC 0007](0007-elastic-security-platform.md) — additive platform key, rule schema id unchanged
- opentide: `models/rule.py`, `models/platform.py` (`RuleConfigurations`), `models/schema_registry.py`, `models/threat.py` (`ThreatVector_v2_1`), `loading/rule_loader.py`, `loading/object_loader.py`, `generation/schema_pipeline.py`, `generation/artifact_gate.py`, `deployment/planning.py`, `validation/pipeline.py`, `validation/session.py`
