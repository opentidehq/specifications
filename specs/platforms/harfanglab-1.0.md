---
spec: platform-harfanglab
version: "1.3"
schema_id: platform::harfanglab::1.0
status: normative
supersedes: null
---

# HarfangLab (`platform::harfanglab::1.0`)

## Summary

`configurations.harfanglab` is a HarfangLab detection rule of one kind: a Sigma behavioural rule **or** a YARA scan rule, never both. There is no query validator. The HarfangLab rule id is the Tide rule's `metadata.uuid` for both kinds.

A YARA block is written either as a whole YARA text (`yara.signature`, a [`YaraSignature`](../languages/yara-1.0.md#yarasignature)) or in the decomposed form (`meta`, `strings`, `condition`, `imports`) that deploy assembles into one rule. Both are checked offline against the [YARA language](../languages/yara-1.0.md) under the [HarfangLab profile](#yara-profile).

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST NOT require `sigma` or `yara`. `maturity`, `confidence`, and `action` have defaults, so a block with only the shared fields validates.
- A block MUST NOT carry both `sigma` and `yara` (`harfanglab_rule_kind`). A Sigma detection and a YARA file for the same threat are two opentide rules.
- Deploy MUST fail unless `sigma` or `yara` is present.
- A `sigma` object MUST include `logsource.category`, `logsource.product`, `selections`, and `condition` for static validation. Each selection MUST include `name`, `field`, and `value`. The HarfangLab loader supplies an empty `selections` list when that key is omitted, so registry load accepts a Sigma block the validator rejects.
- A `yara` object MUST use exactly one form. The **signature** form sets `signature` and none of `meta`, `strings`, `condition`, `imports` (`harfanglab_yara_form`). The **decomposed** form MUST include `meta.context`, `meta.os`, `strings`, and `condition`.
- A block MUST satisfy every [constraint](#constraints), reported with its code.
- `yara.signature`, and the rule the decomposed form assembles, MUST be checked against the [YARA language](../languages/yara-1.0.md) under the [HarfangLab profile](#yara-profile). Its errors fail static validation; its warnings do not.
- `action` SHOULD be `Alert`, `Alert & Block`, or `Alert, Block & Quarantine`. Any other string deploys as `alert`.
- `maturity` SHOULD be `Stable`, `Testing`, or `Experimental`. Any other string deploys as `experimental`.
- `confidence` SHOULD be `Weak`, `Moderate`, or `Strong`. Any other string deploys as `moderate`.
- Legacy external-id keys are invalid. `rule_id_bundle`, `rule_id`, and `rule_id::<tenant>` fail `external_id_in_rule`. Migration removes them as `external_id_unused`; HarfangLab continues to address Sigma and YARA rules by `metadata.uuid`.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `maturity` | string | optional | `Experimental` | Rule maturity. Mapped to HarfangLab `hl_status`. |
| `confidence` | string | optional | `Moderate` | Analyst confidence. Mapped to `rule_confidence_override`. |
| `action` | string | optional | `Alert` | What the agent does on a match. Mapped to `global_state`. |
| `tags` | list[string] | optional | null | Sigma tags, and the YARA `tags` meta line of the decomposed form. |
| `sigma` | [HarfangLabSigma](#sigma-harfanglabsigma) | optional | null | Behavioural rule. Not with `yara`. |
| `yara` | [HarfangLabYara](#yara-harfanglabyara) | optional | null | File or memory scan rule. Not with `sigma`. |

### Action, maturity, and confidence

| `action` | `global_state` | Agent |
|----------|----------------|-------|
| `Alert` | `alert` | alert only |
| `Alert & Block` | `block` | block |
| `Alert, Block & Quarantine` | `quarantine` | quarantine |
| any other | `alert` | alert only |

On a Sigma deploy, `DISABLEMENT` forces `global_state` to `disabled` and sets the rule disabled, regardless of `action`. A YARA deploy does not consult the status strategy when it builds `global_state`; the action table above still applies.

| `maturity` | `hl_status` |
|------------|-------------|
| `Stable` | `stable` |
| `Testing` | `testing` |
| `Experimental` | `experimental` |
| any other | `experimental` |

| `confidence` | override |
|--------------|----------|
| `Weak` | `weak` |
| `Moderate` | `moderate` |
| `Strong` | `strong` |
| any other | `moderate` |

Sigma `level` and the YARA score come from `response.alert_severity`, not from these three fields:

| `response.alert_severity` | Sigma level | YARA score |
|---------------------------|-------------|------------|
| `Informational` | `informational` | 10 |
| `Low` | `low` | 30 |
| `Medium` | `medium` | 50 |
| `High` | `high` | 70 |
| `Critical` | `critical` | 90 |
| missing or unknown | `medium` | 50 |

### `sigma` (HarfangLabSigma)

Deploy builds a Sigma YAML document. The title is the Tide rule `name`, the id is `metadata.uuid`, and the author is `metadata.author`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `logsource.category` | string | yes | Sigma logsource category (`process_creation`). |
| `logsource.product` | string | yes | Sigma logsource product (`windows`). |
| `selections` | list[Selection] | yes | Named selections. |
| `condition` | string | yes | Sigma condition expression (`selection`, `selection1 and selection2`). |
| `false_positives` | list[string] | optional | Sigma false-positive notes. |

`selections[]`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Selection name used by `condition`. |
| `field` | string | yes | Event field (`Image`, `CommandLine`). |
| `value` | string \| number \| boolean \| list of those | yes | Match value. A list is a Sigma list. |
| `modifiers` | list[string] | optional | Sigma modifiers (`contains`, `endswith`). Empty when omitted. |

### `yara` (HarfangLabYara)

A `yara` object takes one of two forms.

**Signature form.** A [`YaraSignature`](../languages/yara-1.0.md#yarasignature):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature` | string | yes | A whole YARA text: imports, then one or more YARA rules, written out in the block. Deploy sends it as the YaraFile `content`, verbatim. |

The author writes every meta line, `context` included. Deploy adds and rewrites nothing.

**Decomposed form.** Deploy builds one YARA rule. The rule name is the Tide rule `name` lowercased, with non-alphanumeric characters turned into `_`, and prefixed with `rule_` when it would start with a digit. Meta `id` is `metadata.uuid`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `meta` | [YaraMeta](#yarameta) | yes | Scan context, OS, and optional score override. |
| `strings` | string | yes | YARA string section body, one definition per line, without the `strings:` header. |
| `condition` | string | yes | YARA condition body, without the `condition:` header. |
| `imports` | list[string] | optional | YARA modules (`pe`, `elf`). Each becomes `import "<module>"`. |

#### `yara.meta`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `context` | list[string] | yes | Scan contexts. The value `file` is rewritten from `os`: `Windows` → `file.pe`, `MacOS` → `file.macho`, `Linux` → `file.elf`. Other context values are kept. |
| `os` | string | yes | `Windows`, `MacOS`, or `Linux`. Also written to meta `os`. |
| `arch` | list[string] | optional | Architectures, joined with commas. |
| `score` | string | optional | `Informational`, `Low`, `Medium`, `High`, or `Critical`. A known value overrides the score taken from `response.alert_severity`. An unknown value falls back to that severity, then to 50. |
| `classification` | string | optional | Free-form classification written to meta. |

Author meta uses `metadata.author`, then `metadata.organisation.name`. `metadata.created` and `metadata.modified` are written when set. Public references are joined into meta `references`.

The language server checks the decomposed form as the rule deploy assembles it, byte for byte: the `import` lines, the derived rule name, every generated meta line with deploy's escaping (including the fields deploy writes unescaped), and the two bodies. Each diagnostic maps back to the authored field it comes from: `strings`, `condition`, `imports`, `meta`, `tags`, a rule field such as `name` or `references`, or the `yara` key when no authored field applies. A diagnostic is never dropped because its position falls in generated text.

### Constraints

Static validation MUST reject a block that breaks any of these, and report the code:

| Code | Constraint |
|------|------------|
| `harfanglab_rule_kind` | `sigma` and `yara` are not both set. |
| `harfanglab_yara_form` | A `yara` object sets `signature`, or the decomposed keys, not both. |
| `harfanglab_yara_section_header` | Decomposed form: `strings` and `condition` contain no `strings:`, `condition:`, or `rule` header. Deploy writes the headers. |
| `harfanglab_yara_import` | Decomposed form: each `imports` entry is a module the [YARA language](../languages/yara-1.0.md#modules) knows. |
| `harfanglab_yara_rule_name` | Decomposed form: the YARA rule name deploy derives from the rule `name` is not a YARA keyword, keeps only ASCII letters, digits, and `_`, and is at most 128 characters. A name such as `Condition` derives `condition`, `Détection` keeps `é`, and a 140-character name derives a 140-character identifier; libyara refuses all three. |

### YARA profile

The [HarfangLab profile](../languages/yara-1.0.md#platform-profiles) of the YARA language: dialect `libyara4`, UTF-8, no size limit, one or more YARA rules per `signature`, and confirmed modules `pe`, `elf`, `math`, `hash`, and `time`.

Every non-private rule of a `signature` SHOULD set meta `context`. A missing `context` is `yara_meta_missing`. A value that is not a comma-joined list, without blanks, of `file`, `memory`, `file.pe`, `file.elf`, and `file.macho` is the `harfanglab_yara_context` [advisory](../validation.md#platform-advisories). `file`, `memory`, and `file,memory` are the values HarfangLab's published rules use. `file.pe`, `file.elf`, and `file.macho` are the values the decomposed form's `os` rewrite writes, alone or with others (`file.pe,memory`). The advisory applies to the decomposed form too, on the `context` deploy writes. A present `context` that is not a string is the advisory, not `yara_meta_missing`. No HarfangLab document defines the key ([RFC 0015](../../rfcs/0015-yara-language.md#harfanglab-yara)).

### Deploy

| Block status strategy | HarfangLab result |
|-----------------------|-------------------|
| `DISABLEMENT` | Sigma rule disabled (`global_state: disabled`, `enabled: false`). A YARA rule is still created or updated with the `action` mapping. |
| `DELETION` | The Sigma or YARA rule deleted by `metadata.uuid`. |
| any other | Create or update by `metadata.uuid`. |

The tenant `source_id` is sent with the rule. The tenant `type` (`Sigma` or `YARA`) selects which HarfangLab API the workspace is configured for; the block's `sigma` / `yara` keys select which compiler runs.

A YARA rule's `content` is `yara.signature` in the signature form, verbatim, and the assembled rule in the decomposed form. Every other part of the YARA deploy is the same for both forms: endpoint, payload fields, name, identity, and the status strategy table above.

### Query validation

| Check | HarfangLab |
|-------|------------|
| `opentide validate` (offline, analysis engine) | YARA: `yara.signature`, and the rule the decomposed form assembles, under the [YARA language](../languages/yara-1.0.md). Sigma: not checked. |
| `opentide validate query --live` | no (`supported: false`) |

## Relationships

- [platforms](index.md) — shared fields, no query validation, external ids
- [yara-1.0](../languages/yara-1.0.md) — the YARA language, `YaraSignature`, and the HarfangLab profile
- [deployment-state.md](../deployment-state.md) — `external_id_unused` in migration; HarfangLab has no shard entry
- [rule-1.0.md](../objects/rule-1.0.md) — `response.alert_severity` feeds level and score
- [metadata.md](../metadata.md) — uuid, author, organisation, dates

## Defaults & overrides

| Field | Default |
|-------|---------|
| `maturity` | `Experimental` |
| `confidence` | `Moderate` |
| `action` | `Alert` |
| Sigma level / YARA score | from `response.alert_severity`, else medium / 50 |
| Rule id | `metadata.uuid` |

## Examples

Sigma:

```yaml
configurations:
  harfanglab:
    enabled: true
    schema: platform::harfanglab::1.0
    status: STAGING
    maturity: Testing
    confidence: Strong
    action: Alert
    tags: [attack.execution, attack.t1059]
    sigma:
      logsource:
        category: process_creation
        product: windows
      selections:
        - name: selection
          field: Image
          value: cmd.exe
          modifiers: [endswith]
      condition: selection
      false_positives:
        - Administrative scripts
```

YARA:

```yaml
configurations:
  harfanglab:
    schema: platform::harfanglab::1.0
    action: "Alert & Block"
    yara:
      meta:
        context: [file]
        os: Windows
        arch: [x86, x64]
        classification: trojan
      imports: [pe]
      strings: |
        $a = "cmd.exe" ascii
      condition: |
        $a
```

YARA, signature form:

```yaml
configurations:
  harfanglab:
    schema: platform::harfanglab::1.0
    action: "Alert & Block"
    yara:
      signature: |
        import "pe"

        rule Loader_Stage1 {
          meta:
            context = "file,memory"
          strings:
            $cfg = { 43 46 47 21 [4-16] 00 01 }
          condition:
            pe.number_of_sections > 3 and $cfg
        }
```

Fixtures: [fixtures/platforms/harfanglab-sigma.yaml](../../fixtures/platforms/harfanglab-sigma.yaml), [fixtures/platforms/harfanglab-yara.yaml](../../fixtures/platforms/harfanglab-yara.yaml), [fixtures/platforms/harfanglab-yara-signature.yaml](../../fixtures/platforms/harfanglab-yara-signature.yaml); invalid: [rule-harfanglab-sigma-and-yara.yaml](../../fixtures/invalid/rule-harfanglab-sigma-and-yara.yaml), [rule-harfanglab-yara-both-forms.yaml](../../fixtures/invalid/rule-harfanglab-yara-both-forms.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the HarfangLab configuration model and deployer. |
| 1.1 | 2026-10-16 | `rule_id_bundle` is removed. Legacy external-id keys fail `external_id_in_rule`, and migration removes them as `external_id_unused` ([RFC 0010](../../rfcs/0010-deployment-external-ids.md)). Identity stays `metadata.uuid`. Schema id unchanged. |
| 1.2 | 2026-11-10 | `yara.signature`: a whole YARA text (`YaraSignature`), deployed as the YaraFile `content` verbatim, beside the decomposed form. A block is one kind: `sigma` and `yara` together fail `harfanglab_rule_kind`, replacing "deploy MUST publish `sigma`". New constraint codes and the HarfangLab YARA profile; YARA is checked offline against [yara-1.0](../languages/yara-1.0.md) ([RFC 0015](../../rfcs/0015-yara-language.md)). The YARA deployer is otherwise unchanged. Schema id unchanged. |
| 1.3 | 2026-11-10 | Clarifications from the first implementation review: the decomposed form is checked exactly as deploy assembles it, every diagnostic mapped to an authored field and none dropped; `harfanglab_yara_rule_name` also covers a derived name over 128 characters; `harfanglab_yara_context` accepts any comma-joined list of `file`, `memory`, `file.pe`, `file.elf`, `file.macho`, applies to the decomposed form, and covers a non-string `context`. Schema id unchanged. |
