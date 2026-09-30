---
spec: platform-harfanglab
version: "1.0"
schema_id: platform::harfanglab::1.0
status: normative
supersedes: null
---

# HarfangLab (`platform::harfanglab::1.0`)

## Summary

`configurations.harfanglab` is a HarfangLab detection rule, either a Sigma behavioural rule or a YARA scan rule. There is no query validator. The HarfangLab rule id is the Tide rule's `metadata.uuid` for both kinds. A block may carry both `sigma` and `yara`; deploy publishes the Sigma rule and does not publish the YARA rule in that case.

Shared fields are defined in [platforms](index.md#shared-platform-block).

## Requirements

- Static validation MUST NOT require `sigma` or `yara`. `maturity`, `confidence`, and `action` have defaults, so a block with only the shared fields validates.
- Deploy MUST fail unless `sigma` or `yara` is present.
- When both are present, deploy MUST publish `sigma` and MUST NOT publish `yara`.
- A `sigma` object MUST include `logsource.category`, `logsource.product`, `selections`, and `condition` for static validation. Each selection MUST include `name`, `field`, and `value`. The HarfangLab loader supplies an empty `selections` list when that key is omitted, so registry load accepts a Sigma block the validator rejects.
- A `yara` object MUST include `meta.context`, `meta.os`, `strings`, and `condition`.
- `action` SHOULD be `Alert`, `Alert & Block`, or `Alert, Block & Quarantine`. Any other string deploys as `alert`.
- `maturity` SHOULD be `Stable`, `Testing`, or `Experimental`. Any other string deploys as `experimental`.
- `confidence` SHOULD be `Weak`, `Moderate`, or `Strong`. Any other string deploys as `moderate`.
- `rule_id_bundle` MAY be present. The current deployer does not read it.

## Definition

### Block

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `maturity` | string | optional | `Experimental` | Rule maturity. Mapped to HarfangLab `hl_status`. |
| `confidence` | string | optional | `Moderate` | Analyst confidence. Mapped to `rule_confidence_override`. |
| `action` | string | optional | `Alert` | What the agent does on a match. Mapped to `global_state`. |
| `tags` | list[string] | optional | null | Sigma tags, and the YARA `tags` meta line. |
| `sigma` | [HarfangLabSigma](#sigma-harfanglabsigma) | optional | null | Behavioural rule. Preferred when `yara` is also set. |
| `yara` | [HarfangLabYara](#yara-harfanglabyara) | optional | null | File or memory scan rule. |
| `rule_id_bundle` | map[string, string] | optional | null | Accepted. Not used for the HarfangLab id. |

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

Deploy builds a YARA rule. The rule name is the Tide rule `name` lowercased, with non-alphanumeric characters turned into `_`, and prefixed with `rule_` when it would start with a digit. Meta `id` is `metadata.uuid`.

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

### Deploy

| Block status strategy | HarfangLab result |
|-----------------------|-------------------|
| `DISABLEMENT` | Sigma rule disabled (`global_state: disabled`, `enabled: false`). A YARA rule is still created or updated with the `action` mapping. |
| `DELETION` | Sigma or YARA rule deleted by `metadata.uuid`. Sigma is chosen when both blocks are present. |
| any other | Create or update by `metadata.uuid`. |

The tenant `source_id` is sent with the rule. The tenant `type` (`Sigma` or `YARA`) selects which HarfangLab API the workspace is configured for; the block's `sigma` / `yara` keys select which compiler runs.

## Relationships

- [platforms](index.md) — shared fields, no query validation
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

Fixtures: [fixtures/platforms/harfanglab-sigma.yaml](../../fixtures/platforms/harfanglab-sigma.yaml), [fixtures/platforms/harfanglab-yara.yaml](../../fixtures/platforms/harfanglab-yara.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-09-30 | Initial field contract from the HarfangLab configuration model and deployer. |
