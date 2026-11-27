# RFC 0012: Rules should read like the other objects

- **RFC:** 0012
- **Title:** Rules should read like the other objects
- **Author:** opentide maintainers
- **Status:** draft (revision 6, open for comments)
- **Created:** 2026-09-30
- **Revised:** 2026-11-27. Revisions 4 to 6 rewrite the October draft against opentide 1.0 (the Rust core, thirteen platforms). After four rounds of maintainer review it now covers:
  - an identity-only root
  - one `rule` block, with platform blocks grouped under `rule.detection`
  - severity on each platform block
  - one `signals` list
  - `mitre_attack`
  - a `fidelity` block for false positives and blind spots
  - an `analysis` block: how to work out whether an alert is real, as ordered steps with typed, validated and runnable searches
- **Issue:** [opentidehq/specifications#24](https://github.com/opentidehq/specifications/issues/24)
- **Implementation plan:** [opentide `docs/internal/rule-2.0.md`](https://github.com/opentidehq/opentide/blob/claude/wonderful-faraday-n0gfwa/docs/internal/rule-2.0.md). The earlier tracker, opentidehq/opentide#394, was closed because it described the retired Python code.

## Summary

A threat file keeps its content in a `threat:` block, and an objective file keeps its content in an `objective:` block. A rule file has neither. Its content is spread over the root, a `configurations:` wrapper, and a `response.procedure` tree that mixes alert severity, team, prose and hunt queries.

A `rule::2.0` file is an envelope (`name`, `metadata`, `references`) plus one `rule:` block with these parts:

- **What the rule detects:** `description`, `signals`, `mitre_attack`.
- **How far to trust it:** `fidelity` (false positives and blind spots, as structured entries).
- **How to analyse its alerts:** `analysis`, ordered steps a person or an agent follows. Each step gives the searches that answer it and what each verdict looks like.
- **How it is implemented:** `detection`, one block per platform. Each block carries its own operational state: `enabled`, `status` and `severity`.

`rule::1.0` and `rule::1.1` files keep their layout and keep working ([versioning 1.1](../specs/versioning.md)). One explicit command moves a file to 2.0.

## Motivation

**Three shapes.** Threats and objectives put the name and metadata outside, and their content in a block named after the object. Rules do not.

**Operational state in two places.** Deploy reads `configurations.<platform>.status`, which opentide 1.0 requires on every block. A root `status` also exists, and only sharing and one MCP tool read it, as a fallback. Severity is split three ways:

- Ten of the thirteen platform blocks have their own severity or priority field: Sentinel and Microsoft Defender `alert.severity`, SentinelOne and CrowdStrike `details.severity`, and `severity` or `priority` on Elastic, Sysdig, Bitdefender, Graylog, Exabeam and Google SecOps. Each falls back to `response.alert_severity`.
- Splunk, Carbon Black Cloud and HarfangLab read `response.alert_severity` directly.
- MISP's threat level reads a third value, the root `severity`.

A rule is not "High". Its Sentinel analytics rule can be High while its noisier Splunk search is Low.

**Three technique policies.** Most platforms send the block's own technique list, else the techniques inherited through `detection_model`, and never read the root `techniques`. Splunk correlation searches and Elastic merge the root list with the inherited one. MISP sends the root list only. Threats and objectives name the field `mitre_attack`.

**One link, one target.** `detection_model` holds one UUID, of an objective or a signal. A rule that implements two signals, possibly of two objectives, cannot say so.

**A response that is a bag.** `response` holds deployment data (`alert_severity`), routing (`responders`), a playbook link, and a `procedure` with free prose (`analysis`, `containment`) and `searches`.

- A search names its target in free text (`system: Microsoft Sentinel`), which the documentation renderer matches loosely to guess a language.
- A search has no question it answers, no inputs and no time window.
- It cannot be run by name.
- Nothing ties it to the alert it serves.

**Nowhere to say when a rule is wrong.** There is no place for known false positives or blind spots. The Elastic and HarfangLab blocks each grew their own `false_positives` strings.

**"Configuration" means two things.** It names the workspace's TOML under `.opentide/configurations/` and also the per-platform detection inside a rule.

## Research

How established practice places these concerns, and what this RFC takes from each:

| Source | Where investigation searches live | False positives and blind spots | Taken here |
|---|---|---|---|
| [Splunk Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/investigations/investigate-findings-using-drilldown-searches-and-dashboards-in-splunk-enterprise-security) detections | In the detection: `drilldown_searches`, a list of a name, a search and an earliest and latest offset around the finding's time, with `$field$` tokens from the finding. Since ES 8.1, two drilldowns of one detection cannot share a name. | `known_false_positives` (text) in the content's detection YAML | Searches belong to the rule, attached to its alert. They have a unique name, parameters bound from the alert, and a time window around it. |
| [Elastic Security](https://www.elastic.co/docs/solutions/security/detect-and-alert/write-investigation-guides) rules | In the investigation guide (`note`): query buttons (`!{investigate{…}}`) whose values come from alert fields (`{{kibana.alert.…}}`) | `false_positives` (list of strings) | Searches sit inside the analysis guidance, and their inputs come from the alert. |
| [Palantir's ADS framework](https://github.com/palantir/alerting-detection-strategy-framework) | Response is a section of the detection strategy | "Blind Spots and Assumptions", "False Positives", and "Validation" are separate sections that must be complete before production | A parent block for how far to trust the rule, and the analysis as part of the rule |
| [RE&CT](https://github.com/atc-project/atc-react) (Atomic Threat Coverage) | Response actions grouped by incident-response stage (preparation, identification, containment, eradication, recovery, lessons learned). Detection rules link to response playbooks. | — | Not taken: containment and recovery are incident response, which playbooks own, not a rule |
| Sigma | none | `falsepositives` (list of strings) | — |

The pattern is consistent. A rule's searches are run because the rule fired, take the alert's values as input, and answer a question about that alert. They belong in the rule's analysis guidance, attached to the question they answer. What happens after the alert is confirmed (containment, eradication, recovery) is incident response, owned by playbooks, not by the rule. Proactive hunts, run without an alert, are not part of a rule either. They stay with the objective's signals (`examples`) or a future hunting object, and are out of scope here.

## Detailed design

### Affected specs

- New: `specs/objects/rule-2.0.md`.
- Changed:
  - `specs/objects/rule-1.0.md`, `rule-1.1.md` (history notes; still normative)
  - `specs/metadata.md`
  - `specs/platforms/index.md` and the severity sections of each platform spec
  - `specs/sharing.md`, `specs/sharing/misp-1.0.md`
  - `specs/deployment.md`
  - `specs/validation.md`
  - `specs/metaschema-keywords.md`
  - `specs/objects/objective-1.0.md` and `objective-1.1.md` (drift, below)
- New vocabularies: `fidelity.frequency`, `fidelity.blind_spot`.
- Pins: a `["rule::2.0"]` section in `schemas/pins/rule.toml`.

### The document

```yaml
name: LSASS memory read by an unsigned process
metadata:
  uuid: 6d1c8a52-3f0e-4c1b-9a77-2b8e5d4f1a90
  schema: rule::2.0
  version: 3
  created: "2026-01-12"
  modified: "2026-11-20"
  reviewed: "2026-11-20"
  tlp: amber
  contributors: [j.doe]
references:
  public:
    1: https://attack.mitre.org/techniques/T1003/001/
rule:
  description: |
    An unsigned process opens a handle to lsass.exe with VM_READ access.
  signals:
    - 7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d   # a signal of the credential-access objective
    - 2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f   # a signal of the defence-evasion objective
  mitre_attack: [T1003.001]
  fidelity:
    false_positives:
      - name: Backup and endpoint agents
        description: Backup software and some EDR agents read LSASS memory on a schedule.
        frequency: common
        identify: The process is signed by the vendor and runs from its install directory.
        tuning: Excluded per tenant by signer in the Sentinel exclusions.
    blind_spots:
      - name: Access through a signed vulnerable driver
        description: A kernel driver reads LSASS memory without opening a process handle.
        kind: evasion
        covered_by: [9b8a7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d]   # the vulnerable-driver load rule
        mitigations: [M1038]
  analysis:
    responders: soc-l2
    summary: |
      A process read LSASS memory. Most alerts are backup or EDR agents; rule those out first.
    steps:
      - question: Is the reading process a known agent?
        guide: Check who signed the process and where it runs from.
        searches:
          - name: Signer and path of the reader
            platform: microsoft_defender
            parameters:
              device: Host::Hostname
              process: Host::Process
            window: {before: PT1H, after: PT15M}
            query: |
              DeviceProcessEvents
              | where DeviceName == {{device}} and FileName == {{process}}
              | project Timestamp, FolderPath, ProcessVersionInfoCompanyName, InitiatingProcessFileName
        verdicts:
          benign: Signed by a backup or EDR vendor, running from its install directory.
          malicious: Unsigned, or running from a user-writable path.
        false_positive: Backup and endpoint agents
      - question: Did the same binary run on other hosts?
        searches:
          - name: Same binary elsewhere
            platform: microsoft_defender
            parameters:
              sha256: Host::File Hash
            window: {before: P7D}
            query: |
              DeviceProcessEvents
              | where SHA256 == {{sha256}}
              | summarize by DeviceName
        verdicts:
          suspicious: Other hosts ran it in the last week.
  detection:
    sentinel:
      enabled: true
      status: STAGING
      severity: High
      query: |
        DeviceEvents
        | where ActionType == "OpenProcessApiCall"
        | where FileName =~ "lsass.exe"
      scheduling:
        frequency: PT1H
        lookback: PT2H
      alert:
        title: LSASS memory read
        suppression: false
    splunk:
      enabled: true
      status: DEVELOPMENT
      severity: Medium
      query: |
        index=edr EventCode=10 TargetImage="*lsass.exe"
```

### The anatomy of a rule

| Part | Question it answers | 2.0 | 1.x |
|---|---|---|---|
| Identity | Which object is this? | root: `name`, `metadata`, `references` | the same |
| Intent | What does it detect, and why? | `rule.description`, `rule.signals`, `rule.mitre_attack` | root `description`, `techniques`, `detection_model` |
| Fidelity | When is it wrong, and what can it not see? | `rule.fidelity` | none (two platform blocks improvise) |
| Analysis | Is this alert real? Who looks, what do they check, and what does each answer mean? | `rule.analysis` | `response`, `response.procedure` |
| Implementation | How is it expressed on each platform? | `rule.detection.<platform>`: the payload | `configurations.<platform>` |
| Operation | Is it live, where, and how loud? | `rule.detection.<platform>`: the envelope (`enabled`, `status`, `severity`, `tenants`, `flags`) | root `status` and `severity`, `response.alert_severity`, block `status` |

### The root

The root of a `rule::2.0` file holds `name`, `metadata` and optional `references`, and nothing else.

| Key | Kept because |
|---|---|
| `name` | Every object names itself the same way. Deploy uses it as the default display name, and lint checks file names against it. |
| `metadata` | Identity, revision, dates, TLP and authorship, shared by all objects. |
| `references` | Provenance of the object, the same `ObjectReferences` as on threats and objectives. Sharing and exports read it in one place for every family. |

The root MUST NOT carry `description`, `status`, `severity`, `techniques`, `mitre_attack`, `detection_model`, `signals`, `response`, `analysis`, `configurations`, `platforms` or `file`. Those keys identify a 1.x file. The error names the 2.0 path, for example "`configurations` is not a `rule::2.0` key; platform blocks are keys of `rule.detection`".

### The `rule` block

| Field | Required | Default | Meaning |
|---|---|---|---|
| `description` | yes | — | What the rule detects and how. Markdown. |
| `signals` | no | `[]` | UUIDs of the objectives and signals the rule implements ([Signals](#signals)). |
| `mitre_attack` | no | `[]` | ATT&CK technique ids, `att&ck::1.2`, as on threats and objectives ([ATT&CK](#attck)). |
| `fidelity` | no | — | False positives and blind spots ([Fidelity](#fidelity)). |
| `analysis` | no | — | How to work out whether an alert is real ([Analysis](#analysis)). |
| `detection` | no | — | One block per platform the rule is implemented on ([Detection](#detection)). |

Unknown keys MUST fail. The set of `rule` fields is closed; the set of platforms is open, and lives in `detection`.

A rule with no `detection`, or an empty one, is a valid draft.

### Signals

`rule.signals` is a list of UUIDs. Each entry MUST name an objective, or a signal defined under an objective, in the workspace; otherwise the entry is `invalid_ref`, as for `detection_model` today. An objective stands for all of its effective signals. Entries MAY name signals of different objectives.

| Listed | The rule covers |
|---|---|
| nothing | nothing (a draft) |
| an objective | that objective, fully (as `detection_model: <objective>` on 1.x) |
| a signal | that signal, and its owning objective partially (as `detection_model: <signal>` on 1.x) |
| several | the union. Each objective reached only through some of its signals is covered partially, and reports list the via-signal UUIDs. |

A UUID listed twice is `duplicate_signal`. A signal listed beside its own objective adds nothing and gets the hint `signal_covered_by_objective`. With signal reuse ([RFC 0011](0011-signal-reuse.md)), indirect coverage starts from the listed signals, plus every effective signal of each listed objective.

Completion offers objectives and signals together, as the `objective` model vocabulary does for `detection_model` today. A signal is labelled `{objective name}::{signal name}`.

### ATT&CK

The techniques a platform sends, sharing publishes and coverage counts follow one policy:

1. A block's own technique list (for example `sentinel.alert.techniques`), when it is non-empty, for that platform.
2. Else `rule.mitre_attack`, when it is non-empty.
3. Else the techniques inherited through `rule.signals`: for each listed objective, and for each listed signal's owning objective, its `mitre_attack`, else its threats' techniques. Duplicates are removed, and the order of `signals` is kept.

Explicit beats inherited, and the lists are never merged. A rule usually detects a narrower set than its objectives, so merging would overclaim coverage.

### Fidelity

`rule.fidelity` says how far to trust the rule. False positives are where it fires on benign activity (precision). Blind spots are where it stays silent on malicious activity (recall). Both are lists of structured entries, so that triage, tuning, coverage reports and platforms can use them, not only people reading prose.

#### `fidelity.false_positives[]`

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Short label, unique among the rule's false positives. |
| `description` | no | What benign activity triggers the rule. Markdown. |
| `frequency` | no | `common`, `occasional` or `rare` (`fidelity.frequency::1.0`). |
| `identify` | no | How an analyst recognises it during triage. Markdown. |
| `tuning` | no | How it is excluded, or could be. Markdown. |
| `platforms` | no | Platform identifiers where it occurs. Default: every platform of the rule. Each entry MUST be a registry platform. |

The Elastic and HarfangLab blocks have their own `false_positives` (lists of strings). When a block sets none, deploy sends the `name` of each false positive that applies to that platform. Documentation renders the full entries. An analysis step names the false positive its `benign` verdict identifies, so `identify` is read next to the evidence that settles it.

#### `fidelity.blind_spots[]`

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Short label, unique among the rule's blind spots. |
| `description` | no | What the rule cannot see, or assumes. Markdown. |
| `kind` | no | `evasion` (an adversary can avoid it), `visibility` (the data does not show it), or `assumption` (it holds only if something else holds, such as an agent running), from `fidelity.blind_spot::1.0` |
| `covered_by` | no | UUIDs of rules or signals that detect what this rule misses. Each MUST resolve in the workspace (`invalid_ref`). |
| `mitigations` | no | ATT&CK mitigation ids (`mitigations::1.0`) that prevent the gap from being exploited. |

`covered_by` becomes a `compensates` edge in the catalogue, so coverage reports can show a technique as covered with a known gap and a compensating detection. A blind spot with no `covered_by` and no `mitigations` is an open gap, and reports list it.

### Analysis

`rule.analysis` is how to work out whether an alert from this rule is real. It is one object, written for a person and an agent alike: a short summary, then ordered steps. Each step asks one question, gives the searches that answer it, and says what each answer means. Containment, remediation and other incident response are out of scope: they belong to the playbooks and the case-management tooling that take over once the alert is confirmed.

| Field | Required | Meaning | 1.x |
|---|---|---|---|
| `responders` | no | The team that analyses the alert: a `[[responders]]` name from `deployment.toml`, defaulted from `[deployment] default_responders` | `response.responders` |
| `summary` | no | What an alert means and how to approach it. Markdown. | `response.procedure.analysis` |
| `steps` | no | The ordered questions to answer ([Steps](#steps)) | `response.procedure.searches`, one step per search |

An `analysis` with neither `summary` nor `steps` is `empty_analysis`.

Elastic sends `summary` and the steps, rendered as Markdown with their searches as code blocks, as the investigation guide (Kibana `note`), unless the block sets `guide.investigation`. Documentation renders the same.

#### Steps

| Field | Required | Meaning |
|---|---|---|
| `question` | yes | What this step establishes, as a question. Unique among the rule's steps. |
| `guide` | no | How to answer it. Markdown. |
| `searches` | no | Queries that answer it ([Searches](#searches)). When there are several, they are alternatives on different platforms: run the one for the platform you work in. |
| `verdicts` | no | What each answer means: `benign`, `suspicious` and `malicious`, each a Markdown description of the evidence. At least one when present. |
| `false_positive` | no | The `name` of the `fidelity.false_positives` entry that a `benign` verdict at this step identifies. It MUST name one (`unknown_false_positive`). |

A step with neither `guide` nor `searches` is `empty_analysis_step`.

Steps are read in order, and a decisive verdict ends the analysis. That is how an analyst works through an alert, and it is what lets an agent follow the same procedure: run each step's search with the alert's values, compare the result with the verdicts, and stop or go on. Branching between steps is not part of this revision.

#### Searches

A search is a query that someone analysing the alert runs. Its inputs come from the alert.

| Field | Required | Meaning | 1.x |
|---|---|---|---|
| `name` | yes | Unique across the rule. It is the search's handle (`opentide query --rule <uuid> --search "<name>"`). | `purpose` |
| `description` | no | What the result shows. Markdown. | none |
| `platform` | yes | A platform identifier from the registry: where the search runs, and so its language. | `system` (free text) |
| `language` | no | Required when the platform has several query languages (Elastic: `kuery`, `lucene`, `eql`, `esql`). MUST NOT be set otherwise. | `language` |
| `parameters` | no | A map of parameter name to entity type, a `signal.entities::1.0` value (`Host::Hostname`, `Host::File Hash`, `Cloud::Account`). | none |
| `window` | no | The time range around the alert's time: `before` and `after`, ISO 8601 durations. Default: the platform's own default range. | none |
| `query` | yes | The query. `{{name}}` stands for a parameter's value. | `query` |

A placeholder stands for one complete literal value of the query's language, so it is written without quotes (`where DeviceName == {{device}}`). Whoever runs the search substitutes a literal quoted and escaped for that language. A value can never change the query's structure.

**Validation.** `opentide validate` checks every search:

| Code | Severity | When |
|---|---|---|
| `search_platform_unknown` | error | `platform` is not in the registry |
| `search_platform_not_enabled` | warning | the workspace has not enabled `platform` |
| `search_language_required`, `search_language_not_allowed` | error | `language` is missing on a multi-language platform, or set on a single-language one |
| `search_name_duplicate` | error | two searches of the rule share a `name` |
| `search_parameter_undeclared` | error | the query uses `{{x}}` and `parameters` has no `x` |
| `search_parameter_unused` | warning | a declared parameter is never used |
| `search_parameter_type` | error | a parameter's type is not a `signal.entities` value |
| `search_window_invalid` | error | `before` or `after` is not a positive ISO 8601 duration |
| the platform engine's codes | as today | the query, with each placeholder replaced by a literal of its language, fails the offline check of the platform's language |

`opentide validate query --live` also sends searches, placeholders substituted the same way, to the tenants of platforms that have a live check.

**Running.** `opentide query --rule <uuid> --search "<name>" --param device=WS-0142 --at <alert time>` substitutes the parameters, applies `window` around `--at`, and runs the search on the platform's tenant. The MCP server exposes the analysis as data (steps, searches, verdicts), and its `run_query` tool takes the same inputs. An agent working an alert can therefore follow the steps with the alert's values.

**Platforms.** Splunk detections MAY receive the searches whose `platform` is `splunk` as `drilldown_searches`: the `name`, the query with `{{x}}` written as `$x$`, and `window` as the earliest and latest offsets. That export is an implementation choice and is not required by this RFC.

### Detection

`rule.detection` maps a platform identifier to that platform's block. Its keys MUST be platforms of the registry, or platforms a loaded plugin declares; any other key is an unknown key that names the registry's platforms. Order is the author's and has no meaning.

Grouping the blocks under one key keeps the `rule` block's own fields a closed set while the platforms grow with the registry and with plugins, so neither can shadow the other. Every consumer that walks the platforms (deploy, promotion, sharing, documentation, the outline, query validation) reads one map.

#### Platform blocks

A platform block has two parts:

- **The envelope:** the fields every platform shares, defined by this rule revision.
- **The payload:** the platform's own fields, defined by its platform schema (`platform::sentinel::1.0` and the others), unchanged.

Because the envelope belongs to the rule revision, adding `severity` touches no platform schema, and a payload revision never restates the envelope.

| Envelope field | Required | Meaning | 1.x |
|---|---|---|---|
| `enabled` | no, `false` | Whether this block takes part in deployment | same |
| `status` | yes | A deployment status from `deployment.toml` | same. opentide 1.0 already requires it, and the 1.x spec catches up. |
| `severity` | yes | `alert_severity::1.0`: the severity of this platform's alerts | `response.alert_severity`, shared by every block |
| `tenants` | no | Tenants this block deploys to. Default: every tenant of the platform that is not `manual` and accepts the status's strategy. | same |
| `flags` | no | Labels that `[[modifiers]]` conditions in platform configuration match | same |
| `name` | no | Display name on this platform. Default: the root `name`. | same |
| `schema` | no | The payload's schema: `platform::<key>::<major>.<minor>`, a registered revision of that key's family. Default: the newest. Legacy identifiers (`sentinel::2.4`) are refused. | legacy ids accepted |

The 1.x envelope's `contributors` is not part of 2.0. Authorship is `metadata.author` and `metadata.contributors`.

**Severity on the block.** The envelope `severity` is on opentide's scale. A payload field that carries the vendor's own severity or priority stays valid and wins for that vendor. Examples are Sentinel's `alert.severity`, Falco's eight-level `priority`, Elastic's severity overrides and Google SecOps `priority`. When the vendor field is unset, deploy derives it from the envelope `severity`, with the mapping each platform spec already defines for `response.alert_severity`. Splunk, Carbon Black Cloud and HarfangLab read `severity` directly.

**The rule's severity is derived, never authored.** It is the highest `severity` among enabled blocks, or `Informational` with no enabled block. Sharing (MISP `threat_level_id`), documentation and catalogue sorting use it.

A new platform is a new optional key of `detection` and does not bump `rule::2.0`. Blocks carry no external ids ([RFC 0010](0010-deployment-external-ids.md)). Deployment-state shards are keyed by `metadata.uuid`, so moving a block does not touch `.opentide/states/deployment/`.

### Status outside deploy

A `rule::2.0` rule matches a sharing block's `rule_statuses` when at least one enabled platform block has a status in the list. Blocks for platforms the workspace has not enabled count. A rule with no enabled block matches nothing. The MCP `deployment_status` tool reads block statuses only. 1.x files keep the root-status fallback ([sharing.md](../specs/sharing.md) 1.2).

### Pins

```toml
["rule::2.0"]
"metadata.tlp" = "tlp::1.0"
"rule.mitre_attack" = "att&ck::1.2"
"rule.fidelity.false_positives.frequency" = "fidelity.frequency::1.0"
"rule.fidelity.blind_spots.kind" = "fidelity.blind_spot::1.0"
"rule.fidelity.blind_spots.mitigations" = "mitigations::1.0"
"rule.analysis.steps.searches.parameters.*" = "signal.entities::1.0"
"rule.detection.<platform>.severity" = "alert_severity::1.0"   # one row per platform in the file
```

`rule.signals` binds the `objective` model vocabulary (objectives, and every signal defined under one). `rule.fidelity.blind_spots.covered_by` binds the rule and signal model vocabularies. `rule.analysis.responders` binds `tide.config.responders`, as on 1.x.

### Migrating a file

`opentide migrate rule` moves `rule::1.0` and `rule::1.1` files to `rule::2.0`. It is a dry run unless `--apply` is given. Opening, validating or deploying a 1.x file never rewrites it.

| 1.x | 2.0 | Needs a person when |
|---|---|---|
| `description` | `rule.description` | never |
| `detection_model: X` | `rule.signals: [X]` | never |
| `techniques` | `rule.mitre_attack` (omitted when empty) | never |
| `response.alert_severity` (or root `severity` without a `response`, or `Informational`) | `severity` on every platform block | a root `severity` that differs from `response.alert_severity` is reported: MISP's threat level changes |
| `response.responders` | `rule.analysis.responders` | never |
| `response.playbook` | `references.internal.playbook` | never (reported) |
| `response.procedure.analysis` | `rule.analysis.summary` | never |
| `response.procedure.containment` | appended to `rule.analysis.summary` under a "Containment" heading, so nothing is lost | never (reported: move it to the playbook) |
| `response.procedure.searches[i]` | `rule.analysis.steps[i]`: `question` = `purpose`, with one search: `name` = `purpose` (made unique with a suffix), `platform` from `system`, `language` and `query` kept, no parameters | a `system` that names no platform (`SIEM`, `EDR console`): the file is left unchanged (exit 2, `needs_human_decision`) |
| `configurations.<p>`, or `platforms.<p>` when it is the only copy | `rule.detection.<p>` | the same platform in both: refused |
| a block's `contributors` | merged into `metadata.contributors` | never (reported) |
| a legacy block `schema` | `platform::<p>::1.0` | never |
| root `status` | removed | a rule with no enabled block is reported: it stops matching `rule_statuses` |
| `file` | removed | never (reported) |
| `metadata.reviewed`, `version`, `modified` | unchanged | never |

The migration writes no `fidelity`, and it writes no parameters, windows or verdicts. 1.x has nothing to derive them from. It refuses a file that fails validation as declared, so it never turns an invalid 1.x file into a different invalid 2.0 file.

The rewrite preserves text:

- Root entries move under an inserted `rule:` with two more spaces of indentation, and their comments move with them. A block scalar keeps its content, because every line gains the same indentation.
- `configurations:` becomes `detection:` and moves under `rule:` like the other root entries, so each platform block gains the same two spaces of indentation and keeps its content. One `severity:` line is inserted after `status:`.
- Keys are renamed in place.
- Each rewritten file is parsed again and compared with the intended document. A file that differs is left unchanged.
- BOM, line endings, quoting and key order are kept.

Migration is forward-only and idempotent.

### Other specs that name rule fields

- `specs/metadata.md`: `metadata.reviewed` is defined for `rule::1.1` and `rule::2.0`.
- `specs/platforms/index.md`: the block envelope for 2.0 is defined here, and a block lives at `rule.detection.<platform>`. Each platform spec's severity section names the envelope `severity` as the default for its native field. The Elastic and HarfangLab specs name `fidelity.false_positives` as the default for their `false_positives`.
- `specs/sharing.md`, `specs/sharing/misp-1.0.md`:
  - the status match above
  - relations from `rule.signals`
  - `threat_level_id` from the derived rule severity
  - techniques by the ATT&CK policy
- `specs/deployment.md`: promotion rewrites block statuses (`configurations.*` on 1.x, `rule.detection.*` on 2.0).
- `specs/validation.md`: the codes above.
- `specs/metaschema-keywords.md`: model vocabularies for `signals` and `covered_by`.
- `specs/objects/objective-1.0.md` and `objective-1.1.md`: drop the top-level `composition`, which opentide 1.0 already reports as an unknown key. This fixes spec drift in the same change, because this RFC is about objects reading alike.
- [RFC 0011](0011-signal-reuse.md): direct coverage of a `rule::2.0` file is `rule.signals`.

### Fixtures

- Valid:
  - a full rule (the example above)
  - a draft with no block
  - signals across two objectives
  - an Elastic search with `language`
  - a search with parameters and a window
- Invalid:
  - each root key a 1.x file has
  - a block without `status` or `severity`
  - `response.alert_severity`
  - a block `contributors`
  - a legacy block `schema`
  - each search code above
  - an empty analysis, an empty step, an unknown `false_positive`
  - a `covered_by` that resolves to nothing
  - a false positive with an unknown platform
- Migration: 1.0 and 1.1 inputs with their 2.0 outputs. They cover comments, block scalars, a severity conflict, searches, legacy `platforms`, and a `system` that needs a person.

## Drawbacks

Two layouts exist until people migrate. Every consumer reads both, as the versioning spec requires.

`severity` is written once per block instead of once per rule. That cost is the point: the platforms can disagree on purpose.

A search sits one level deeper than on 1.x (`analysis.steps[].searches[]` instead of `response.procedure.searches[]`), and placeholders add a small syntax to query text. In return, every search answers a stated question, and is checked, runnable and tied to the alert.

A rule no longer carries containment guidance or a playbook field. Migration keeps both (the prose in the summary, the link in `references`) and reports them, so a team can move them to its playbooks.

A rule that relied on the root `severity` for its MISP threat level, or on Splunk's or Elastic's merge of techniques, changes payload when migrated. The migration report lists each one.

## Alternatives

- **Rename `configurations` only.** Rules stay the odd object, and severity, status and searches stay where they are.
- **Platform keys directly on `rule`** (revisions 2 to 4 of this RFC). One level less, but it mixes the rule's closed set of fields with an open set of platforms that grows with the registry and with plugins. It needs a rule that no platform may be named like a field, editor completion offers both kinds of key at once, and plugin platforms would force the `rule` block open to unknown keys.
- **One rule-level severity that blocks override.** Two sources of truth again, which this RFC removes for status.
- **Only the vendors' native severity fields.** Splunk, Carbon Black and HarfangLab would need new payload fields, and sharing would need an inverse mapping from thirteen vendor scales.
- **`objective` plus `signals` fields.** Cannot link a rule to signals of several objectives.
- **Searches as a sibling of the guidance (revision 3 of this RFC).** Searches are run because the rule fired and answer a question about the alert. Separated from that question, they lose the reason they exist.
- **A response by stage: triage, investigation, containment, remediation, with typed actions (revisions 4 and 5 of this RFC).** It spread one procedure over four objects and turned the rule into an incident-response playbook. Containment and recovery depend on the asset, the incident and the organisation, not on the rule that fired. The rule's job is to say how to judge its alert.
- **`false_positives` and `blind_spots` as strings on `rule`.** Cheaper, but triage, tuning and coverage could not use them, and a compensating detection could not be linked.

## Unresolved questions

- **The name of the parent block.** `fidelity` (precision and recall: false positives and blind spots), `limitations`, or `assessment`?
- **A third `fidelity` child, `validation`.** The ADS framework requires true-positive validation. A sketch: `validation[]` with `name`, `method` (manual, or an emulation test reference), and the platforms expected to alert. Add it now, or in a later additive change?
- **Branching steps.** Should a verdict be able to name the next step, or is an ordered list with a decisive verdict enough?
- **The playbook link.** Is `references.internal.playbook` the right home for 1.x `response.playbook`, or should `analysis` keep a `playbook` field as the hand-off once an alert is confirmed?
- **Splunk drilldown export.** Should the platform spec make it a SHOULD?
- **`metadata.reviewed` on threats and objectives,** and the root `criticality` on threats: for their next revisions, not this one.

## Resolved in review

1. `opentide new`, `extract` and the MCP rule template follow the newest revision. The registry is not flipped until every consumer reads 2.0.
2. Sharing matches any enabled block, including blocks for platforms the workspace has not enabled.
3. The link is one `signals` list that names objectives or signals, across objectives.
4. `techniques` becomes `mitre_attack`, inside `rule`.
5. `enabled` stays on blocks.
6. Severity belongs to each platform block. The rule's severity is derived.
7. Searches belong to the analysis, attached to the question they answer.
8. 1.x is "superseded", not "deprecated", in the release that ships 2.0. `validate` adds a `rule_revision_superseded` hint. 1.x keeps validating and deploying.
9. Platform blocks are grouped under `rule.detection`, not flat on `rule`.
10. The rule says how to analyse its alert, in one `analysis` object. Containment and remediation are not part of a rule.

## References

- [opentidehq/specifications#24](https://github.com/opentidehq/specifications/issues/24)
- [specs/versioning.md](../specs/versioning.md) 1.1
- [RFC 0008](0008-rule-reviewed-date.md), [RFC 0010](0010-deployment-external-ids.md), [RFC 0011](0011-signal-reuse.md), [RFC 0021](0021-defender-graph-beta-detection-rules.md)
- [Splunk Enterprise Security: drilldown searches](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/investigations/investigate-findings-using-drilldown-searches-and-dashboards-in-splunk-enterprise-security)
- [Elastic Security: write investigation guides](https://www.elastic.co/docs/solutions/security/detect-and-alert/write-investigation-guides)
- [Palantir: Alerting and Detection Strategy framework](https://github.com/palantir/alerting-detection-strategy-framework)
- [RE&CT](https://github.com/atc-project/atc-react)
- [opentide implementation plan](https://github.com/opentidehq/opentide/blob/claude/wonderful-faraday-n0gfwa/docs/internal/rule-2.0.md)
