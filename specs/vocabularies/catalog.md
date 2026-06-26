---
spec: vocabulary-catalog
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Vocabulary catalog

## Summary

Index of canonical vocabulary files bundled with OpenTide. Each file lives in `vocabularies/` and is referenced by field path in object specs and metaschema `tide.vocab` keywords.

## Requirements

- The set of bundled vocabularies MUST match the files in `vocabularies/` at release time.
- Adding or removing a vocabulary MUST update this catalog and [CHANGELOG.md](../../CHANGELOG.md) via RFC.
- Each entry MUST validate per [format.md](format.md).
- Every listed vocabulary MUST declare a top-level `version`; the current baseline release for bundled vocabularies is `1.0`.

## Definition

| File | Name | Field | Version |
|------|------|-------|---------|
| `actors.vocab.toml` | Threat Actors | `actors` | `1.0` |
| `alert_severity.vocab.toml` | MDR Alert Severity | `alert_severity` | `1.0` |
| `att&ck.vocab.toml` | MITRE ATT&CK | `att&ck` | `1.0` |
| `att&ck.groups.vocab.toml` | MITRE ATT&CK Groups | `att&ck.groups` | `1.0` |
| `chaining_relations.vocab.toml` | Vector Chaining Relationship | `chaining_relations` | `1.0` |
| `collection.vocab.toml` | Data Collection | `collection` | `1.0` |
| `criticality.vocab.toml` | Criticality | `criticality` | `1.0` |
| `datasources.vocab.toml` | MITRE ATT&CK Data Sources | `datasources` | `1.0` |
| `detection.composition.vocab.toml` | Detection Composition Strategy | `detection.composition` | `1.0` |
| `detection.methodology.vocab.toml` | Detection Methodology | `detection.methodology` | `1.0` |
| `detection.types.vocab.toml` | Detection Types | `detection.types` | `1.0` |
| `efforts.vocab.toml` | NIST 800-61 Recoverability Efforts | `efforts` | `1.0` |
| `feasibility.vocab.toml` | Difficulty to Detect | `feasibility` | `1.0` |
| `impact.vocab.toml` | Impact | `impact` | `1.0` |
| `killchain.vocab.toml` | Unified Kill Chain | `killchain` | `1.0` |
| `level.vocab.toml` | Threat Level to Organization | `level` | `1.0` |
| `leverage.vocab.toml` | Leverage | `leverage` | `1.0` |
| `malapi.vocab.toml` | Malicious Window API | `malapi` | `1.0` |
| `maturity.vocab.toml` | Detection Maturity Level (DML-8) | `maturity` | `1.0` |
| `mitigations.vocab.toml` | MITRE ATT&CK Mitigations | `mitigations` | `1.0` |
| `objectives.vocab.toml` | Strategic Objectives | `objectives` | `1.0` |
| `pap.vocab.toml` | Permissible Action Protocol | `pap` | `1.0` |
| `resources.vocab.toml` | Adversary Resource Level | `resources` | `1.0` |
| `responders.vocab.toml` | Alert Handling Team | `responders` | `1.0` |
| `rsit.vocab.toml` | Reference Security Incident Classification Taxonomy | `rsit` | `1.0` |
| `scheduling.vocab.toml` | Rule Scheduling | `scheduling` | `1.0` |
| `sectors.vocab.toml` | Victim Industry Sector | `sectors` | `1.0` |
| `severity.vocab.toml` | Threat Severity | `severity` | `1.0` |
| `signal.entities.vocab.toml` | Signal Entities | `signal.entities` | `1.0` |
| `sophistication.vocab.toml` | Adversary Sophistication | `sophistication` | `1.0` |
| `stakeholders.vocab.toml` | Stakeholders to Notify | `stakeholders` | `1.0` |
| `surface.vocab.toml` | Threat Surface | `surface` | `1.0` |
| `tier.vocab.toml` | Threat Actor Tier | `tier` | `1.0` |
| `tlp.vocab.toml` | Traffic Light Protocol | `tlp` | `1.0` |
| `viability.vocab.toml` | Vector Viability | `viability` | `1.0` |
| `violation.vocab.toml` | Policy, mandate or governance violations | `violation` | `1.0` |

**Total:** 36 vocabulary files.

## Relationships

- [format.md](format.md) — TOML structure and sync interface
- Object specs — reference vocabularies by field name
- [metaschema-keywords.md](../metaschema-keywords.md) — `tide.vocab` binding

## Defaults & overrides

Vocabularies are not client-overridable. See [configuration.md](../configuration.md).

## Examples

```toml
# vocabularies/tlp.vocab.toml (excerpt)
name = "Traffic Light Protocol"
field = "tlp"
version = "1.0"
[[keys]]
id = "TLP:CLEAR"
name = "clear"
```

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-06-26 | Added vocabulary `version` visibility to catalog entries |
| 1.0 | 2026-06-25 | Initial catalog — 36 vocabularies from opentide bundle |
