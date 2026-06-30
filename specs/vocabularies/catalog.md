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

## Definition

| File | Name | Field |
|------|------|-------|
| `actors.vocab.toml` | Threat Actors | `actors` |
| `alert_severity.vocab.toml` | MDR Alert Severity | `alert_severity` |
| `att&ck.vocab.toml` | MITRE ATT&CK | `att&ck` |
| `att&ck.groups.vocab.toml` | MITRE ATT&CK Groups | `att&ck.groups` |
| `chaining_relations.vocab.toml` | Vector Chaining Relationship | `chaining_relations` |
| `collection.vocab.toml` | Data Collection | `collection` |
| `criticality.vocab.toml` | Criticality | `criticality` |
| `datasources.vocab.toml` | MITRE ATT&CK Data Sources | `datasources` |
| `detection.composition.vocab.toml` | Detection Composition Strategy | `detection.composition` |
| `detection.methodology.vocab.toml` | Detection Methodology | `detection.methodology` |
| `detection.types.vocab.toml` | Detection Types | `detection.types` |
| `efforts.vocab.toml` | NIST 800-61 Recoverability Efforts | `efforts` |
| `feasibility.vocab.toml` | Difficulty to Detect | `feasibility` |
| `impact.vocab.toml` | Impact | `impact` |
| `killchain.vocab.toml` | Unified Kill Chain | `killchain` |
| `level.vocab.toml` | Threat Level to Organization | `level` |
| `leverage.vocab.toml` | Leverage | `leverage` |
| `malapi.vocab.toml` | Malicious Window API | `malapi` |
| `maturity.vocab.toml` | Detection Maturity Level (DML-8) | `maturity` |
| `mitigations.vocab.toml` | MITRE ATT&CK Mitigations | `mitigations` |
| `objectives.vocab.toml` | Strategic Objectives | `objectives` |
| `pap.vocab.toml` | Permissible Action Protocol | `pap` |
| `resources.vocab.toml` | Adversary Resource Level | `resources` |
| `responders.vocab.toml` | Alert Handling Team | `responders` |
| `rsit.vocab.toml` | Reference Security Incident Classification Taxonomy | `rsit` |
| `scheduling.vocab.toml` | Rule Scheduling | `scheduling` |
| `sectors.vocab.toml` | Victim Industry Sector | `sectors` |
| `severity.vocab.toml` | Threat Severity | `severity` |
| `signal.entities.vocab.toml` | Signal Entities | `signal.entities` |
| `sophistication.vocab.toml` | Adversary Sophistication | `sophistication` |
| `stakeholders.vocab.toml` | Stakeholders to Notify | `stakeholders` |
| `surface.vocab.toml` | Threat Surface | `surface` |
| `tier.vocab.toml` | Threat Actor Tier | `tier` |
| `tlp.vocab.toml` | Traffic Light Protocol | `tlp` |
| `viability.vocab.toml` | Vector Viability | `viability` |
| `violation.vocab.toml` | Policy, mandate or governance violations | `violation` |

### Deprecated (removed)

The following threat-scoping vocabularies were superseded by `surface.vocab.toml` and MUST NOT be used on `threat::1.0` objects:

| Former file | Field | Replacement |
|-------------|-------|-------------|
| `domains.vocab.toml` | `domains` | `threat.terrain` → `surface::1.0` |
| `platforms.vocab.toml` | `platforms` | `threat.terrain` → `surface::1.0` |
| `targets.vocab.toml` | `targets` | `threat.terrain` → `surface::1.0` |

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
[[keys]]
id = "TLP:CLEAR"
name = "clear"
```

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial catalog — 36 vocabularies from opentide bundle |
