# RFC 0012: Rules should read like the other objects

- **RFC:** 0012
- **Title:** Rules should read like the other objects
- **Author:** OpenTide maintainers
- **Status:** draft
- **Created:** 2026-09-30
- **Revised:** 2026-10-19 (renumbered from 0008; aligned with `rule::1.1`, retired `responders` vocabulary, Elastic, and RFC 0010)
- **Issue:** [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- **PR:** [#25](https://github.com/OpenTideHQ/specifications/pull/25)
- **Implementation:** [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)

## Summary

A threat file has a `threat:` block. An objective file has an `objective:` block. A rule file does not. Its description, severity, techniques, objective link, and response sit on the document root, and the actual detections sit under a `configurations:` wrapper (with a leftover `platforms:` map beside it).

`rule::2.0` puts the detection in a `rule:` block and places each platform directly on that block. Platform payloads stay as they are. Deployment status stays on the platform, which is where deploy already reads it. The link to an objective is named `objective`.

Files that still say `rule::1.0` or `rule::1.1` keep today's layout. Both shapes have to validate, deploy, and survive every other feature; that requirement is [versioning 1.1](../specs/versioning.md) ([#27](https://github.com/OpenTideHQ/specifications/pull/27)), not this proposal. This RFC does not redesign Sentinel, Splunk, or any other platform.

## Motivation

Authors and agents already know the pattern from the other two objects: name and metadata on the outside, the object's own content in a block with the object's name. Rules are the exception, so every reader has to remember a third shape, plus which of `status`, `configurations.*.status`, and `platforms` is real.

Deploy, promotion, and the platform deployers use the status on the platform block. The status on the root of a `rule::1.0` file is not what gets deployed. Sharing's `rule_statuses` filter and generated documentation do still read that root status today (opentide `sharing/engine.py`, `documentation/parts/sections.py`), so this revision has to say what replaces it for them. `detection_model` holds the UUID of an objective, or of a signal under one, behind a name that sounds like a data model.

## Detailed design

### The document

Same envelope as a threat or an objective: `name`, `metadata`, optional `references`. Schema id `rule::2.0`. `metadata.reviewed` is defined on `rule::2.0` with the meaning it has on `rule::1.1` ([rule-1.1.md](../specs/objects/rule-1.1.md#review-staleness)); a `rule::2.0` file without it is unreviewed.

```yaml
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::2.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  reviewed: "2026-09-01"
  tlp: clear
rule:
  description: |
    Detects credential access via suspicious process creation.
  severity: High
  techniques: [T1059]
  objective: 00000000-0000-4000-8002-000000000001
  response:
    alert_severity: High
  sentinel:
    enabled: true
    schema: platform::sentinel::1.0
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
```

| | `rule::1.0` / `rule::1.1` | `rule::2.0` |
|--|-------------|-------------|
| Description, severity, techniques, response | document root | `rule.*` |
| Objective or signal UUID | `detection_model` | `rule.objective` |
| Platform payload | `configurations.sentinel` (or legacy `platforms`) | `rule.sentinel` |
| Deployment status | root `status`, which deploy ignores (sharing and docs read it), and `configurations.*.status`, which deploy uses | `rule.<platform>.status` only |
| `metadata.reviewed` | `rule::1.1` only | optional, same meaning as `rule::1.1` |

`name` stays on the envelope so a rule, a threat, and an objective all identify themselves the same way.

### The `rule` block

| Field | Required | Notes |
|-------|----------|--------|
| `description` | yes | The narrative. |
| `severity` | no | Defaults to `Informational`. This is the detection's severity, not the alert severity inside a platform. |
| `techniques` | no | ATT&CK ids. Defaults to an empty list. |
| `objective` | no | UUID of the objective this rule implements. |
| `response` | no | Same response block as today (`alert_severity`, `playbook`, `responders`, `procedure`). `responders` stays free text, defaulted from `[deployment] default_responders`; it is not a vocabulary. |
| `<platform>` | no | One key per platform: `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `crowdstrike`, `harfanglab`, `carbon_black_cloud`, and `elastic` ([RFC 0007](0007-elastic-security-platform.md)). |

There is no status on `rule` itself. An enabled platform block must set `status`. A disabled block may omit it. The status values are the deployment statuses the workspace already configures.

The root of a `rule::2.0` file must not carry `description`, `status`, `severity`, `techniques`, `detection_model`, `objective`, `response`, `configurations`, or `platforms`. Those keys are how you recognise a 1.0 file.

A rule with no platform keys is still a valid draft. It deploys when at least one platform block has `enabled: true`.

### Platform blocks

They move. They do not change.

A Sentinel block is still a Sentinel block: `query`, `scheduling`, `alert`, and the rest of `platform::sentinel::1.0`. The same is true for Defender, Splunk (including the older spellings the loader already accepts), SentinelOne, CrowdStrike, HarfangLab, and Carbon Black. Elastic, from [RFC 0007](0007-elastic-security-platform.md), lands at `rule.elastic` on this revision and at `configurations.elastic` on `rule::1.0` and `rule::1.1`.

Blocks carry no external ids on any revision ([RFC 0010](0010-deployment-external-ids.md)): `external_id_in_rule` applies to every `rule.<platform>` block. Deployment-state shards are keyed by `metadata.uuid`, so moving a block does not touch `.opentide/states/deployment/`.

Platform specs that read a rule-level field name both paths: Carbon Black severity and Splunk `alert.managedBy` read `response.*` (`rule.response.*` on 2.0), and report and saved-search descriptions read `description` (`rule.description` on 2.0).

Adding a platform later is an optional key. It does not bump `rule::2.0`. A platform's own schema id (`platform::sentinel::1.0`, and whatever comes after it) is independent of the rule revision.

### Pins

`rule::1.0` and `rule::1.1` pins stay where they are. `rule::2.0` pins the same contracts on the new paths: `rule.severity` (`severity::1.0`), `rule.techniques` (`att&ck::1.2`), `rule.response.alert_severity` (`alert_severity::1.0`), and `metadata.tlp` (`tlp::1.0`). `rule.response.responders` has no pin: the `responders` vocabulary is retired and the field is free text. `rule.objective` binds the `objective` model vocabulary, as `detection_model` does: every objective and every signal defined under one.

### Migrating a file

One step, from `rule::1.0` or `rule::1.1` to `rule::2.0`, run on purpose. Opening or deploying a 1.x file does not rewrite it.

- `description`, `severity`, `techniques`, and `response` move under `rule`.
- `detection_model` becomes `rule.objective`. The value is copied as is, whether it names an objective or a signal.
- Each `configurations.<platform>` (or `platforms.<platform>`, if that key was the only copy) becomes `rule.<platform>`.
- A root `status` is copied onto platform blocks that don't already have one, then removed. A block that already has a status keeps it, because that is the status deploy uses.
- `metadata.reviewed` on a `rule::1.1` file is kept verbatim. A `rule::1.0` file gets none, so it stays unreviewed.
- Legacy external-id keys are not carried. They already fail `external_id_in_rule`, and `opentide deploy migrate-state` removes them.
- `metadata.schema` becomes `rule::2.0`. `metadata.version` stays put.

If the same platform appears under both `configurations` and `platforms`, migration fails. If a platform key is unknown, migration fails rather than dropping it.

### Status outside deploy

On `rule::2.0` a rule matches a sharing block's `rule_statuses` when at least one enabled platform block has a status in that list. A rule with no enabled block matches nothing. Generated documentation shows the status of each platform block instead of one rule status. `rule::1.0` and `rule::1.1` keep using the root `status` for both until they are migrated.

### Other specs that name rule fields

- [sharing/misp-1.0.md](../specs/sharing/misp-1.0.md): the `rule` relation source is `rule.objective` on 2.0 (top-level `detection_model` on 1.x), and `threat_level_id` comes from `rule.severity`. The technique source `rule.techniques[]` already names the 2.0 path.
- [RFC 0011](https://github.com/OpenTideHQ/specifications/pull/23) (signal reuse, draft): the direct objective of a `rule::2.0` file is `rule.objective`, or the owner of the signal it names.

### What lands after this RFC is accepted

- `specs/objects/rule-2.0.md` with the shape above.
- A history note on `rule-1.0.md` and `rule-1.1.md`. Those revisions stay valid.
- `specs/metadata.md` and the staleness predicate in `rule-1.1.md` cover `rule::2.0`.
- `specs/sharing.md` and `specs/sharing/misp-1.0.md` for the status match, relation source, and threat level above.
- `schemas/pins/rule.toml` section for `rule::2.0`, checked by `scripts/validate.py`.
- A valid `rule::2.0` fixture, plus invalid fixtures for a missing `rule` block, a leftover `configurations` key, a document-level `status`, and an enabled platform with no `status`.
- `SPECS.md` and `CHANGELOG.md`.

[platforms/index.md](../specs/platforms/index.md) should say where a block lives (`configurations.<platform>` on 1.x, `rule.<platform>` on 2.0) and keep pointing at the platform schema for the fields inside the block.

## Drawbacks

Two layouts will exist until people migrate. Deploy and documentation have to read `configurations.sentinel` on a 1.0 file and `rule.sentinel` on a 2.0 file. That is the point of the versioning spec: both have to work.

Anyone who edited the root `status` and believed deploy followed it was already mistaken. Migration keeps that value when the platform block had none.

## Alternatives

Leaving the fields on the root and only renaming `configurations` keeps rules as the odd object. Putting platform keys next to `rule:` instead of inside it splits one detection across two places. Editing `rule::1.0` in place would invalidate every existing file. Subclassing today's rule model so old code keeps compiling would drag `configurations` and a root status into the new document.

## Unresolved questions

- New rules should be born as `rule::2.0` once that model exists. Existing files stay on whatever they declare. Confirm that `opentide new` should follow the newest revision.
- Confirm the sharing match on `rule::2.0`: any enabled platform block with a status in `rule_statuses` (proposed), or every enabled block.
- `rule.objective` also holds signal UUIDs, which the name hides. Confirm the name, or pick one that covers both (for example `rule.implements`).
- `rule::1.0` and `rule::1.1` should be marked deprecated only after both shapes load and a migrate command exists. Until then they stay normative. Deprecated means "don't write new 1.x files", not "1.x files stop validating".

## References

- [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)
- [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md), [specs/objects/rule-1.1.md](../specs/objects/rule-1.1.md), [specs/objects/threat-1.0.md](../specs/objects/threat-1.0.md), [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md)
- [specs/versioning.md](../specs/versioning.md) 1.1 — every registered revision has to work for validation, deployment, and every other feature; migration is explicit and never changes `metadata.version` ([#27](https://github.com/OpenTideHQ/specifications/pull/27))
- [RFC 0007](0007-elastic-security-platform.md) — Elastic block, unchanged, new location only
- [RFC 0008](0008-rule-reviewed-date.md) — `metadata.reviewed`, carried onto `rule::2.0`
- [RFC 0010](0010-deployment-external-ids.md) — no external ids in platform blocks; deployment state keyed by `metadata.uuid`
