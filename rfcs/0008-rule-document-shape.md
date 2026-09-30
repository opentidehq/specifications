# RFC 0008: Rules should read like the other objects

- **RFC:** 0008
- **Title:** Rules should read like the other objects
- **Author:** OpenTide maintainers
- **Status:** draft
- **Created:** 2026-09-30
- **Revised:** 2026-09-30
- **Issue:** [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- **Implementation:** [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)

## Summary

A threat file has a `threat:` block. An objective file has an `objective:` block. A rule file does not. Its description, severity, techniques, objective link, and response sit on the document root, and the actual detections sit under a `configurations:` wrapper (with a leftover `platforms:` map beside it).

`rule::2.0` puts the detection in a `rule:` block and places each platform directly on that block. Platform payloads stay as they are. Deployment status stays on the platform, which is where deploy already reads it. The link to an objective is named `objective`.

Files that still say `rule::1.0` keep today's layout. Running both shapes in one workspace is a versioning requirement, specified separately in [specs/versioning.md](../specs/versioning.md). This RFC does not redesign Sentinel, Splunk, or any other platform.

## Motivation

Authors and agents already know the pattern from the other two objects: name and metadata on the outside, the object's own content in a block with the object's name. Rules are the exception, so every reader has to remember a third shape, plus which of `status`, `configurations.*.status`, and `platforms` is real.

Deploy, promotion, and the platform deployers use the status on the platform block. The status on the root of a `rule::1.0` file is not what gets deployed. `detection_model` is an objective UUID wearing a name that sounds like a data model.

## Detailed design

### The document

Same envelope as a threat or an objective: `name`, `metadata`, optional `references`. Schema id `rule::2.0`.

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

| | `rule::1.0` | `rule::2.0` |
|--|-------------|-------------|
| Description, severity, techniques, response | document root | `rule.*` |
| Objective UUID | `detection_model` | `rule.objective` |
| Platform payload | `configurations.sentinel` (or legacy `platforms`) | `rule.sentinel` |
| Deployment status | root `status`, which deploy ignores, and `configurations.*.status`, which deploy uses | `rule.<platform>.status` only |

`name` stays on the envelope so a rule, a threat, and an objective all identify themselves the same way.

### The `rule` block

| Field | Required | Notes |
|-------|----------|--------|
| `description` | yes | The narrative. |
| `severity` | no | Defaults to `Informational`. This is the detection's severity, not the alert severity inside a platform. |
| `techniques` | no | ATT&CK ids. Defaults to an empty list. |
| `objective` | no | UUID of the objective this rule implements. |
| `response` | no | Same response block as today (`alert_severity`, `playbook`, `responders`, `procedure`). |
| `<platform>` | no | One key per platform: `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `crowdstrike`, `harfanglab`, `carbon_black_cloud`, and `elastic` when that platform exists. |

There is no status on `rule` itself. An enabled platform block must set `status`. A disabled block may omit it. The status values are the deployment statuses the workspace already configures.

The root of a `rule::2.0` file must not carry `description`, `status`, `severity`, `techniques`, `detection_model`, `objective`, `response`, `configurations`, or `platforms`. Those keys are how you recognise a 1.0 file.

A rule with no platform keys is still a valid draft. It deploys when at least one platform block has `enabled: true`.

### Platform blocks

They move. They do not change.

A Sentinel block is still a Sentinel block: `query`, `scheduling`, `alert`, and the rest of `platform::sentinel::1.0`. The same is true for Defender, Splunk (including the older spellings the loader already accepts), SentinelOne, CrowdStrike, HarfangLab, and Carbon Black. Elastic, from [RFC 0007](0007-elastic-security-platform.md), lands at `rule.elastic` on this revision and at `configurations.elastic` on `rule::1.0`.

Adding a platform later is an optional key. It does not bump `rule::2.0`. A platform's own schema id (`platform::sentinel::1.0`, and whatever comes after it) is independent of the rule revision.

### Pins

`rule::1.0` pins stay where they are. `rule::2.0` pins the same vocabularies on the new paths: `rule.severity`, `rule.techniques`, `rule.response.alert_severity`, `rule.response.responders`, and `metadata.tlp`. `objective` is a UUID, not a vocabulary.

### Migrating a file

One step, from `rule::1.0` to `rule::2.0`, run on purpose. Opening or deploying a 1.0 file does not rewrite it.

- `description`, `severity`, `techniques`, and `response` move under `rule`.
- `detection_model` becomes `rule.objective`.
- Each `configurations.<platform>` (or `platforms.<platform>`, if that key was the only copy) becomes `rule.<platform>`.
- A root `status` is copied onto platform blocks that don't already have one, then removed. A block that already has a status keeps it, because that is the status deploy uses.
- `metadata.schema` becomes `rule::2.0`. `metadata.version` stays put.

If the same platform appears under both `configurations` and `platforms`, migration fails. If a platform key is unknown, migration fails rather than dropping it.

### What lands after this RFC is accepted

- `specs/objects/rule-2.0.md` with the shape above.
- A history note on `rule-1.0.md`. That revision stays valid.
- `schemas/pins/rule.toml` section for `rule::2.0`.
- A valid `rule::2.0` fixture, plus invalid fixtures for a missing `rule` block, a leftover `configurations` key, a document-level `status`, and an enabled platform with no `status`.
- `SPECS.md` and `CHANGELOG.md`.

`platforms.md` should say where a block lives (`configurations.<platform>` on 1.0, `rule.<platform>` on 2.0) and keep pointing at the platform schema for the fields inside the block.

## Drawbacks

Two layouts will exist until people migrate. Deploy and documentation have to read `configurations.sentinel` on a 1.0 file and `rule.sentinel` on a 2.0 file. That is the point of the versioning spec: both have to work.

Anyone who edited the root `status` and believed deploy followed it was already mistaken. Migration keeps that value when the platform block had none.

## Alternatives

Leaving the fields on the root and only renaming `configurations` keeps rules as the odd object. Putting platform keys next to `rule:` instead of inside it splits one detection across two places. Editing `rule::1.0` in place would invalidate every existing file. Subclassing today's rule model so old code keeps compiling would drag `configurations` and a root status into the new document.

## Unresolved questions

- New rules should be born as `rule::2.0` once that model exists. Existing files stay on whatever they declare. Confirm that `opentide new` should follow the newest revision.
- `rule::1.0` should be marked deprecated only after both revisions load and a migrate command exists. Until then it stays normative. Deprecated means "don't write new 1.0 files", not "1.0 files stop validating".

## References

- [OpenTideHQ/specifications#24](https://github.com/OpenTideHQ/specifications/issues/24)
- [OpenTideHQ/opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)
- [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md), [specs/objects/threat-1.0.md](../specs/objects/threat-1.0.md), [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md)
- [specs/versioning.md](../specs/versioning.md) — both revisions have to work for validation, deployment, and every other feature
- [RFC 0007](0007-elastic-security-platform.md) — Elastic block, unchanged, new location only
