---
title: Specifications
description: What a Tide object is, how the object families chain, and how to read the normative opentide specifications.
---

# opentide Specifications

These are the **normative specifications** for opentide — the contract that every detection object, tool, and agent relies on. The [opentide](https://github.com/opentidehq/opentide) package implements this contract; the generated JSON Schema is a build artifact, never the source of truth. Each spec is versioned independently — there is no framework-wide version.

<Callout type="info">
Writing detections rather than the spec? Start with [Usage → Object model](/docs/usage/concepts/object-model/) for the hands-on view. These pages are the precise, normative reference behind it.
</Callout>

## What is a Tide object?

Detection content in opentide is a small graph of typed **objects**, each a YAML file with a shared `metadata` block. Three families exist:

| Family | Schema | Answers | Spec |
|--------|--------|---------|------|
| **Threat** | `threat::1.0` | What do we defend against? | [threat-1.0](specs/objects/threat-1.0.md) |
| **Objective** | `objective::1.0`, `objective::1.1` (draft) | What are we trying to detect? On 1.1 a signal may `reuse` one defined on another objective already in the repository. | [objective-1.0](specs/objects/objective-1.0.md), [objective-1.1](specs/objects/objective-1.1.md) |
| **Rule** | `rule::1.0`, `rule::1.1` | How do we detect it, on which platform? | [rule-1.0](specs/objects/rule-1.0.md), [rule-1.1](specs/objects/rule-1.1.md) |

### How objects chain

Objects reference each other by UUID. **References** point from rule to objective to threat; detection **coverage** flows the other way. On `objective::1.1` (draft, [RFC 0011](rfcs/0011-signal-reuse.md)), a `reuse` binding also covers the objective that owns that signal, and every other objective that reuses it. That coverage is indirect and partial. The rule still has one `detection_model`.

```mermaid
flowchart LR
  Rule -->|detection_model| Objective
  Objective -->|objective.threats| Threat
  Threat -. "is covered by" .-> Objective
  Objective -. "is implemented by" .-> Rule
```

### Two version fields

Every object declares both, and they are independent:

- `metadata.schema` (e.g. `rule::1.0`) — the **structural revision**, selecting the validation model. See [versioning](specs/versioning.md).
- `metadata.version` (e.g. `1.2.0`) — the **instance content version**; git is the authoritative history.

## Where things live

| Artifact | Location |
|----------|----------|
| Normative specs | this section, `specs/` |
| Conformance fixtures (valid/invalid YAML) | [`fixtures/`](https://github.com/opentidehq/specifications/tree/main/fixtures) |
| Canonical vocabularies (allowed values) | [`vocabularies/`](https://github.com/opentidehq/specifications/tree/main/vocabularies) |
| Implementation | [opentide](https://github.com/opentidehq/opentide) Python package |

## Reading order

```mermaid
flowchart LR
  overview["This overview"] --> conf["Conformance (MUST/SHOULD/MAY)"]
  conf --> meta["Metadata"]
  meta --> obj["Object spec (threat / objective / rule)"]
  obj --> val["Validation"]
```

1. **[Conformance](conformance.md)** — how to read the normative keywords.
2. **[Metadata](specs/metadata.md)** — the block every object shares.
3. **The object spec** you care about — [threat](specs/objects/threat-1.0.md), [objective](specs/objects/objective-1.0.md) ([1.1](specs/objects/objective-1.1.md) draft), or [rule](specs/objects/rule-1.1.md) (`rule::1.0` remains valid).
4. **[Validation](specs/validation.md)** — what the engine checks and when.
5. **A platform schema**, when you are writing `configurations.<platform>` — start at [Platforms](specs/platforms/index.md), then the block you deploy (for example [Sentinel](specs/platforms/sentinel-1.0.md)).

## Full index

The [spec index](SPECS.md) lists every active spec, its version, and status. Core infrastructure specs cover [workspace layout](specs/workspace.md), [configuration](specs/configuration.md), [deployment](specs/deployment.md), [platforms](specs/platforms/index.md), [metaschema keywords](specs/metaschema-keywords.md), and [vocabularies](specs/vocabularies/format.md). The eight `platform::<identifier>::1.0` field contracts live under [Platforms](specs/platforms/index.md).

Changes follow the process in [Governance](GOVERNANCE.md).
