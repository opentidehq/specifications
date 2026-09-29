# RFC 0007: Signal reuse across detection objectives

- **RFC:** 0007
- **Title:** Signal reuse across detection objectives
- **Author:** OpenTide
- **Status:** proposed
- **Created:** 2026-09-29
- **Issue:** [#22](https://github.com/OpenTideHQ/specifications/issues/22)
- **PR:** [#23](https://github.com/OpenTideHQ/specifications/pull/23)

## Summary

A detection objective (DOM) may incorporate a signal defined on another objective that is already in the repository. That ability is a new objective schema, `objective::1.1`, specified in `specs/objects/objective-1.1.md`. The incorporating entry is a single UUID, completed from the workspace signal library. The signal keeps one UUID and one owning objective. A rule still names a single direct DOM through `detection_model`. Coverage also counts every other DOM that includes that signal, labeled indirect and partial, so one rule covers several DOMs. The YAML key is `reuse`. Normative text is [specs/objects/objective-1.1.md](../specs/objects/objective-1.1.md). `ref` is withdrawn. See [Field name](#field-name).

## Motivation

Objectives inline their signals. Reusing evidence means pasting the signal into a second DOM, minting another UUID, and letting the two copies drift. `detection_model` names one objective. The coverage graph is threat → that objective → its signals → the rule. The second DOM, and the threats it lists, stay uncovered.

Detection engineers need one signal, authored once, listed by every DOM that depends on it. Completion should offer that library once the owning objective is in the repo. Coverage, documentation, explorer relation counts, and sharing relations should follow the link in every direction: the rule on the consumer, the rule on the owner, and any other DOM that lists the same signal.

Stakeholders:

- **Detection engineers** author the reference and need completion, hover text, and docs to show the real signal.
- **Coverage consumers** (generated docs, explorer, reviewers) need direct and indirect coverage distinguished, including partial coverage of another DOM's threats.
- **Implementers** need one resolution rule. The registry, the coverage walker, validation, schema generation, and MISP relations must agree on the owner.

### What the implementation does today

This is the behavior the proposal is built against (opentide at the revision that matches `objective::1.0`):

- A signal lives only inside `objective.signals[]`. The spec's optional `parent` is a parent signal UUID ([specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md)).
- On ingest, the registry copies each signal into the `signal` bucket and **replaces** `parent` with the owning objective UUID (`registry/builder.py`, `indexing/inflight.py`). A repeated signal UUID is last-writer-wins. Object `id-uniqueness` checks `metadata.uuid` only, so two definitions can share a signal UUID without an error.
- `build_object_vocabularies` inserts those signal UUIDs into the **objective** model vocabulary, named `{objective name}::{signal name}`, with `tide.object.parent` set to the objective. `detection_model` is generated from `tide.vocab: "objective"`, so editor completion offers signal UUIDs for a field that must be an objective UUID.
- `catalog.coverage_graph` draws a 2-hop graph from the single `detection_model`. A rule is attached to a signal only when something in the relation walker already points `detection_model` at that signal UUID, which authored rules do not do. The usual edge is objective → rule.
- MISP `opentide-relation` on an objective emits `objective.threats[]` only ([specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md)). Signal UUIDs are not Tide object identifiers.

There is no content-pack import. An objective is available to the rest of the repo when its YAML is in the workspace object index: a file under `paths.objects.objective`, or an inflight shard that wins over the committed document. That index is the library. A future `share pull` would qualify only after it writes objective files into that tree. Sharing 1.0 has no pull.

## Detailed design

This is an objective schema change. Coverage, the signal library, completion, and the extra MISP relation are behavior on top of that schema. They are not a separate object family and they are not a documentation-only edit of `objective::1.0`.

### Schema revision: `objective::1.1`

| | `objective::1.0` | `objective::1.1` |
|--|------------------|------------------|
| Spec file | [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md). Field tables unchanged. Pointer to 1.1 added. | [specs/objects/objective-1.1.md](../specs/objects/objective-1.1.md) |
| `metadata.schema` | `objective::1.0` | `objective::1.1` |
| Signal item | Definition only. Required `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, `data`. | Definition, or a library binding |
| Status | Stays `normative`. Not deprecated. | `normative` |
| `supersedes` | `null` | `null` |

`objective::1.1` is the next minor schema revision, the same step [versioning.md](../specs/versioning.md) and [RFC 0001](0001-authority-model.md) describe for `rule::1.1`. The minor bump is the structural revision. Definitions are unchanged, so this is not `objective::2.0`.

`metadata.version` is the instance's content version. It does not select the schema, and this RFC does not change how authors bump it. Consumers route on `metadata.schema` only.

An objective that contains a binding MUST declare `metadata.schema: objective::1.1`. The same document declared as `objective::1.0` is invalid: 1.0 still requires a full definition on every signal. A definition-only objective MAY stay on `objective::1.0` forever. It MAY move to `objective::1.1` by changing `metadata.schema` and leaving the signals as definitions, because 1.1 accepts every 1.0 signal list. That migration is per object. [versioning.md](../specs/versioning.md) forbids a repository-wide cutover, so `objective::1.0` is not deprecated and authors are not required to touch DOMs that do not bind a signal.

On acceptance the new spec file is:

```yaml
---
spec: objective
version: "1.1"
schema_id: objective::1.1
status: normative
supersedes: null
---
```

The 1.1 field tables copy 1.0, then replace the signal-item rule with the definition-or-binding union. `objective-1.0.md` gains a history row and a relationship pointer: signal bindings are `objective::1.1`. Its field tables do not change.

Generated artifacts, both kept:

| Artifact | `objective::1.0` | `objective::1.1` |
|----------|------------------|------------------|
| JSON Schema | `objective.1.0.schema.json` | `objective.1.1.schema.json` |
| Template | `objective.1.0.template.yaml` | `objective.1.1.template.yaml` |

The IDE router gains a branch for `objective::1.1`. `metadata.schema` is a `const` on each artifact. [schemas/pins/objective.toml](../schemas/pins/objective.toml) gains an `["objective::1.1"]` table with the same vocabulary pins as `["objective::1.0"]`. The binding key is the `signal` model vocabulary, not a pinned `.vocab.toml` contract.

Sharing already emits `metadata.schema` verbatim. An `objective::1.1` event tells a receiver the signal list may contain bindings. A receiver that only implements 1.0 fails that object.

No new object family. No rule schema change. No vocabulary file change.

The spec, the 1.0 pointer, fixtures, pins, `SPECS.md`, and `CHANGELOG.md` are in this PR. opentide registers a second model (`__schema_identifier__ = "objective::1.1"`) in its own PR, with a migration of `objective::1.0` → `objective::1.1` that rewrites only `metadata.schema`.

The metadata 1.1 precedent does not apply. Metadata has no `schema_id`. An objective does, and a signal list that old `objective::1.0` parsers reject cannot keep that identifier.

### Signal item

On `objective::1.1`, each `objective.signals[]` entry is one of two shapes. Exactly one. On `objective::1.0`, only the definition exists.

**Definition** — unchanged. Required: `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, `data`. Optional fields stay as they are, including `parent`.

**Binding** — one library UUID and no local definition. The YAML key is the open choice in [Field name](#field-name). Examples use `reuse`:

```yaml
- reuse: 00000000-0000-4000-8099-000000000001
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reuse` (working key) | string (UUIDv4) | yes | Signal UUID of a definition in the workspace library |

A binding carries no local name, description, severity, methodology, entities, data, examples, detectors, effort, or `parent`. Those values are read from the definition at render, validation, and coverage time. The binding does not allocate a UUID and does not insert a second signal record.

The binding key together with any definition field is `signal_entry_mixed`.

List order is the composition order. Definitions and bindings may interleave. The objective's composition strategy applies to the full effective list. The owning objective's composition is unchanged.

`objective.signals` still requires at least one entry. A resolved binding counts. An unresolved one does not, and is still an error.

### Field name

The binding is one library UUID. The normative key, used by [specs/objects/objective-1.1.md](../specs/objects/objective-1.1.md), is `reuse`. The other rows were the alternatives. `ref` stays withdrawn.

| Key | YAML | Reads as | Cost |
|-----|------|----------|------|
| `reuse` | `- reuse: <uuid>` | Take this library signal into the composition. | Normative key in `objective::1.1`. |
| `include` | `- include: <uuid>` | This signal joins the objective. | Also how people talk about pulling in a file or a whole document. |
| `signal` | `- signal: <uuid>` | This list item is that signal. | The parent key is already `signals`, and the completion vocabulary is named `signal`. |
| `from` | `- from: <uuid>` | Origin of this slot. | Short, and easy to hear as "copied from". |
| `clone` | `- clone: <uuid>` | The word from the original request, defined as this same binding. | A clone is a fork that can drift. The spec would have to keep correcting that reading. The field is still only a UUID, with no local body. |
| `source` | `- source: <uuid>` | Where the signal is defined. | Signal `data` already uses data-source and log-source language. |
| `import` | `- import: <uuid>` | Bring in a library signal. | In this RFC, "imported" means the owning DOM is already in the repo. The key would mean a second thing. |
| bare UUID | `- <uuid>` | The array item is the completed value. A string is a binding. A mapping is a definition. | No name to dislike. A bare UUID is opaque in review, and a later overlay has to grow a oneOf around a string. |

`ref` is withdrawn. It names the pointer, and it sits beside `references` (URLs) and `opentide-relation`.

### Library and import

The **signal library** is the set of definitions in the workspace signal index.

- **Owner.** The objective whose `signals[]` contains the definition. Exactly one.
- **Imported.** The owner's document is in that index (committed object YAML, or an inflight shard that wins). A UUID typed from outside the index is not imported.
- **Identity.** The library key is the definition's `uuid`. References point at that key. They are not separate keys.

Two definitions with the same UUID are `duplicate_signal_uuid`. The index MUST NOT keep last-writer-wins.

A binding target that is absent from the library is `unresolved_signal`. A binding whose owner is the same objective is `self_signal`. The same UUID twice in one objective's effective set (two bindings, or a definition plus a binding) is `duplicate_signal`.

`effective_signals(objective)` is the ordered signal UUIDs on that objective: definition UUIDs, and binding values resolved to definition UUIDs.

Narrow validation (`--file`, `--uuid`, `--type`) still resolves references against the full workspace index, the same way threat UUID checks do.

Inflight overlay rules are unchanged. A reference to a signal whose definition arrives in a winning shard resolves. A reference to a signal removed by a winning shard fails.

### TLP

Rank, least restrictive first, matches [`vocabularies/tlp.vocab.toml`](../vocabularies/tlp.vocab.toml): `clear` < `green` < `amber` < `amber+strict` < `red`.

A binding is valid when the consumer's `metadata.tlp` is the same rank as the owner's or stricter. A consumer that is less restrictive than the owner is `signal_tlp`. The check uses the two objectives' metadata, not `sharing.toml` `max_tlp`.

### Autocomplete

Add a model vocabulary named `signal`, built beside the objective model vocabulary (same builder, merged into the vocabulary index). It is not a file in `vocabularies/` and it has no schema pin.

| Entry field | Value |
|-------------|--------|
| id | definition UUID |
| `name` | `{owning objective name}::{signal name}` |
| `description` | definition description |
| `criticality` | definition severity |
| `tlp` | owning objective TLP |
| `tide.object.parent` | owning objective UUID |

Only definitions are entries. A reference does not add a row.

The `objective::1.1` metaschema binds the field. The `objective::1.0` metaschema does not grow a binding key:

```python
"reuse": {"tide.vocab": "signal"}  # key follows Field name
```

`tide.vocab` resolution is the existing model-vocabulary path used by `detection_model` / `tide.vocab: "objective"`. Generated JSON Schema turns the library into an `enum` plus descriptions, so completion and hover show the signal name, description, severity, and owning DOM.

The enum is a snapshot from the last `opentide generate schemas`. Validation uses the live index, so a newly imported DOM can be referenced before schemas are regenerated. Completion updates when schemas are regenerated, the same refresh authors already need for new objective UUIDs on `detection_model`.

Signal UUIDs leave the `objective` model vocabulary. After that, `detection_model` completion lists objectives only, which matches the rule spec (the value MUST be an objective UUID).

### Ownership and `parent`

Authored `parent` stays a parent **signal** UUID on a definition. It is optional. When set, it MUST be a UUIDv4 in the signal library. It SHOULD name a signal in the same objective's effective set. It does not incorporate a signal and it does not change coverage. A reference has no `parent`.

The index record for a definition MUST keep both:

| Index field | Meaning |
|-------------|---------|
| `owner` | Owning objective UUID. Not an authored YAML field. |
| `parent` | Authored parent signal UUID, or absent. |

Today ingest writes the objective UUID into `parent` and drops the authored value. Acceptance requires ingest, including inflight overlay, to stop that overwrite.

Relation walks follow `owner` for the objective → signal hop (the hop the code currently finds by reading `parent`). `parent` is only the optional signal → signal edge. `parents()` of a signal that returned the objective UUID via `parent` MUST return the objective via `owner`, and MUST NOT drop the objective hop.

### Coverage

`detection_model` remains a single objective UUID. Rules do not gain a signal pointer or a list of DOMs. Coverage is derived.

Let D be the objective identified by `rule.detection_model`. If `detection_model` is absent, the rule covers nothing. Let S be `effective_signals(D)`.

A DOM **includes** a signal when that UUID is in its effective set.

| Relation | Rule | Kind |
|----------|------|------|
| Covers D | `detection_model` is D | **direct** |
| Covers another DOM O | O includes at least one signal that is also in S | **indirect** |

Indirect coverage has a reason. Both reasons are required:

| Reason | O |
|--------|---|
| `owns` | O is the owner of some signal in S, and O is not D |
| `shares` | O is not D, O is not that owner, and O includes some signal in S |

A rule implements every signal in S. That is true for a DOM with only local definitions and for a DOM that references foreign signals. Signal → rule edges in the coverage graph use this rule, including the no-reference case, where those edges are mostly absent today.

Indirect coverage is **partial**. It covers the shared signals, not the other DOM's full composition. Diagrams, docs, and explorer output MUST say that it is partial and MUST list the signal UUIDs in `S ∩ effective_signals(O)` plus the reason (`owns` or `shares`). They MUST NOT present the indirect DOM as a second `detection_model`.

Threats:

| Kind | Threats shown |
|------|----------------|
| direct | `D.objective.threats` |
| indirect | `O.objective.threats` for each indirect O, each annotated with the via-signals and the reason |

The walk stops at S. If A references signal S owned by B, and B references signal T owned by C, a rule whose direct DOM is A covers A (direct) and B (indirect, `owns`). It does not cover C, because T is not in A's effective set. Mutual references are valid. Walkers keep a visited set.

`techniques_resolver` and ATT&CK layer export stay on the direct DOM and that DOM's threats. Indirect threats appear in coverage output. Their technique ids are not copied onto the rule.

Documentation coverage graphs (`catalog.coverage_graph` and the pages that call it) MUST draw this set for a focused objective, rule, or threat:

- The focused objective's effective signals, resolved to definition name and owner.
- An edge from a binding objective to a foreign signal, distinct from the owner's edge (label `reuse` on the binding, owner edge unlabeled or `owns`). The label matches the chosen key.
- Every rule whose direct DOM includes that signal, edge signal → rule `implements`.
- Direct threats, and indirect threats marked partial with the via-signals.

Explorer relation counts MUST include each covered DOM once. A reference is a relation between the consumer objective and the owner objective.

### Sharing

On an objective, `opentide-relation` gains one value per distinct owner UUID of a referenced signal, alongside the existing `objective.threats[]` values. Emission rules in [specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md) stay: canonical lowercase UUIDs, one attribute per UUID, ascending order, still emitted when that owner was not shared to the block (informational note). Signal UUIDs are not relation values. The consumer document stores the binding key only. The definition remains on the owner document, so a receiver renders the signal from the owner event.

A binding does not change the consumer's `content_hash` when the definition text changes. The owner's hash changes, and the owner is what gets re-shared.

### Validation codes

Checked in the schema check's cross-object reference step ([specs/validation.md](../specs/validation.md)). Severity `error`.

Codes name the condition, so they stay put when the YAML key is chosen.

| Code | Condition |
|------|-----------|
| `unresolved_signal` | the binding UUID is not a definition in the library |
| `self_signal` | the binding target is owned by this objective |
| `duplicate_signal` | the same UUID appears twice in one objective's effective set |
| `duplicate_signal_uuid` | two definitions in the workspace share a signal UUID |
| `signal_entry_mixed` | the binding key is combined with any definition field |
| `signal_tlp` | consumer TLP is less restrictive than the owner's |
| `invalid_uuid` | the binding value is not a UUIDv4 (existing UUID check) |

The specifications-repo fixture checker (`scripts/object_fixtures.py`) currently requires `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, and `data` on every signal. The spec PR teaches it the binding shape and the single-file codes (`signal_entry_mixed`, `invalid_uuid` on the binding value). Cross-file resolution (`unresolved_signal`, TLP, duplicate owners) is `opentide validate` against a workspace index. The checker does not grow a registry.

### Examples

The owner can stay on `objective::1.0`. The library indexes its definitions either way. The consumer that binds one of them is `objective::1.1`.

Owner, already in the repo (`objective::1.0`):

```yaml
name: Credential Access Objective
metadata:
  uuid: 00000000-0000-4000-8002-000000000001
  schema: objective::1.0
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: green
composition:
  strategy: synergetic
  description: Compose signals for credential access detection
objective:
  priority: High
  type: Threat
  description: Detect credential access techniques
  composition:
    strategy: synergetic
    description: Compose signals for credential access detection
  threats:
    - 00000000-0000-4000-8001-000000000001
  signals:
    - name: Suspicious logon signal
      uuid: 00000000-0000-4000-8099-000000000001
      description: Suspicious authentication activity
      severity: Medium
      methodology: analytics
      entities: [host]
      data:
        availability: Complete
        requirements: Security event logs
```

Consumer (`objective::1.1`), after that owner is imported. Completion of `reuse` inserts the signal UUID. The description shown beside it is `Credential Access Objective::Suspicious logon signal`. The 1.0 schema artifact does not offer that key.

```yaml
name: Lateral Movement Objective
metadata:
  uuid: 00000000-0000-4000-8002-000000000002
  schema: objective::1.1
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  tlp: amber
composition:
  strategy: synergetic
  description: Compose movement signals with the shared logon signal
objective:
  priority: High
  type: Threat
  description: Detect lateral movement that reuses credential-access evidence
  composition:
    strategy: synergetic
    description: Compose movement signals with the shared logon signal
  threats:
    - 00000000-0000-4000-8001-000000000003
  signals:
    - reuse: 00000000-0000-4000-8099-000000000001
    - name: Remote service logon
      uuid: 00000000-0000-4000-8099-000000000002
      description: A new service logon on a second host
      severity: High
      methodology: analytics
      entities: [host]
      data:
        availability: Complete
        requirements: Security event logs
```

A rule with `detection_model: 00000000-0000-4000-8002-000000000002`:

| DOM | Kind | Via |
|-----|------|-----|
| Lateral Movement (`…0002`) | direct | `detection_model` |
| Credential Access (`…0001`) | indirect `owns` | `…8099…0001` |

The credential-access threat is partial, via that signal. Remote service logon is not part of that indirect cover.

A rule with `detection_model` pointing at Credential Access covers Credential Access directly and Lateral Movement indirectly with reason `shares`, via the same signal only. It does not implement Remote service logon.

### Fixtures (spec PR)

| Fixture | Expectation |
|---------|-------------|
| `fixtures/cross-object/objective-reuses-signal.yaml` | `metadata.schema: objective::1.1`. Binding value is the signal UUID in `fixtures/valid/objective-1.0.yaml` (`…8099…0001`). `metadata.tlp` is `clear` or stricter, matching that owner. Passes the shape checker. Filename follows the chosen key. |
| `fixtures/invalid/objective-1.0-signal-binding.yaml` | Binding on `metadata.schema: objective::1.0`. Fails 1.0 (definition fields required). |
| `fixtures/invalid/objective-signal-entry-mixed.yaml` | Binding key plus `name`. Code `signal_entry_mixed`. |
| `fixtures/invalid/objective-signal-bad-uuid.yaml` | Binding value is not a UUIDv4. Code `invalid_uuid`. |
| `fixtures/valid/objective-1.0.yaml` | Unchanged definition. Still valid. |

Workspace-level cases (opentide tests, not a second copy of the object model in this repo): dangling binding, self-binding, duplicate in one list, two definitions with one UUID, TLP laundering, mutual bindings, inflight add and delete.

### Affected specs

| Path | Change on acceptance |
|------|----------------------|
| `specs/objects/objective-1.1.md` | New normative spec. `schema_id: objective::1.1`. Definition or binding. Library, owner, TLP, effective set. |
| [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md) | Unchanged field tables. History row and relationship pointer: bindings are `objective::1.1`. Status stays `normative`. |
| [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md) | `detection_model` is the direct DOM. The UUID may be `objective::1.0` or `objective::1.1`. Indirect DOMs are derived. Field table unchanged. |
| [specs/validation.md](../specs/validation.md) | Codes above. A binding on `objective::1.0` fails schema. Checker vs `opentide validate` split. |
| [specs/metaschema-keywords.md](../specs/metaschema-keywords.md) | `signal` model vocabulary. Binding key on the 1.1 metaschema only. Objective vocabulary lists both revisions, objectives only. |
| [specs/workspace.md](../specs/workspace.md) | Artifact rows `objective.1.1.schema.json` and `objective.1.1.template.yaml`. |
| [schemas/pins/objective.toml](../schemas/pins/objective.toml) | `["objective::1.1"]` copies the `objective::1.0` pins. |
| [specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md) | Objective relations include owners of bound signals. `schema` is still emitted verbatim, so the value may be `objective::1.1`. |
| [site/index.md](../site/index.md) | Schema table and coverage diagram include `objective::1.1`. The overview is descriptive; the object specs stay normative. |
| `fixtures/` as listed | 1.1 consumer, 1.0 rejection, checker codes in `scripts/object_fixtures.py`. |
| [SPECS.md](../SPECS.md), [CHANGELOG.md](../CHANGELOG.md) | New row: objective 1.1, schema `objective::1.1`. The 1.0 row stays. |

No change to `vocabularies/`. `objective::1.0` is not deleted and not deprecated.

### opentide follow-up

File in [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) after this RFC is accepted. Expected touch points, for that issue:

- `models/objective.py` — `objective::1.1` model beside `objective::1.0`; migration rewrites only `metadata.schema`
- `registry/builder.py` and `indexing/inflight.py` — `owner` vs authored `parent`; reject duplicate definition UUIDs
- `indexing/object_vocab.py` — `signal` vocabulary; drop signal rows from `objective`
- `generation/framework.py` — `parents` / `childs` use `owner`
- `documentation/catalog.py` — coverage graph and `rules_for_signal`
- `export/explorer_export.py` — relation counts
- MISP relation emission for objective owners
- tests for the workspace-level cases above

## Drawbacks

- A widely reused signal makes every rule that implements any including DOM a partial cover of the others. That is the point of one signal, and it will inflate coverage for a signal that was referenced too freely.
- The consumer cannot override severity, examples, or data requirements. A different threshold is a new definition.
- Completion lags the live index until schemas are regenerated.
- A clear or green objective cannot bind an amber or red signal. Authors hit `signal_tlp` when they widen distribution by accident.
- Splitting `owner` from `parent` changes the index record every current signal walker reads. Walkers that still treat `parent` as the objective UUID will lose the objective hop.
- Remote MISP consumers see the definition only on the owner event. The consumer event carries the UUID and the relation. Its content hash does not move when the signal text changes.
- Coverage output grows by one DOM per consumer and per co-consumer.

## Alternatives

**`clone: <uuid>` on a full signal.** The starting proposal: an optional field, completed from the library, beside `name` and `uuid`. Set aside. A full entry is a second definition. Giving it the source UUID collides with the single library key. Giving it a new UUID makes a copy that drifts, and coverage can no longer treat the rule as covering the source signal. Completion of the source UUID still works under that design; the coverage requirement does not.

**Reuse authored `parent`.** Set aside. `parent` is a signal-to-signal composition edge. Ingest already stuffs the objective UUID into that field. Using it as "this entry is that signal" removes the composition edge and keeps the ambiguity.

**Several `detection_model` values on the rule.** Set aside. The rule would name DOMs by hand. The list would drift from the signals the direct DOM actually includes. Deriving indirect DOMs from the binding keeps a single authored link.

**`objective.imports: [<objective-uuid>]`.** Set aside. Importing every signal of another DOM is coarser than the signal the author meant, and coverage would claim the rest.

**A `signal::1.0` object family.** A signal file with its own `metadata.uuid` would make ownership obvious. It also moves every existing signal out of its objective. References give cross-DOM identity without that migration.

**Local overlays on a reference** (severity, examples). Set aside for this revision. Two severities for one UUID is a second signal. A later revision can add overlays if a consumer has a real case.

**Keep signal UUIDs inside the objective vocabulary.** Set aside. `detection_model` would keep offering signals. The rule spec already rejects those values. A separate `signal` vocabulary is what the binding key completes against.

**YAML key `ref`.** Withdrawn. It names a pointer, which is the mechanism, and it sits next to `references` (URLs on the objective) and `opentide-relation` without saying that the author is reusing a signal. Candidates are in [Field name](#field-name).

**Stay on `objective::1.0` and bump the spec frontmatter to 1.1.** Set aside. That pattern fits metadata, which has no schema id. A binding is not a valid 1.0 signal. Serving it under `metadata.schema: objective::1.0` makes the identifier a lie: old engines, the 1.0 JSON Schema, and a receiver that only knows 1.0 all claim to understand the document and then drop or reject the signal list. The library, coverage, and completion are the system around the change. The change itself is the schema.

**`objective::2.0`.** Set aside. A major revision is for a definition that no longer means what 1.0 said. Signal definitions are unchanged. The next structural step in [versioning.md](../specs/versioning.md) is the minor, `::1.1`.

**Deprecate `objective::1.0` in the same change.** Set aside. Deprecation tells every author to migrate. 1.0 documents stay valid, and versioning forbids a single-step repo migration. 1.0 remains normative for definition-only objectives.

## Unresolved questions

1. Confirm indirect reason `shares` (co-consumers). Dropping it leaves `owns` only. The YAML does not change either way. This RFC includes `shares` so a rule covers every DOM that lists the signal. The binding key is settled: `reuse`.
2. Confirm ATT&CK layers stay on the direct DOM. Indirect threat techniques would widen `techniques_resolver` and double-count layers if they were copied onto the rule.
3. Confirm the TLP rank, including `amber` versus `amber+strict`. This RFC treats `amber+strict` as stricter: an `amber+strict` objective may bind an `amber` signal; the reverse is `signal_tlp`.
4. Should a definition's `parent` be required to sit in the same effective set, or is any library signal enough? This RFC says MUST be in the library and SHOULD be in the same effective set.

## References

- Issue [#22](https://github.com/OpenTideHQ/specifications/issues/22)
- [specs/objects/objective-1.1.md](../specs/objects/objective-1.1.md), [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md), [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md)
- [specs/validation.md](../specs/validation.md), [specs/metaschema-keywords.md](../specs/metaschema-keywords.md)
- [specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md) relation table
- opentide: `models/objective.py`, `registry/builder.py`, `indexing/inflight.py`, `indexing/object_vocab.py`, `documentation/catalog.py`, `generation/framework.py`, `export/explorer_export.py`
- [RFC 0001](0001-authority-model.md) and [specs/versioning.md](../specs/versioning.md) — next structural revision is `objective::1.1`, coexist with `objective::1.0`, no repo-wide migration
