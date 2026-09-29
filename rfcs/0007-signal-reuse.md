# RFC 0007: Signal reuse across detection objectives

- **RFC:** 0007
- **Title:** Signal reuse across detection objectives
- **Author:** OpenTide
- **Status:** proposed
- **Created:** 2026-09-29
- **Issue:** [#22](https://github.com/OpenTideHQ/specifications/issues/22)

## Summary

A detection objective (DOM) may incorporate a signal defined on another objective that is already in the repository. The incorporating entry is a reference, `ref: <signal-uuid>`, completed from the workspace signal library. The signal keeps one UUID and one owning objective. A rule still names a single direct DOM through `detection_model`. Coverage also counts every other DOM that includes that signal, labeled indirect and partial, so one rule covers several DOMs. A copied `clone` field was the starting idea; a second definition cannot stay the same signal, so this RFC uses a live reference instead.

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

Additive on `objective::1.0`. Existing objectives remain valid. `metadata.schema` stays `objective::1.0`. No new object family, no new vocabulary file, no rule-schema change.

On acceptance, edit the objective spec in place and bump its frontmatter `version` to `1.1` (document revision, same schema id), following the metadata 1.1 precedent. Record the history row. Update the other specs listed under [Affected specs](#affected-specs). Ship fixtures in that same spec PR. opentide follows in its own PR.

### Signal item

Each `objective.signals[]` entry is one of two shapes. Exactly one.

**Definition** — unchanged. Required: `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, `data`. Optional fields stay as they are, including `parent`.

**Reference:**

```yaml
- ref: 00000000-0000-4000-8099-000000000001
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ref` | string (UUIDv4) | yes | Signal UUID of a definition in the workspace library |

A reference carries no local name, description, severity, methodology, entities, data, examples, detectors, effort, or `parent`. Those values are read from the definition at render, validation, and coverage time. The reference does not allocate a UUID and does not insert a second signal record.

`ref` together with any definition field is `signal_ref_not_exclusive`.

List order is the composition order. Definitions and references may interleave. The objective's composition strategy applies to the full effective list. The owning objective's composition is unchanged.

`objective.signals` still requires at least one entry. A resolved reference counts. An unresolved one does not, and is still an error.

### Library and import

The **signal library** is the set of definitions in the workspace signal index.

- **Owner.** The objective whose `signals[]` contains the definition. Exactly one.
- **Imported.** The owner's document is in that index (committed object YAML, or an inflight shard that wins). A UUID typed from outside the index is not imported.
- **Identity.** The library key is the definition's `uuid`. References point at that key. They are not separate keys.

Two definitions with the same UUID are `duplicate_signal_uuid`. The index MUST NOT keep last-writer-wins.

A reference target that is absent from the library is `unresolved_signal_ref`. A reference whose owner is the same objective is `self_signal_ref`. The same UUID twice in one objective's effective set (two refs, or a definition plus a ref) is `duplicate_signal`.

`effective_signals(objective)` is the ordered signal UUIDs on that objective: definition UUIDs, and `ref` values resolved to definition UUIDs.

Narrow validation (`--file`, `--uuid`, `--type`) still resolves references against the full workspace index, the same way threat UUID checks do.

Inflight overlay rules are unchanged. A reference to a signal whose definition arrives in a winning shard resolves. A reference to a signal removed by a winning shard fails.

### TLP

Rank, least restrictive first, matches [`vocabularies/tlp.vocab.toml`](../vocabularies/tlp.vocab.toml): `clear` < `green` < `amber` < `amber+strict` < `red`.

A reference is valid when the consumer's `metadata.tlp` is the same rank as the owner's or stricter. A consumer that is less restrictive than the owner is `signal_ref_tlp`. The check uses the two objectives' metadata, not `sharing.toml` `max_tlp`.

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

The objective metaschema binds the field:

```python
"ref": {"tide.vocab": "signal"}
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
- An edge from a referencing objective to a foreign signal, distinct from the owner's edge (label `ref` on the reference, owner edge unlabeled or `owns`).
- Every rule whose direct DOM includes that signal, edge signal → rule `implements`.
- Direct threats, and indirect threats marked partial with the via-signals.

Explorer relation counts MUST include each covered DOM once. A reference is a relation between the consumer objective and the owner objective.

### Sharing

On an objective, `opentide-relation` gains one value per distinct owner UUID of a referenced signal, alongside the existing `objective.threats[]` values. Emission rules in [specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md) stay: canonical lowercase UUIDs, one attribute per UUID, ascending order, still emitted when that owner was not shared to the block (informational note). Signal UUIDs are not relation values. The consumer document stores `ref` only. The definition remains on the owner document, so a receiver renders the signal from the owner event.

A reference does not change the consumer's `content_hash` when the definition text changes. The owner's hash changes, and the owner is what gets re-shared.

### Validation codes

Checked in the schema check's cross-object reference step ([specs/validation.md](../specs/validation.md)). Severity `error`.

| Code | Condition |
|------|-----------|
| `unresolved_signal_ref` | `ref` is not a definition in the library |
| `self_signal_ref` | `ref` target is owned by this objective |
| `duplicate_signal` | the same UUID appears twice in one objective's effective set |
| `duplicate_signal_uuid` | two definitions in the workspace share a signal UUID |
| `signal_ref_not_exclusive` | `ref` is combined with any definition field |
| `signal_ref_tlp` | consumer TLP is less restrictive than the owner's |
| `invalid_uuid` | `ref` is not a UUIDv4 (existing UUID check) |

The specifications-repo fixture checker (`scripts/object_fixtures.py`) currently requires `name`, `uuid`, `description`, `severity`, `methodology`, `entities`, and `data` on every signal. The spec PR teaches it the reference shape and the single-file codes (`signal_ref_not_exclusive`, `invalid_uuid` on `ref`). Cross-file resolution (`unresolved_signal_ref`, TLP, duplicate owners) is `opentide validate` against a workspace index. The checker does not grow a registry.

### Examples

Owner, already in the repo:

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

Consumer, after that owner is imported. Completion of `ref` inserts the signal UUID. The description shown beside it is `Credential Access Objective::Suspicious logon signal`.

```yaml
name: Lateral Movement Objective
metadata:
  uuid: 00000000-0000-4000-8002-000000000002
  schema: objective::1.0
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
    - ref: 00000000-0000-4000-8099-000000000001
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
| `fixtures/cross-object/objective-refs-signal.yaml` | Consumer whose `ref` is the signal UUID in `fixtures/valid/objective-1.0.yaml` (`…8099…0001`). `metadata.tlp` is `clear` or stricter, matching that owner. Passes the shape checker. |
| `fixtures/invalid/objective-signal-ref-and-name.yaml` | `ref` plus `name`. Code `signal_ref_not_exclusive`. |
| `fixtures/invalid/objective-signal-ref-bad-uuid.yaml` | `ref` is not a UUIDv4. Code `invalid_uuid`. |
| `fixtures/valid/objective-1.0.yaml` | Unchanged definition. Still valid. |

Workspace-level cases (opentide tests, not a second copy of the object model in this repo): dangling ref, self-ref, duplicate in one list, two definitions with one UUID, TLP laundering, mutual refs, inflight add and delete.

### Affected specs

| Path | Change on acceptance |
|------|----------------------|
| [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md) | Union of definition and `ref`. Library, owner, TLP, effective set. Frontmatter `version: "1.1"`. `schema_id` stays `objective::1.0`. |
| [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md) | State that `detection_model` is the direct DOM and that indirect DOMs are derived. Field table unchanged. |
| [specs/validation.md](../specs/validation.md) | Codes above. Checker vs `opentide validate` split. |
| [specs/metaschema-keywords.md](../specs/metaschema-keywords.md) | `signal` model vocabulary. `ref` example. Objective vocabulary is objectives only. |
| [specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md) | Objective relations include referenced-signal owners. |
| [site/index.md](../site/index.md) | Coverage diagram gains the indirect hop. The overview is descriptive; the objective spec stays normative. |
| `fixtures/` as listed | Shape fixtures and checker codes in `scripts/object_fixtures.py`. |
| [SPECS.md](../SPECS.md), [CHANGELOG.md](../CHANGELOG.md) | Objective document version 1.1, schema id unchanged. |

No change to `vocabularies/`. No `objective::1.1` schema file.

### opentide follow-up

File in [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide) after this RFC is accepted. Expected touch points, for that issue:

- `models/objective.py` — reference shape
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
- A clear or green objective cannot reference an amber or red signal. Authors hit `signal_ref_tlp` when they widen distribution by accident.
- Splitting `owner` from `parent` changes the index record every current signal walker reads. Walkers that still treat `parent` as the objective UUID will lose the objective hop.
- Remote MISP consumers see the definition only on the owner event. The consumer event carries the UUID and the relation. Its content hash does not move when the signal text changes.
- Coverage output grows by one DOM per consumer and per co-consumer.

## Alternatives

**`clone: <uuid>` on a full signal.** The starting proposal: an optional field, completed from the library, beside `name` and `uuid`. Set aside. A full entry is a second definition. Giving it the source UUID collides with the single library key. Giving it a new UUID makes a copy that drifts, and coverage can no longer treat the rule as covering the source signal. Completion of the source UUID still works under that design; the coverage requirement does not.

**Reuse authored `parent`.** Set aside. `parent` is a signal-to-signal composition edge. Ingest already stuffs the objective UUID into that field. Using it as "this entry is that signal" removes the composition edge and keeps the ambiguity.

**Several `detection_model` values on the rule.** Set aside. The rule would name DOMs by hand. The list would drift from the signals the direct DOM actually includes. Deriving indirect DOMs from `ref` keeps a single authored link.

**`objective.imports: [<objective-uuid>]`.** Set aside. Importing every signal of another DOM is coarser than the signal the author meant, and coverage would claim the rest.

**A `signal::1.0` object family.** A signal file with its own `metadata.uuid` would make ownership obvious. It also moves every existing signal out of its objective. References give cross-DOM identity without that migration.

**Local overlays on a reference** (severity, examples). Set aside for this revision. Two severities for one UUID is a second signal. A later revision can add overlays if a consumer has a real case.

**Keep signal UUIDs inside the objective vocabulary.** Set aside. `detection_model` would keep offering signals. The rule spec already rejects those values. A separate `signal` vocabulary is what `ref` completes against.

## Unresolved questions

1. Confirm indirect reason `shares` (co-consumers). Dropping it leaves `owns` only. The YAML does not change either way. This RFC includes `shares` so a rule covers every DOM that lists the signal.
2. Confirm ATT&CK layers stay on the direct DOM. Indirect threat techniques would widen `techniques_resolver` and double-count layers if they were copied onto the rule.
3. Confirm the TLP rank, including `amber` versus `amber+strict`. This RFC treats `amber+strict` as stricter: an `amber+strict` objective may reference an `amber` signal; the reverse is `signal_ref_tlp`.
4. Should a definition's `parent` be required to sit in the same effective set, or is any library signal enough? This RFC says MUST be in the library and SHOULD be in the same effective set.

## References

- Issue [#22](https://github.com/OpenTideHQ/specifications/issues/22)
- [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md), [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md)
- [specs/validation.md](../specs/validation.md), [specs/metaschema-keywords.md](../specs/metaschema-keywords.md)
- [specs/sharing/misp-1.0.md](../specs/sharing/misp-1.0.md) relation table
- opentide: `models/objective.py`, `registry/builder.py`, `indexing/inflight.py`, `indexing/object_vocab.py`, `documentation/catalog.py`, `generation/framework.py`, `export/explorer_export.py`
- [RFC 0001](0001-authority-model.md) — additive change keeps `objective::1.0`; spec frontmatter version still bumps
