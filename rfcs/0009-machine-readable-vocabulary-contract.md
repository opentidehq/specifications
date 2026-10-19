---
rfc: 0009
title: A machine-readable vocabulary contract
status: draft
created: 2026-10-14
---

# RFC 0009 — A machine-readable vocabulary contract

- **RFC:** 0009
- **Title:** A machine-readable vocabulary contract
- **Author:** @behemothsecurity
- **Status:** draft
- **Created:** 2026-10-14

## Summary

This repository is the normative source for OpenTide's taxonomy, but it publishes that taxonomy
as documents for people rather than as a contract for machines. The gap is not cosmetic: a
consumer reading only this repository **cannot determine whether a field's authored values are
stage-prefixed**, because `tide.vocab.scoped` is specified here and declared nowhere here. This
RFC makes the vocabulary contract readable without inference: it extends the existing
`schemas/pins/*.toml` manifests to carry per-field vocabulary keywords, ships a generated and
CI-verified vocabulary index, holds `specs/vocabularies/catalog.md` to the directory it
describes, and gives a vocabulary a way to be deprecated in place instead of deleted.

Every part is additive. No key is added or removed, no field changes meaning, and no object
schema revision is required.

## Motivation

### The contract hole

`specs/vocabularies/format.md` is normative about staged vocabularies:

> A field bound to a staged vocabulary MUST declare `tide.vocab.scoped`, and its authored values
> MUST be `<stage>::<key>`. The prefix is what tells two stages' identically-named keys apart,
> and omitting it makes those values unreachable (see [RFC 0005](0005-scoped-signal-entities.md)).

`specs/metaschema-keywords.md` declares the keyword's type. `specs/objects/threat-1.0.md` goes
further and calls the unscoped form invalid:

> Each `ThreatActor.name` MUST be a scoped `actors::1.0` value (`<stage>::<id>`, for example
> `att&ck::G0007` or `misp::<uuid>`). Unscoped ids are invalid.

And yet **no artifact in this repository says which fields set that flag.** It is specified here
and implemented in `opentide` (`src/opentide/validation/field_vocab.py` reads it off
`field_schema`). A consumer that has only this repository must guess.

`schemas/pins/*.toml` is where the answer belongs. Those files already call themselves the
*"machine-readable source of truth"* for pin tables, and they already bind field path to
vocabulary contract — but only that:

```toml
["objective::1.0"]
"objective.signals.entities" = "signal.entities::1.0"
"metadata.tlp" = "tlp::1.0"
```

Nothing there distinguishes `objective.signals.entities`, which takes `Host::Account`, from
`metadata.tlp`, which takes a bare `clear`.

### What it costs downstream

`OpenTideHQ/website` rendered wrong values for three of the five staged vocabularies — `Account`
for `signal.entities`, `Accept` for `malapi`, and a bare actor name for `actors`, where the
specification requires `Host::Account`, `Internet::Accept` and `att&ck::G1028`. Having no flag to
read, a human transcribed the values and they drifted unnoticed.

[website#43](https://github.com/OpenTideHQ/website/pull/43) fixed it by **inferring** scoping
from the shape of the `stages` declaration: a `[[stages]]` table array implies scoped values,
while a plain string array — `att&ck`'s and `killchain`'s tactic lists — does not. That heuristic
is correct today and is documented nowhere. It exists only because the authoritative flag is
unreachable, and it is exactly the kind of private reimplementation the authority model in
[RFC 0001](0001-authority-model.md) exists to prevent.

### Retirement has no path

Retiring `responders` ([#38](https://github.com/OpenTideHQ/specifications/pull/38)) deleted
`responders.vocab.toml` outright. Downstream, that froze the website's deploys for roughly twenty
hours.

Per-*key* retirement is well specified — `removed` carries the contract line a key leaves at —
but there is no file-level equivalent, and `GOVERNANCE.md` already holds object specs to a
stricter rule than vocabularies get:

> a breaking object change gets a new spec file (e.g. `rule-1.1.md`) and the old file is marked
> `deprecated`, never deleted.

A vocabulary should not be weaker than an object spec here.

### Resolution is not publishable

[RFC 0003](0003-per-key-vocabulary-versioning.md) defines a contract as the resolved key set —
`version <= M.m` and not `removed`. That resolver lives only in `opentide`. A consumer wanting
"the values of `signal.entities::1.0`" must either reimplement per-key resolution and stage
expansion, or parse thirty-five TOML files including the 1.3 MB `att&ck.vocab.toml`. The honest
reading is that the resolved contract — the thing RFC 0003 defines — is currently unpublished.

## Detailed design

### 1. Per-field vocabulary keywords in `schemas/pins/*.toml`

Affected paths: `schemas/pins/threat.toml`, `schemas/pins/objective.toml`,
`schemas/pins/rule.toml`, `specs/metaschema-keywords.md`, `specs/vocabularies/format.md`.

A pin entry's value MAY be a table instead of a string. A bare string keeps its exact present
meaning, so **every existing entry and every existing consumer is unaffected**.

| Key | Type | Required | Default | Meaning |
|-----|------|:--------:|:-------:|---------|
| `vocab` | string | yes | — | Vocabulary contract id, `field::major.minor`. Identical to today's bare string |
| `scoped` | boolean | no | `false` | Authored values are `<stage>::<key>`. Mirrors `tide.vocab.scoped` |
| `stages` | list[string] | no | every stage the vocabulary declares | Narrows the field to these stage ids. Mirrors `tide.vocab.stages` |

A consumer MUST treat a string value `S` as equivalent to `{ vocab = S }` with the defaults above.

A field bound to a staged vocabulary MUST declare `scoped = true`. A field bound to an unstaged
vocabulary MUST NOT declare `scoped = true`.

```toml
["objective::1.0"]
"metadata.tlp" = "tlp::1.0"
"composition.strategy" = "detection.composition::1.0"
"objective.composition.strategy" = "detection.composition::1.0"
"objective.type" = "detection.types::1.0"
"objective.signals.severity" = "alert_severity::1.0"
"objective.signals.methodology" = "detection.methodology::1.0"
"objective.signals.entities" = { vocab = "signal.entities::1.0", scoped = true }
"objective.signals.effort" = "efforts::1.0"
"objective.mitre_attack" = "att&ck::1.1"
```

```toml
["threat::1.0"]
"metadata.tlp" = "tlp::1.0"
"criticality" = "criticality::1.0"
"threat.severity" = "severity::1.0"
"threat.impact" = "impact::1.0"
"threat.leverage" = "leverage::1.0"
"threat.viability" = "viability::1.0"
"threat.surface" = { vocab = "surface::1.0", scoped = true }
"threat.mitre_attack" = "att&ck::1.1"
"threat.actors.name" = { vocab = "actors::1.1", scoped = true }
"threat.killchain" = "killchain::1.0"
"threat.chaining" = { vocab = "chaining_relations::1.0", scoped = true }
```

The five staged vocabularies are `actors`, `chaining_relations`, `malapi`, `signal.entities` and
`surface`. `att&ck` and `killchain` declare `stages` as a plain string list — tactic and phase
classification, not a value prefix — and stay bare.

`schemas/pins/rule.toml` needs no change. Both its sections, `rule::1.0` and `rule::1.1`, pin
only `tlp`, `severity`, `att&ck` and `alert_severity`, none of which is staged, so every entry
stays in string form.

`malapi` is staged but **no pin binds it** — it appears only in
`specs/vocabularies/catalog.md`. That is not an error today, but it means the per-field rule
above can never be exercised for it, which is the argument for the orphan check in §3.

### 2. A generated vocabulary index

Affected paths: new `vocabularies/index.json`, new `scripts/generate_vocabulary_index.py`,
`specs/vocabularies/format.md`.

Committed to the tree so a consumer can read it from a tag or a submodule pin without running
anything, and regenerated plus verified in CI so it cannot go stale.

```json
{
  "source": {
    "commit": "<sha of the tree it was generated from>",
    "generated_by": "scripts/generate_vocabulary_index.py"
  },
  "count": 35,
  "vocabularies": [
    {
      "field": "signal.entities",
      "file": "signal.entities.vocab.toml",
      "name": "Signal Entities",
      "description": "...",
      "reference": "",
      "key": "name",
      "staged": true,
      "stages": ["Host", "Network", "Cloud"],
      "key_count": 28,
      "value_count": 35,
      "deprecated": null
    }
  ]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `field` | string | The field path the vocabulary constrains |
| `file` | string | Source filename under `vocabularies/` |
| `name`, `description`, `reference` | string | Copied from the file's top level |
| `key` | `"name"` \| `"id"` | The entry key, as the file declares it |
| `staged` | boolean | The file declares `[[stages]]` tables |
| `stages` | list[string] | Declared stage ids, empty when unstaged |
| `key_count` | integer | `[[keys]]` entries |
| `value_count` | integer | Authored values after stage expansion |
| `deprecated` | object \| null | See §4 |

`key_count` and `value_count` differ exactly when a key belongs to several stages. RFC 0005
states `signal.entities` resolves to 35 values over 28 keys; publishing both numbers makes that
checkable rather than rediscoverable.

This RFC deliberately does **not** put the resolved enum itself in the index. A full resolved
dump of `att&ck`, `actors` and `surface` is megabytes and would churn the diff of every content
change. Publishing resolved enums per contract revision is worth doing and is listed under
unresolved questions.

### 3. CI holds the catalogue to the directory

Affected paths: `scripts/validate.py`, `specs/vocabularies/catalog.md`.

`validate.py` today validates each TOML against `schemas/vocabulary.schema.json`, forbids a
top-level `version`, checks `field` matches the filename stem, detects duplicate keys, and
validates pin shape. It never compares the catalogue to the directory, so
`specs/vocabularies/catalog.md` — hand-maintained, and the thing downstream consumers scrape
today — can silently diverge.

`validate.py` MUST additionally fail when:

- a `*.vocab.toml` file exists that the catalogue does not list, or the catalogue lists a file
  that does not exist
- a catalogue row's `field` column disagrees with the file's declared `field`
- `vocabularies/index.json` is stale against the TOMLs
- a pin entry names a vocabulary contract no file provides
- a `*.vocab.toml` file exists that no pin entry references, and it is not deprecated — the
  converse of the check above. `malapi` is in this state today, so this check lands as a warning
  and is promoted to an error once each orphan is either bound or deprecated
- a field bound to a staged vocabulary omits `scoped = true`, or a field bound to an unstaged
  vocabulary declares it

The catalogue's `Total:` line MUST agree with the file count.

### 4. File-level deprecation, and a sunset window

Affected paths: `schemas/vocabulary.schema.json`, `specs/vocabularies/format.md`,
`specs/versioning.md`, `GOVERNANCE.md`.

A vocabulary file MAY declare a top-level `deprecated` table. A deprecated vocabulary stays in
the tree and stays in the catalogue, marked.

| Key | Type | Required | Meaning |
|-----|------|:--------:|---------|
| `since` | string | yes | ISO date the deprecation was published |
| `sunset` | string | yes | ISO date on or after which the file MAY be removed |
| `reason` | string | yes | Why it is going away |
| `replacement` | string | no | The `field` of the vocabulary that replaces it, when there is one |

```toml
name = "Responders"
field = "responders"
description = "..."

[deprecated]
since = "2026-10-13"
sunset = "2027-04-13"
reason = "Shipped with keys = [] while the rule schema pinned a field to it, so no instance could validate a value. Now a deployment.toml configuration enum."
# replacement omitted: there is no successor vocabulary
```

Requirements:

- A vocabulary MUST NOT be deleted before its `sunset` date. This mirrors the existing rule that
  a superseded object spec is marked `deprecated`, never deleted
- `sunset` MUST be at least one hundred and eighty days after `since`, giving consumers two
  quarters to migrate
- A pin MUST NOT bind a field to a deprecated vocabulary in a **new** schema revision; existing
  revisions keep theirs until they are themselves superseded
- A vocabulary whose `keys` is empty MUST be either deprecated or removed — the `responders`
  failure mode, where a field pinned to an empty vocabulary made every instance unvalidatable,
  becomes a CI error

### Schema ID impact

None. No object schema revision changes. Per RFC 0003 and the precedent RFC 0005 set when
`threat.surface` was scoped, declaring scoping adds and removes no key and so triggers no
vocabulary contract revision.

### Fixture changes

Under `fixtures/`:

- `valid/pins-scoped-field.toml` — a pin entry in table form with `scoped = true`
- `invalid/pins-staged-field-unscoped.toml` — a staged vocabulary bound without `scoped`
- `invalid/pins-unstaged-field-scoped.toml` — the converse
- `valid/vocabulary-deprecated.vocab.toml` — a file-level `deprecated` table
- `invalid/vocabulary-deprecated-short-sunset.vocab.toml` — a sunset under 180 days
- `invalid/vocabulary-empty-keys.vocab.toml` — empty `keys` with no deprecation

### Vocabulary impact

No vocabulary's keys change. Five files are confirmed staged in the index (`actors`,
`chaining_relations`, `malapi`, `signal.entities`, `surface`); the other thirty are not.

## Drawbacks

- **A generated file in the tree churns diffs.** `vocabularies/index.json` changes whenever a
  vocabulary does. It is small by design — metadata and counts, no resolved enums — and the
  alternative, leaving consumers to parse 1.3 MB of TOML, is worse.
- **Two shapes for a pin value.** A reader must handle string and table. The alternative, a
  flag day converting every entry to table form, breaks every existing consumer for cosmetic
  uniformity.
- **A 180-day sunset slows cleanup.** A vocabulary known to be unusable sits in the tree for two
  quarters. That is the cost of consumers being able to pin; `responders` is the argument for
  paying it.
- **CI gets stricter.** A contributor adding a vocabulary must update the catalogue and
  regenerate the index. Both are mechanical and the second is a script; today the same
  contributor can silently desynchronise the catalogue instead.

## Alternatives

**Leave scoping to be inferred from the `[[stages]]` shape.** Rejected: it is what
[website#43](https://github.com/OpenTideHQ/website/pull/43) does today, and it is undocumented,
unversioned, and duplicated per consumer. It also cannot express a field that narrows to a
subset of stages, which `tide.vocab.stages` already allows.

**Publish scoping from `opentide` instead.** Rejected: it inverts the authority model in
RFC 0001. The specs are the normative source and `opentide` implements them; a consumer should
not have to install a Python package to learn how to spell a value.

**A new standalone manifest holding field bindings and scoping.** Rejected: `schemas/pins/*.toml`
already is that manifest, already binds field to contract, and already describes itself as the
machine-readable source of truth. A second file would create two places to disagree.

**Put the resolved enums in the index.** Deferred, not rejected. It is the most useful artifact
for a consumer, and too large to carry in one churning file. It wants its own addressing scheme —
see below.

**Generate JSON Schema here instead.** Rejected: GOVERNANCE.md already settles this. Generated
JSON Schema is for editor and router validation, never for authoring normative changes.

## Unresolved questions

- **Resolved enums.** What is the right artifact for "the values of `signal.entities::1.0`"? A
  file per contract revision under `schemas/enums/`, built on release rather than committed, is
  the obvious shape, but the churn and size tradeoff needs a decision.
- **Tags and releases.** `git tag` in this repository returns nothing, so no consumer can pin a
  specification version — `OpenTideHQ/website` pins a raw commit SHA in a submodule. This has no
  spec-text impact and is separable from this RFC, but it is the cheapest fix on the list.
  Should it be folded in, or tracked separately?
- **Sunset enforcement.** Should CI fail once a deprecated vocabulary is past its `sunset` and
  still present, or is that a maintainer's judgement?
- **Does `rule` need scoped pins?** Resolved during review: no. `rule::1.0` and `rule::1.1` pin
  only unstaged vocabularies. See §1.
- **Orphan vocabularies.** `malapi` is staged and bound by no pin. Should an unbound vocabulary
  be an error, a permanent warning, or evidence that a pin is missing somewhere?
- **RFC numbering.** `0005` is used twice in `rfcs/README.md`
  (`0005-scoped-signal-entities.md` and `0005-sharing-system.md`). Worth correcting separately,
  and noted here so this RFC's `0009` is not built on a miscount.

## References

- [#39](https://github.com/OpenTideHQ/specifications/issues/39) — the spec-change issue this RFC answers
- [#38](https://github.com/OpenTideHQ/specifications/pull/38) — retired `responders`; the deletion this RFC gives a path for
- [website#43](https://github.com/OpenTideHQ/website/pull/43) — downstream fix, and the `[[stages]]`-shape heuristic it had to invent
- [RFC 0001](0001-authority-model.md) — authority model and change process
- [RFC 0003](0003-per-key-vocabulary-versioning.md) — per-key vocabulary versioning and schema pins
- [RFC 0005](0005-scoped-signal-entities.md) — stage-scoped `signal.entities`, and one prefixing rule for every staged vocabulary
- `specs/objects/threat-1.0.md` — "Unscoped ids are invalid"
- `specs/metaschema-keywords.md` — declares `tide.vocab.scoped`
