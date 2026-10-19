---
rfc: 0005
title: Stage-scoped signal.entities, and one prefixing rule for every staged vocabulary
status: accepted
created: 2026-10-13
supersedes: null
---

# RFC 0005 — Stage-scoped `signal.entities`

## Summary

`objective.signals[].entities` becomes **stage-scoped**: an authored value is
`<stage>::<key>`, as `threat.surface` already is. Stage identifiers on
`signal.entities` are capitalised to `Host`, `Network` and `Cloud` so the two
staged vocabularies agree on casing as well as on prefixing.

This is a breaking change to authored content. It adds no key and removes no
key, so no vocabulary contract revision is required.

## Motivation

### The flattening is lossy

`signal.entities` defines 28 keys across three stages, and **seven of those
keys carry two stages**:

| Key | Stages |
|---|---|
| `Account` | Host, Cloud |
| `User` | Host, Cloud |
| `Authentication` | Host, Cloud |
| `Token` | Host, Cloud |
| `Permissions` | Cloud, Host |
| `Email` | Network, Host |
| `API Call` | Network, Cloud |

Unscoped, the generated enum is **28 bare key names**. Scoped it is **35
values**. The seven missing values are not cosmetic: whether a detection
signal keys on a **host** account or a **cloud** account is a substantive
distinction — different telemetry, a different data contract, frequently a
different platform — and it is currently unexpressible.

This is the same collision class that justified scoping `threat.surface`,
where five keys (`VPN`, `VPN::OpenVPN`, `VPN::WireGuard`, `Wireless`,
`Industrial`) are each defined under both `Infrastructure` and `Protocol`.

### The two staged vocabularies contradicted each other

After the scope restoration on `surface`, the two files stated opposite rules
in the same release:

> `surface.vocab.toml` — "an authored value is **ALWAYS** prefixed with its
> stage id"

> `signal.entities.vocab.toml` — "Authored values are the key names … and are
> **not** prefixed with the stage id"

A reader had no way to tell which rule was the framework's position. One rule
for all staged vocabularies removes the question.

## Design

### Authored form

```yaml
objective:
  signals:
    - name: Anomalous cloud sign-in
      entities:
        - Cloud::Account        # a directory identity
        - Network::IP Address
    - name: Suspicious local logon
      entities:
        - Host::Account         # a local or domain account on the endpoint
        - Host::Process
```

`Cloud::Account` and `Host::Account` are distinct, valid values.

### Stage identifier casing

`signal.entities` stages become `Host`, `Network`, `Cloud` (previously `host`,
`network`, `cloud`). `surface` already uses capitalised stage identifiers
(`OS`, `Application`, `Authentication`, `Cloud`, `Infrastructure`, `Security`,
`IoT`, `Protocol`), so this makes the authored form uniform across every
staged vocabulary that carries a human-facing stage.

`actors` keeps lowercase `misp` and `att&ck` stage identifiers: those name
external frameworks whose own spelling is lowercase, and they are not
human-facing category labels.

### No contract revision

Per [RFC 0003](0003-per-key-vocabulary-versioning.md), a vocabulary contract
revision tracks **key lifecycle** — a key entering, leaving, or being renamed.
Scoping changes neither the key set nor any key's lifecycle; the prefix is
applied at resolve time from `tide.vocab.stages`, which the entries already
declare. `signal.entities::1.0` therefore stays as it is.

This follows the precedent set when `threat.surface` was scoped, where
`surface::1.0` was likewise unchanged.

### Resolution is raw-first

A consumer resolving an authored value MUST try the **whole value as a key
name** before reading its leading token as a stage identifier.

Key names legitimately contain `::`. `surface` defines `AWS::Compute::EC2` as
a single key, and six keys — `Security::TLS`, `Security::Kerberos`,
`Security::NTLM`, `Security::OAuth`, `Security::SAML`,
`Security::OpenID Connect` — whose first token is *also* a stage identifier.
Reading the prefix first resolves `Security::Kerberos`, a `Protocol` key, to
the unrelated `Authentication` key `Kerberos`.

No key in any shipped vocabulary is also a valid scoped form, so raw-first
resolution is unambiguous.

## Migration

Instances re-prefix authored values with `opentide migrate vocab-scope`, which
covers every scoped field rather than this one alone.

The migration applies only **mechanical** outcomes — a key defined under
exactly one stage, where the prefix is implied by the vocabulary, and a stage
whose casing drifted. A bare key defined under **several** stages is reported
with its candidates and left untouched, because the authored intent is not
recoverable from the value: `Account` could have meant either stage. Those
values MUST be resolved by a human, or recovered from version control where
the pre-flattening revision is available.

## Alternatives considered

**Leave `signal.entities` flattened and document the asymmetry.** Rejected.
The asymmetry is not a design choice with a rationale; the seven collisions
make the flattening lossy in exactly the way that justified scoping `surface`.
Documenting it would record a defect as intent.

**Scope the vocabulary but keep lowercase stage identifiers.** Rejected. It
leaves the two staged vocabularies disagreeing on casing, so an author still
cannot predict the form from the vocabulary alone, and `host::Account` beside
`OS::Windows` reads as two different mechanisms.

**Disambiguate by splitting the colliding keys** (`Host Account`,
`Cloud Account`). Rejected. It duplicates seven keys, breaks the key set (a
major contract revision under RFC 0003), and pushes the stage into the key
name, which is what stages exist to avoid.

## Relationships

- [RFC 0003](0003-per-key-vocabulary-versioning.md) — why no contract revision
- [specs/objects/objective-1.0.md](../specs/objects/objective-1.0.md) — the field
- [specs/vocabularies/format.md](../specs/vocabularies/format.md) — staged vocabularies
- opentide#509 — implementation and migration
