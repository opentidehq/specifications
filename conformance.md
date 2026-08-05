---
title: Conformance
description: How to read the normative keywords (MUST, SHOULD, MAY) used throughout the OpenTide specifications.
---

# Conformance

OpenTide specifications are **normative**: they define requirements an implementation, detection object, or tool must meet to conform. This page defines the keywords those requirements use and what conformance means.

## Requirement keywords

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in the specifications are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) — that is, they carry these meanings only when in ALL CAPS.

| Keyword | Meaning |
|---------|---------|
| **MUST** / **REQUIRED** / **SHALL** | An absolute requirement. Non-conformance is an error. |
| **MUST NOT** / **SHALL NOT** | An absolute prohibition. |
| **SHOULD** / **RECOMMENDED** | Valid reasons may exist to ignore this, but the full implications must be understood and weighed first. |
| **SHOULD NOT** / **NOT RECOMMENDED** | Valid reasons may exist to do this, but weigh the implications first. |
| **MAY** / **OPTIONAL** | Truly optional. Implementations must interoperate with others that make the opposite choice. |

## What conformance means

An object **conforms** to a spec when it satisfies every MUST and MUST NOT in that spec and in the shared [metadata](specs/metadata.md) contract. The [validation pipeline](specs/validation.md) enforces conformance mechanically:

- **Structural conformance** — the object validates against the JSON Schema generated for its `metadata.schema` revision.
- **Referential conformance** — cross-object references resolve and UUIDs are unique.
- **Vocabulary conformance** — controlled-vocabulary fields use published values.

A conforming **implementation** (such as opentide) validates objects exactly as the specs require and reports capabilities honestly — for example, never reporting query validation as passed for a platform that cannot perform it (see [validation](specs/validation.md) and [platforms](specs/platforms.md)).

## Authority

Where a spec and any generated artifact disagree, the **spec wins**. Generated JSON Schema exists for editor and router validation; it is derived from the specs, not the other way around. The precedence chain and change process are defined in [Governance](GOVERNANCE.md).

## Versioning of conformance

There is no framework-wide version to conform to. An object conforms to the specific **schema revision** it declares in `metadata.schema` (e.g. `rule::1.0`), and each spec is versioned independently. See [Versioning](specs/versioning.md).
