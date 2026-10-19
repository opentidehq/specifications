---
name: publish-rfc
description: Draft an OpenTide specification RFC from a GitHub issue or user request. Use when proposing breaking or non-trivial spec changes.
---

# Publish RFC

Draft a Request for Comments (RFC) for the OpenTide specifications repository.

## When to use

- User opened a spec-change issue with "Draft RFC for me"
- Breaking schema revision proposed
- Multi-spec or architectural change
- Maintainer asked for an RFC together with the spec change. "Draft RFC for me" on an issue, with no schema or object bump, is the RFC-only case.

## Workflow

1. **Read context**
   - User **GitHub** issue or request (OpenTideHQ/specifications or OpenTideHQ/opentide). Never Linear.
   - [GOVERNANCE.md](../../GOVERNANCE.md)
   - [rfcs/0001-authority-model.md](../../rfcs/0001-authority-model.md)
   - Existing RFCs in `rfcs/` — pick next number after highest `NNNN`

2. **Copy template**
   - Start from [rfcs/0000-template.md](../../rfcs/0000-template.md)
   - Save as `rfcs/NNNN-short-title.md`

3. **Fill sections**
   - **Summary** — one paragraph
   - **Motivation** — problem and stakeholders
   - **Detailed design** — spec text changes, new files, fixture impact
   - **Drawbacks** — trade-offs
   - **Alternatives** — rejected options
   - **Unresolved questions** — open items for review

4. **Link affected specs**
   - List every `specs/` path this change touches
   - Note whether a new object spec file is needed (e.g. `rule-1.1.md`)

5. **Land the spec change in the same PR**
   - A schema bump, object bump, new field, or other normative edit is part of the request, even when it is named next to "add an RFC"
   - In that PR, update the specs, fixtures, `SPECS.md`, and `CHANGELOG.md` the RFC names, and extend the fixture checker when this repo proves the new field
   - Write an RFC file only, with no spec edits, when the user explicitly asks for a draft RFC and no schema or object changes

## RFC numbering

- `0000` — template only, never used for proposals
- `0001` — authority model (accepted)
- Next free number: check `ls rfcs/` and increment

## Breaking change rules

- New `schema_id` → new `specs/objects/<family>-<version>.md`
- Old spec: `status: deprecated`, `supersedes` on new file points to old if needed
- Update `SPECS.md` and `CHANGELOG.md` when spec lands, not only when RFC merges

## Forbidden

- Do not edit opentide implementation in this skill's PR unless explicitly requested
- Do not add website or doc-site tooling
- Do not treat JSON Schema as authoritative over markdown specs
- Do not use Linear for OpenTide work. Open a public GitHub spec-change issue in OpenTideHQ/specifications; implementation issues go in OpenTideHQ/opentide. Linear MCP may exist in the agent environment — do not call it for this repository.
