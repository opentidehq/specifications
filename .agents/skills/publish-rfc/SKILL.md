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
- Maintainer asked for an RFC before spec edits

## Workflow

1. **Read context**
   - User issue or request
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
   - List every `specs/` path that will change on acceptance
   - Note whether a new object spec file is needed (e.g. `rule-1.1.md`)

5. **Do not implement yet** unless the user also asked for spec edits
   - RFC PR can be spec-only
   - After acceptance, follow with spec + fixture PR

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
