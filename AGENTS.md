---
title: Agent guide
description: How AI agents should read, propose, and apply OpenTide normative specifications.
---

<Callout type="info">
This guide targets contributors to the [specifications](https://github.com/OpenTideHQ/specifications) repository. Detection engineers reading [opentide.org](https://opentide.org) should start with [Specifications](/docs/specifications/) and [Usage](/docs/usage/).
</Callout>

# Agent guide — OpenTide specifications

Instructions for AI agents working in this repository.

## Authority model

1. **Specs in `specs/` are canonical.** Normative requirements live in markdown with RFC 2119 keywords (MUST, SHOULD, MAY).
2. **Vocabularies in `vocabularies/` are canonical data.** Do not override vocabulary files via client configuration; extend via `schema.toml` in opentide workspaces only.
3. **Fixtures in `fixtures/` are conformance examples.** When changing object specs, update matching fixtures.
4. **opentide implements specs.** Pydantic models and generated JSON Schema follow this repo — not the reverse.
5. **No site build here.** Do not add MkDocs, Nextra, or publishing pipelines to this repo.

## Read order

When answering questions or implementing spec changes:

1. [SPECS.md](SPECS.md) — find the active spec version and path
2. Relevant file under `specs/` — normative requirements
3. [GOVERNANCE.md](GOVERNANCE.md) — change process
4. [rfcs/0001-authority-model.md](rfcs/0001-authority-model.md) — authority chain details
5. `fixtures/` — concrete YAML examples
6. `vocabularies/` — enum data referenced by specs
7. opentide source — implementation reference only when verifying accuracy

## RFC workflow

Non-trivial or breaking changes require an RFC before spec edits:

1. Read the user's issue or request
2. Check [rfcs/](rfcs/) for related accepted RFCs
3. Use the [publish-rfc skill](.agents/skills/publish-rfc/SKILL.md) or copy [rfcs/0000-template.md](rfcs/0000-template.md)
4. Number the RFC sequentially (next after highest existing number)
5. Update specs, fixtures, `SPECS.md`, and `CHANGELOG.md` in the same PR as the RFC (or follow-up after acceptance per maintainer guidance)
6. Reference the RFC number in the PR description

Breaking object schema changes: create a new spec file (`rule-1.1.md`), mark the old file `status: deprecated`, do not delete it.

## Spec file template

Every spec under `specs/` uses this structure:

```yaml
---
spec: <name>
version: "1.0"
schema_id: <family::major.minor>   # when applicable
status: normative                  # draft | normative | deprecated
supersedes: null
---
```

Sections (fixed order): Summary, Requirements, Definition, Relationships, Defaults & overrides, Examples, History.

## Forbidden actions

- **Do not** treat generated JSON Schema as the spec source of truth
- **Do not** add `docs/` for normative content (use `specs/`)
- **Do not** add MkDocs, Nextra, or website build tooling
- **Do not** commit detection content or opentide implementation code here
- **Do not** edit vocabulary files in client `.opentide/configurations/` — canonical copies live in `vocabularies/`
- **Do not** invent a framework version — version each spec independently
- **Do not** merge breaking spec changes without an RFC reference
- **Do not** delete deprecated spec files — mark `status: deprecated` instead

## Vocabulary sync

Canonical `.vocab.toml` files live here. opentide copies them at build into `data/vocabulary/`. Sync direction: **specifications → opentide**. Document the interface in [specs/vocabularies/format.md](specs/vocabularies/format.md).

## Issue and PR templates

- Issues: [.github/ISSUE_TEMPLATE/spec-change.yml](.github/ISSUE_TEMPLATE/spec-change.yml)
- PRs: [.github/PULL_REQUEST_TEMPLATE/spec-change.md](.github/PULL_REQUEST_TEMPLATE/spec-change.md)

## llms.txt

See [llms.txt](llms.txt) for a machine-readable index of spec paths and governance links.
