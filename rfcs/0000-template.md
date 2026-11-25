# RFC 0000: Template

> Copy this file to `rfcs/NNNN-your-title.md` and fill in each section. Do not edit this template for proposals.

- **RFC:** NNNN
- **Title:** (short title)
- **Author:** (name or handle)
- **Status:** draft | accepted | rejected | superseded
- **Created:** YYYY-MM-DD
- **Type:** (only for an RFC that adds or reworks a platform: `platform`)

> **Adding or reworking a platform?** Follow the [platform-rfc skill](https://github.com/opentidehq/specifications/blob/main/.agents/skills/platform-rfc/SKILL.md) as well. Besides the sections below, a platform RFC has `## Research` and a test plan, and its detailed design shows the complete block with every key filled in, a minimal block, the field table, every validation code, the vendor request for the complete block, tenant setup, and the deploy lifecycle. `scripts/test_rfc_platform_checklist.py` checks every RFC marked `- **Type:** platform`.

## Summary

One paragraph overview of the proposal.

## Motivation

Why is this change needed? What problem does it solve? Who is affected?

## Detailed design

Describe spec changes concretely:

- Affected paths under `specs/`
- New or changed requirements (MUST/SHOULD/MAY)
- Schema ID impact (`metadata.schema`)
- Fixture changes under `fixtures/`
- Vocabulary impact under `vocabularies/`

For a platform RFC, number the subsections and include at least: affected specs; the complete block (every key filled in, equal to the complete fixture) and a minimal block; block fields (key, type, required, default, allowed values, vendor property, notes); validation (every code: trigger, message, failing example, fixture); derived fields; the vendor request for the complete block (equal to its golden); tenant setup and authentication; the deploy lifecycle per status (with retries, and what the plan, dry run, and `--json` show); query validation; fixtures; and the upgrade path.

## Drawbacks

Trade-offs, migration cost, complexity added.

## Alternatives

Other approaches considered and why they were rejected.

## Unresolved questions

Open items for reviewer discussion.

## References

- Links to **GitHub** issues (opentidehq/specifications, opentidehq/opentide), prior art, opentide implementation notes
- Never Linear — opentide tracking is public GitHub only
