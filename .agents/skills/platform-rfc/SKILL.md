---
name: platform-rfc
description: Write or review an opentide RFC that adds a detection platform or reworks one (a new `configurations.<platform>` block, a new vendor API, a renamed or removed platform). Use with publish-rfc whenever the RFC touches `specs/platforms/`.
---

# Platform RFC

An RFC that adds or reworks a platform is read by people who will never open the vendor docs or the opentide code: detection engineers writing the block, reviewers deciding the design, and implementers building the deployer. It MUST let each of them work from the RFC alone. A platform RFC that only links to its spec is not ready.

This skill is the bar. It was built from the RFCs that set it: [0007 Elastic](../../../rfcs/0007-elastic-security-platform.md), [0016 Bitdefender](../../../rfcs/0016-bitdefender-gravityzone-platform.md), [0017 Graylog](../../../rfcs/0017-graylog-platform.md), [0018 Exabeam](../../../rfcs/0018-exabeam-platform.md), [0019 Google SecOps](../../../rfcs/0019-google-secops-yara-l.md), and [0021 Microsoft Defender](../../../rfcs/0021-defender-graph-beta-detection-rules.md) as revised. Read two of them before writing.

## Why this skill exists

RFC 0021 first landed as a thin platform RFC: decisions and code lists, with the YAML, the request, and the lifecycle left to the spec. It got through because:

- the [template](../../../rfcs/0000-template.md) and [publish-rfc](../publish-rfc/SKILL.md) listed only the six generic sections, with nothing about platforms;
- the bar lived only in earlier RFCs, which a writer had to know to read;
- "the spec holds the normative text" was read as "the RFC may link instead of showing";
- no test looked at an RFC's content.

The checklist below fixes the first three, and `scripts/test_rfc_platform_checklist.py` fixes the last.

## Workflow

1. Follow [publish-rfc](../publish-rfc/SKILL.md) for numbering, the issue, and landing the spec in the same PR.
2. Add `- **Type:** platform` to the RFC header. The checklist test runs on every RFC with that line.
3. Write the spec (`specs/platforms/<name>-1.0.md`), the complete fixture, the request goldens, and the invalid fixtures first. The RFC shows them; tests keep them equal.
4. Fill every section below. Where the spec is normative, the RFC restates it with examples and reasons and says "where they differ, the spec wins" (RFC 0017's wording). Summarise or link only what is generic to every platform (shared block keys, deployment-state rules).
5. Run `python -m unittest discover -s scripts -p 'test_*.py'`, then check the MDX rules at the end.

## Checklist

### Header

- [ ] `- **Type:** platform`
- [ ] `- **Status:**`, `- **Created:**`, `- **Accepted:**` with the normative spec paths and their versions
- [ ] `- **Issue:**` (a GitHub spec-change issue, never Linear)
- [ ] `- **Related:**` earlier RFCs it reuses or supersedes
- [ ] `- **Implementation:**` the opentide (and language-server) issues or PRs, once they exist

### `## Summary`

- [ ] Platform identifier, display name, and `schema_id`
- [ ] The vendor API surface it deploys through, and the ones it does not
- [ ] The identity model: vendor-assigned id in deployment state, or a client id (the uuid)
- [ ] Additive or breaking, in one sentence

### `## Motivation`

- [ ] Who cannot do what today, and why now (a new vendor API, a vendor removal with its date)
- [ ] For a rework: a table of what the vendor removed or changed, and the replacement
- [ ] Every naming, API-version, and identity choice, with its reason

### `## Research`

- [ ] Dated, labelled sources (vendor docs at a date, vendor source at a tag, `[live]` tests)
- [ ] A transport and authentication table: endpoint, auth flow, least-privilege permissions, error shape, rate limits
- [ ] The vendor methods or objects used, and the enums the block maps
- [ ] What the docs leave open (each becomes an unresolved question)
- [ ] When tested live: a findings table (RFC 0017's V-rows, RFC 0007's Appendix A) and how to reproduce it

### `## Detailed design`

Number the subsections (`### 1. Affected specs`). Each item below is a heading whose text contains the quoted words.

- [ ] **"Affected specs"**: a table of every path and its version change; vocabularies, even when none change
- [ ] **"Complete block"**: one annotated YAML block, `configurations:` first, with **every key the spec defines filled in**, shared keys included, and a comment on each saying its values and the vendor property. It equals the complete fixture (a test). Mark vendor-preview or beta keys.
- [ ] **"Minimal block"**: the smallest valid block, and what it sends
- [ ] **"Block fields"**: one table, a row per key path: key, type, required, default, allowed values or pattern, vendor property, notes. Sub-tables for kinds, actions, or criteria.
- [ ] **"Validation"**: a table of every code (constraints, advisories, deploy diagnostics, and generic codes the block can raise): source (vendor docs or opentide), trigger, message gist, a failing example, the invalid fixture. Each invalid fixture's first line names its code.
- [ ] **"Derived fields"**: name, description, severity mapping, ATT&CK, tags, durations, anything deploy computes
- [ ] **"Request"**: the YAML-to-wire mapping table, and the exact request deploy sends for the complete block (method, URL, headers, body), equal to a golden under `fixtures/platforms/<name>/` (a test). Show every call of the lifecycle (create, update, disable, delete).
- [ ] **"Tenant setup"**: the TOML example, the setup-key table, the permissions or roles, the sign-in flow, and the tenant check (`opentide doctor --live`)
- [ ] **"Deploy lifecycle"**: a table per status strategy (`PREVIEW`, `RELEASE`, `UNIVERSAL`, `DISABLEMENT`, `DELETION`, `INERT`) and per vendor answer or binding; a sequence diagram (`mermaid`) or call table; failure handling; retries and rate limits; what the plan, the dry run, and `--json` show; `--prune`
- [ ] **"Query validation"**: offline, `--live`, and `opentide query`
- [ ] **"Fixtures"**: a table of every fixture and golden and what it proves; the tests that compare them
- [ ] **"Upgrade"**: what an existing user does, step by step, or "Additive: nothing to do". State whether there is tooling.
- [ ] Implementation notes or an engineering plan: work packages per repository, and the PRs once known

### Closing sections

- [ ] `## Drawbacks`
- [ ] Risks of the vendor surface (preview or beta APIs, version churn), with mitigations, when there are any
- [ ] `## Alternatives`: a table or list, each with why not
- [ ] `## Unresolved questions`: numbered, each with the position the spec takes meanwhile
- [ ] A heading containing **"test plan"**: how a person with a tenant (or a Docker stack) confirms each unresolved question and runs the platform end to end; link the plan when it lives in another repository
- [ ] `## References`: vendor pages, prior RFCs, the issue, implementation PRs

## MDX rules

The website renders `rfcs/` and `specs/` as MDX, and CI's `website-sync / website` job builds them.

- No bare `<`, `>`, `{`, or `}` in prose or tables: put placeholders in backticks (`{base}/{uuid}`, `<tenant_id>`) or code blocks.
- Quote frontmatter values that contain `: `.
- A `<Callout>` goes after the title and before `## Summary`, never inside a list or table.
- `mermaid` code blocks render; other diagrams are images or tables.

## Forbidden

- Do not land a platform RFC whose complete block omits a key the spec defines.
- Do not show a request body by hand when a golden exists: paste the golden and add the test.
- Do not use Linear for opentide work.
