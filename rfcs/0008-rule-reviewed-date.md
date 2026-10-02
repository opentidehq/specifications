# RFC 0008: Optional review date on detection rules

- **RFC:** 0008
- **Title:** Optional review date on detection rules
- **Author:** OpenTide
- **Status:** draft
- **Created:** 2026-09-30
- **Issue:** [#28](https://github.com/OpenTideHQ/specifications/issues/28)
- **PR:** [#29](https://github.com/OpenTideHQ/specifications/pull/29)

## Summary

Add an optional `metadata.reviewed` timestamp so a consumer can list detection rules (MDR) that have no recorded review, or whose last review is older than a chosen window. The field is introduced by a minor MDR schema revision, `rule::1.1`. `rule::1.0` stays normative and does not gain the field. Threat and objective schemas do not change.

## Motivation

`metadata.created` is when the rule was born. `metadata.modified` moves on every edit, including edits that are not a review. Neither value answers "which rules has nobody reviewed for N days?"

Detection engineers need that answer for production rules that still deploy and still look current in git. A review that changes no detection text has nowhere to be recorded, and a content edit can make a stale rule look recently touched.

Stakeholders:

- **Detection engineers** need to find rules with no review, or a review older than a window they choose (90 days, a quarter, a year).
- **Workspace maintainers** need the marker on the rule itself, next to `created` and `modified`, without a second index file.
- **Implementers** need one optional field and one new schema identifier, not a new lifecycle status.

## Detailed design

### Decisions

1. **The value is a timestamp named `reviewed`.** It sits on `metadata`, beside `created` and `modified`. It is the instant a person last reviewed the rule for continued fitness. It is not a deployment status and not a content version.
2. **It is optional.** Omitted means no recorded review. A required field would make every new `rule::1.1` document invalid until someone invents a review.
3. **Minor MDR schema bump.** The field arrives as `rule::1.1` (`specs/objects/rule-1.1.md`). `rule::1.0` stays `status: normative` and is not deprecated. Objects opt in by setting `metadata.schema: rule::1.1`, per [versioning.md](../specs/versioning.md). No repository-wide migration.
4. **Rule-only.** `threat::1.0` and `objective::1.0` do not gain the field. An in-place metadata change, the way [RFC 0005](0005-sharing-system.md) added `metadata.pap`, would put a rule-review clock on every Tide object.
5. **The window is not stored.** "Not reviewed for a certain amount of time" is a query. The rule stores the instant; the consumer supplies the duration.

### Field

Same load rules as `metadata.created` and `metadata.modified`: an ISO 8601 date or datetime string, coerced to string on load.

| Field | Type | Required | Applies to | Description |
|-------|------|----------|------------|-------------|
| `reviewed` | string | no | `rule::1.1` | Last human review. Omitted means no recorded review. |

Normative requirements for the acceptance text:

- A `rule::1.1` document MAY omit `metadata.reviewed`.
- When `metadata.reviewed` is present, it MUST be an ISO 8601 date (`YYYY-MM-DD`) or datetime string. A date-only value denotes `00:00:00Z` on that date.
- `threat::1.0`, `objective::1.0`, and `rule::1.0` MUST reject `metadata.reviewed`.
- Implementations MUST NOT write `metadata.reviewed` during validate, deploy, share, or template generation. Template generation leaves it absent. Authors set it when a person reviews the rule.
- Consumers MUST NOT treat `metadata.created` or `metadata.modified` as a review time. Updating `reviewed` does not require a change to `metadata.version` or `metadata.modified`; those stay author-controlled.

```yaml
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.1
  version: 1
  created: "2026-01-01"
  modified: "2026-01-02"
  reviewed: "2026-09-01"   # optional; omit when nobody has reviewed the rule
  tlp: clear
```

### Finding rules that were not reviewed

Evaluated at instant `T`, for a positive duration `W` supplied by the consumer, a rule is **unreviewed** when any of the following holds:

1. `metadata.schema` is `rule::1.0` (this revision has no review field).
2. `metadata.schema` is `rule::1.1` and `metadata.reviewed` is absent.
3. `metadata.schema` is `rule::1.1` and the `reviewed` instant is strictly earlier than `T − W`.

`rule::1.0` is included so a rule left on the old schema cannot drop out of the result. A `reviewed` instant equal to `T − W` or later is not unreviewed. This predicate is a read. It does not modify the rule. No CLI flag is specified here; an opentide command can wrap the same predicate later.

### Normative changes

This PR lands the following. The RFC stays `draft` until review accepts it.

| Path | Action |
|------|--------|
| `specs/objects/rule-1.1.md` | **New.** `schema_id: rule::1.1`, `version: "1.1"`, `status: normative`, `supersedes: null`. Body matches [rule-1.0.md](../specs/objects/rule-1.0.md) except the schema identifier, the `reviewed` requirements above, a review-staleness subsection, and the fixtures below. Platform blocks, defaults, and other fields are unchanged. |
| `specs/objects/rule-1.0.md` | Stays normative. One relationship line pointing at `rule-1.1.md`: this revision does not define `metadata.reviewed`. Not deprecated. |
| `specs/metadata.md` | `1.1` → `1.2`. Field table row for optional `reviewed`, limited to `rule::1.1`. History row citing this RFC. |
| `schemas/pins/rule.toml` | Copy the `["rule::1.0"]` pin table to `["rule::1.1"]`. No vocabulary identifier changes. |
| `fixtures/valid/rule-1.1.yaml` | Valid `rule::1.1` with `metadata.reviewed` set. |
| `fixtures/valid/rule-1.1-unreviewed.yaml` | Valid `rule::1.1` with `metadata.reviewed` omitted. |
| `fixtures/invalid/rule-reviewed-bad-date.yaml` | `rule::1.1` whose `metadata.reviewed` is not an ISO 8601 date or datetime. |
| `fixtures/invalid/rule-1.0-reviewed.yaml` | `rule::1.0` that carries `metadata.reviewed` (rejected). |
| `specs/validation.md` | Fixture checker codes `invalid_reviewed` and `reviewed_not_in_schema`. |
| `scripts/object_fixtures.py` | Accept `rule::1.1`, require an ISO 8601 `reviewed` when present, reject it on every other schema. |
| `SPECS.md`, `CHANGELOG.md`, `llms.txt` | Index `rule` 1.1 and `metadata` 1.2. |

No change to `vocabularies/`, threat, objective, deployment statuses, platform specs, or sharing. Sharing publishes the rule document verbatim, so a present `reviewed` value is carried inside that document without a MISP template change.

`rule::1.0` and `rule::1.1` coexist. A workspace MAY contain both. Migrating one rule is setting `metadata.schema: rule::1.1` and, when a review has happened, `metadata.reviewed`.

## Drawbacks

- Two normative MDR specs until a workspace moves rules to `rule::1.1`. The 1.1 file repeats 1.0.
- A review report lists every unmigrated `rule::1.0` rule as unreviewed. That is noisy in a large repo, and it is the signal that those rules have no review date.
- Authors must set the date themselves. Nothing in validate or deploy refreshes it, including a review that forgets to touch the field.

## Alternatives

- **Optional field on metadata 1.2 with no schema bump** (the `metadata.pap` pattern). Rejected. `pap` applies to every object family. `reviewed` is an MDR concern, and an in-place shared-metadata change would accept the key on threat and objective documents and on frozen `rule::1.0`.
- **Top-level `reviewed` outside `metadata`.** Rejected. `created` and `modified` already live on `metadata`. A second clock belongs next to them.
- **Reuse `metadata.modified`, or add a deployment status such as `REVIEW`.** Rejected. `modified` advances on any edit, so it cannot mean "last review". Deployment status selects a deploy strategy ([deployment.md](../specs/deployment.md)); it is not a timestamp, and a `PRODUCTION` rule is exactly the rule that still needs a periodic review.
- **Required `reviewed`.** Rejected. Absence is the "never reviewed" result. Requiring the field would force a placeholder date onto drafts.
- **A review object** (`reviewed.date`, `reviewed.author`, notes). Rejected for this revision. Staleness needs one instant. Reviewer identity already has `author` and `contributors`.
- **Major bump `rule::2.0`.** Rejected. The revision adds an optional field and removes nothing.

## Unresolved questions

- The opentide command that prints unreviewed rules (name, flags, default window) is an implementation issue in [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide), opened after this RFC is accepted.
- Whether a later revision should record the reviewer separately from `author`. Not required to answer the staleness query.

## References

- Issue: [#28](https://github.com/OpenTideHQ/specifications/issues/28)
- [specs/metadata.md](../specs/metadata.md) — `created` and `modified`; `metadata` 1.1 added optional `pap` without an object schema bump
- [specs/objects/rule-1.0.md](../specs/objects/rule-1.0.md) — MDR object, `rule::1.0`
- [specs/versioning.md](../specs/versioning.md) — minor revisions coexist; objects opt in via `metadata.schema`
- [rfcs/0005-sharing-system.md](0005-sharing-system.md) — prior additive metadata field, and verbatim document sharing
