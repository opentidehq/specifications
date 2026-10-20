# RFC 0013: Deployment plans, query validation scope, and the network proxy

- **RFC:** 0013
- **Title:** Deployment plans, query validation scope, and the network proxy
- **Author:** opentide maintainers
- **Status:** draft
- **Created:** 2026-10-20
- **PR:** [opentidehq/specifications#54](https://github.com/opentidehq/specifications/pull/54)
- **Implementation:** [opentidehq/opentide#598](https://github.com/opentidehq/opentide/pull/598)

## Summary

Specify the deployment plans (`STAGING`, `PRODUCTION`, `FULL`) as pipelines that select rules by status **strategy**, never by status name. Specify what a live query check covers and how `--changed`, `--file`, and `--uuid` narrow it. Require generated pipelines to run that check on the changed rules only, under `FULL`, and to set GitLab `workflow:rules`. Replace the `deployment.toml` `[proxy]` table, which the implementation already refuses, with the global proxy option.

## Motivation

Testing opentide 0.16.0 in production on a catalogue of several hundred rules found four problems. Three of them are gaps in these specs:

1. **The plans were never specified.** `opentide deploy --plan STAGING` reads like a status name. The bundled statuses include `STAGING` and `PRODUCTION`, `deployment.md` says status names are configuration, and nothing said what a plan selects. Users could not tell whether `--plan STAGING` deploys a rule in `DEVELOPMENT`; it does, because `DEVELOPMENT` maps to `PREVIEW`.
2. **The live query gate checked the whole catalogue on every run.** The generated step had no scope, and a few hundred Splunk rules took most of an hour per pipeline. The obvious fix, `--plan STAGING`, is wrong. It also selects strategies and tenants, so a merge request that edits a `PRODUCTION` rule's query would merge it unchecked. It also has no diff to read on a push pipeline.
3. **GitLab merge request pipelines could not start.** A GitLab job with no `rules` defaults to `except: merge_requests`. The generated `deploy_staging` job needs `generate`, which was left out of the merge request pipeline, so GitLab refused the pipeline.
4. **The `[proxy]` table described in `deployment.md` is refused by opentide** (retired in 0.10.0), and the spec did not say how one run reaches a cloud tenant through a proxy and an internal tenant without it.

## Detailed design

### `specs/deployment.md` 1.2 → 1.3

- New **Deployment plans** section. For each plan it lists the pipeline, the rule files read, the strategies deployed, and the tenant classes targeted:
  - `STAGING`: pull or merge request; files the request changed; `PREVIEW`, `UNIVERSAL`.
  - `PRODUCTION`: push to the default branch; files the push changed; `RELEASE`, `UNIVERSAL`, `DISABLEMENT`, `DELETION`.
  - `FULL`: every rule file; `PREVIEW`, `RELEASE`, `UNIVERSAL`, and the deprecated strategies only when the run keeps them.
- MUST: a plan selects by the strategy of the status, never by the status name; plan and status names are never read as each other.
- MUST: a strategy given as a plan (`PREVIEW`, `RELEASE`, …) is refused. SHOULD: the error names the plan that deploys it.
- The tenant `deployment` key's classes are listed: `STAGING`, `PRODUCTION`, `ALWAYS`, `MANUAL`.
- The strategy table gains a "deployed by plan" column, and `UNIVERSAL`, which opentide implements.
- `[proxy]` is replaced by **Network proxy**:
  - The proxy comes from the global `opentide --proxy`, or `OPENTIDE_PROXY` when the option is omitted.
  - Hosts in `NO_PROXY` MUST be reached directly.
  - A `[proxy]` table, a tenant `proxy` key, and `[cve].proxy` MUST fail the command and name `opentide --proxy`.

### `specs/validation.md` 1.3 → 1.4

New **Query validation scope** section:

- A live check reads a deployment plan's rules, `FULL` by default. Under `FULL` it reaches every tenant a rule can reach.
- `--changed`, `--file`, and `--uuid` narrow the rule files and MUST NOT change the plan's strategies or tenants:
  - `--changed` takes the pull or merge request's diff (the `STAGING` plan's files) or the push's (`PRODUCTION`), and refuses outside CI with exit `2`.
  - A `--file` or `--uuid` target that selects nothing fails before any query.
  - `--changed` cannot be combined with `--file` or `--uuid`.
- Generated pipelines MUST pass `--changed --plan FULL`. An omitted `--plan` reads `DEPLOYMENT_PLAN`, which a project-wide variable could set.

### `specs/workspace.md` 1.4 → 1.5

- The generated live query step is `opentide validate query --platform <p> --live --changed --plan FULL` on a full-history checkout. The staging deploy job is listed.
- Generated GitLab pipelines MUST set `workflow:rules` creating merge request and default-branch pipelines.

No schema id, fixture, or vocabulary changes.

## Drawbacks

- **Branch pipelines on GitLab.** With `workflow:rules`, a branch with no merge request runs no pipeline, as on GitHub. Teams that validated branches before opening a merge request open a draft merge request instead.
- **Less is checked per run.** `--changed` checks only the rules a run changed. A tenant added on the default branch is first checked against the rules the next changes touch, unless someone runs a full `validate query --live`.
- **No query check for deprecated strategies.** A changed rule whose strategy is `INERT`, `DISABLEMENT`, or `DELETION` sends no query under `FULL`. Such a rule is not deployed active.
- **`[proxy]` removal.** It is a contract change on paper, but no conforming implementation accepted the table after opentide 0.10.0.

## Alternatives

- **Rename the plans to `PREVIEW` / `RELEASE`.** Rejected. The tenant `deployment` key uses the plan names as tenant classes, so a rename breaks every generated pipeline and every tenant file. Aliases add a second name for each plan without removing the first.
- **Generated query step with `--plan STAGING`.** Rejected. It drops `RELEASE` rules and non-staging tenants from the merge request gate, and fails on push pipelines.
- **Per-platform deploy jobs to route proxies.** Rejected. `NO_PROXY` routes per host in one run. The production job must stay the one job that commits deployment state ([deployment-state.md](../specs/deployment-state.md#continuous-integration)).

## Unresolved questions

- Should `FULL` live validation offer a flag that also checks deprecated strategies' queries?

## References

- [opentidehq/specifications#54](https://github.com/opentidehq/specifications/pull/54): spec changes
- [opentidehq/opentide#598](https://github.com/opentidehq/opentide/pull/598): implementation, release 0.17.0
- [opentidehq/opentide#547](https://github.com/opentidehq/opentide/issues/547): `FULL` live validation reaches every tenant
- [RFC 0007](0007-elastic-security-platform.md): the retired per-tenant `proxy` key
