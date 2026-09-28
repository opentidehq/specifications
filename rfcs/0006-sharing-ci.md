# RFC 0006: Sharing on the production merge

- **RFC:** 0006
- **Title:** Sharing on the production merge
- **Author:** OpenTide
- **Status:** accepted
- **Created:** 2026-09-28
- **Accepted:** 2026-09-28 — normative text in [specs/sharing.md](../specs/sharing.md)
- **Issue:** [#20](https://github.com/OpenTideHQ/specifications/issues/20)
- **PR:** [#21](https://github.com/OpenTideHQ/specifications/pull/21)
- **Supersedes:** the disposition of [RFC 0005](0005-sharing-system.md) question 8 (CI left as usage-guide material)

## Summary

`opentide setup` and `opentide setup ci` gain an optional sharing stage, default off. When the operator selects it, the stage runs `opentide share push --changed` on a push to the default branch, the same production release that already runs `opentide deploy --plan PRODUCTION`. The stage checks the objects that changed, matches them to existing remote events, and publishes per the sharing spec. It does not run on a pull request or a merge request. An enabled `[[misp]]` block does not turn the stage on; the setup choice does.

## Motivation

Deployment already has this mechanic. A pull request deploys changed rules to staging. A push to the default branch deploys them to production. Sharing 1.0 specifies the push itself and stops there, so a detection repository that adopts `opentide setup ci` validates and deploys on merge and never publishes the same objects to MISP.

Operators asked for that production step, and only that step. A pull request is unpublished work. Sharing it would put unmerged content on a community instance. Staging deploy exists because a SIEM has a staging tenant. A MISP block does not.

Stakeholders:

- **Detection engineers** need the objects that just merged to be the objects that get shared, without a hand-written workflow.
- **CTI operators** need a pull request to stay local. Publication happens when the default branch moves.
- **Implementers** need the job in the three workflows `opentide setup ci` already emits, using the production diff deploy already computes.

## Detailed design

Normative text lives in [specs/sharing.md](../specs/sharing.md). [specs/workspace.md](../specs/workspace.md) lists the job next to the inflight jobs. No object schema changes. No fixture changes: this is a pipeline rule, not a new `sharing.toml` shape.

### Setup chooses the stage

The sharing stage is one CI workflow feature, beside staging deploy, inflight shards, promotion, and explorer pages.

| Entry | Selection | Default |
|-------|-----------|---------|
| `opentide setup` wizard, after a CI platform is chosen | Checkbox "Sharing on the default branch" under "CI workflow features" | Off |
| `opentide setup --ci <platform>` | `--sharing` / `--no-sharing` | `--no-sharing` |
| `opentide setup ci <platform>` | `--sharing` / `--no-sharing` | `--no-sharing` |

"Configure later" does not ask and does not write a pipeline. `--sharing` without a CI platform warns and writes nothing. Setup does not write `sharing.toml` and does not ask for API keys. A later run that leaves the stage unselected removes it from the rewritten pipeline.

### The stage we ship

When the stage is selected, `opentide setup` and `opentide setup ci` MUST add `share` to the GitHub Actions, GitLab CI, and Azure Pipelines files they already write (`.github/workflows/opentide.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`). GitHub writes a job. GitLab writes a stage and a job. Azure writes a stage `Share` and a job. When the stage is not selected, those files contain no `opentide share` command and no `share` stage.

| Platform | The job runs when | The job does not run when |
|----------|-------------------|---------------------------|
| GitHub Actions | `github.event_name` is `push`, and the ref is `refs/heads/<default branch>` | `pull_request` |
| GitLab CI | `CI_COMMIT_BRANCH` equals `CI_DEFAULT_BRANCH`, and `CI_PIPELINE_SOURCE` is not `merge_request_event` | merge request pipelines |
| Azure Pipelines | `Build.SourceBranch` is `refs/heads/<default branch>`, and `Build.Reason` is not `PullRequest` | pull request validation |

The command is `opentide share push --changed`. The generated files MUST NOT contain any other `opentide share` command, and MUST NOT run this command on a pull request or merge request.

The stage starts after generate has succeeded and depends only on generate. Deploy jobs keep their current dependencies. Adding the stage does not make deploy wait for share, and does not make share wait for deploy. The checkout MUST include the history the production diff needs.

API keys stay in the CI secret store, under the names the blocks already declare as `${ENV_VAR}`. The generated file MUST NOT contain a key.

### What `--changed` selects

The commit range is the range `opentide deploy --plan PRODUCTION` already uses:

| Platform | Range |
|----------|-------|
| GitHub Actions | First parent of `HEAD` through `GITHUB_SHA` |
| Azure Pipelines | First parent of `HEAD` through `BUILD_SOURCEVERSION` |
| GitLab CI | `CI_COMMIT_BEFORE_SHA` through `CI_COMMIT_SHA` |

The first commit on a repository has no parent. That diff is empty, and the job exits 0. A parent commit that is not in the checkout is a preflight error. It MUST NOT be treated as an empty diff.

Inside that range, `--changed` keeps `.yaml` and `.yml` files whose parent directory is the configured threat, objective, or rule directory. Files nested further down are out of scope, as they are for a deploy plan. Added paths, modified paths, and the new path of a rename are in scope. Deleted paths are not. Deleting a file MUST NOT retract the remote event.

A change that is not one of those files, including an edit that only touches `sharing.toml`, is not in the diff. Sharing the rest of the catalogue is a manual `opentide share push` without `--changed`.

Each selected object then goes through the existing block selection, `max_tlp` ceiling, validation, organisation resolution, and remote lookup. An unchanged content hash stays `unchanged`.

`opentide share push --changed` during a pull request or merge request MUST fail preflight and MUST NOT contact the destination. `--changed` outside GitHub Actions, GitLab CI, and Azure Pipelines MUST fail preflight. An operator on a laptop uses `--file` or `--uuid`, or `preview`.

An empty diff exits 0 with an empty report. It is not `scope_no_match`. A `--changed` run with no enabled block also exits 0, so a repository that has not configured sharing stays green. A plain `opentide share push` with no enabled block remains `scope_no_match`.

`opentide share preview` is unchanged. It is the local dry run. The shipped pipeline does not call it.

## Drawbacks

- A push of several commits to the default branch shares only what the last commit changed on GitHub and Azure, because that is what `deploy --plan PRODUCTION` diffs. GitLab uses `CI_COMMIT_BEFORE_SHA`, which is the previous tip. Sharing follows those ranges instead of inventing a third.
- Enabling a block means the next object merge publishes. Bundled sharing still ships with no enabled block, so the job no-ops until someone opts in.
- There is no pull-request comment that shows the share report. The check happens on the production push, and a failure fails that pipeline.

## Alternatives

- **Always emit the sharing stage.** Rejected. Staging and inflight are choices in `opentide setup`. Sharing publishes outside the repository, so the stage defaults off until the operator selects "Sharing on the default branch" or passes `--sharing`.
- **Also ship `opentide share preview --changed` on pull requests.** Rejected. The pipeline we ship is the production release only. A pull request must not contact the destination, and a preview job would still be a second workflow we have not been asked to generate.
- **Publish from the `pull_request` closed event when `merged` is true.** Rejected. A merge lands as a push to the default branch, which is the event `deploy_production` already handles, on all three platforms.
- **Reuse `deploy --plan STAGING` for sharing.** Rejected. Staging is a pull-request deploy into a staging tenant. Sharing has no staging destination.
- **Share every in-scope object on each production push.** Rejected. The ledger would turn most of them into `unchanged`, but the run would no longer be "the files that just merged".
- **Retract when the object file is deleted.** Rejected. Retract is explicit. A delete in the diff is ignored.

## Unresolved questions

None. The trigger, the command, the diff, and the empty-run exits are decided above.

## References

- Spec-change issue: [specifications#20](https://github.com/OpenTideHQ/specifications/issues/20)
- Spec PR: [specifications#21](https://github.com/OpenTideHQ/specifications/pull/21)
- Sharing spec this attaches to: [specs/sharing.md](../specs/sharing.md), [RFC 0005](0005-sharing-system.md)
- Acceptance of sharing 1.0: [specifications#19](https://github.com/OpenTideHQ/specifications/pull/19)
- opentide implementation: [opentide#184](https://github.com/OpenTideHQ/opentide/issues/184)
- Production deploy the job sits beside: `src/opentide/ci/github.py`, `src/opentide/ci/gitlab.py`, `src/opentide/ci/azure.py`, and the `PRODUCTION` range in `src/opentide/deployment/git_repo.py`
