---
spec: workspace
version: "1.4"
schema_id: null
status: normative
supersedes: null
---

# Workspace layout

## Summary

Defines the standard detection-repository directory layout scaffolded by `opentide setup` and used for object storage, generated artifacts, documentation mirrors, and client configuration overrides.

## Requirements

- A healthy opentide workspace MUST contain `objects/` with subdirectories for each core object family.
- Generated artifacts MUST live under `.opentide/` — not committed as hand-edited sources.
- `.opentide/states/deployment/` is generated deployment state and MUST be committed. `.opentide/states/sharing.jsonl` is a regenerable cache and SHOULD be gitignored. Implementations MUST NOT gitignore the whole `.opentide/states/` directory ([deployment-state.md](deployment-state.md#git-policy)).
- Client configuration overrides MUST live only under `.opentide/configurations/`.
- Object YAML files MUST reside in the paths defined by merged `paths.toml` configuration.
- An object instance MUST be a YAML file placed directly in its family directory (`objects/rules/rule.yaml`, not `objects/rules/team/rule.yaml`). A file in a subdirectory of a family directory is not an object instance: implementations MUST NOT deploy or share it, and SHOULD warn that it is outside the catalogue. Nested folders under a family directory are otherwise outside this specification.
- Object YAML **filenames** SHOULD use dash-case slugs (lowercase, hyphens) ideally aligned with the object `name` field via the same `slugify()` rules the opentide engine uses for documentation paths. The `name` field itself MAY be richer (title case, punctuation, spaces). On slug collision, append a short UUID suffix. This is a soft convention for catalogue hygiene, not a schema validation requirement.
- `opentide generate schemas` MUST emit schema artifacts to `.opentide/schemas/`.
- `opentide generate templates` MUST emit templates to `.opentide/templates/`.

## Definition

### Core object families

| Family | Config key | Default path |
|--------|------------|--------------|
| Threat | `paths.objects.threat` | `objects/threats/` |
| Objective | `paths.objects.objective` | `objects/objectives/` |
| Rule | `paths.objects.rule` | `objects/rules/` |

Registered objects list: `threat`, `objective`, `rule`.

### `.opentide/` layout

| Path | Purpose | Client may override config? |
|------|---------|----------------------------|
| `.opentide/configurations/` | TOML overrides (paths, deployment, schema, platforms) | Yes |
| `.opentide/configurations/platforms/` | Per-platform TOML | Yes |
| `.opentide/configurations/sharing.toml` | Every sharing integration block (`[[misp]]`) | Yes |
| `.opentide/states/sharing.jsonl` | Current sharing synchronization ledger. One JSON object per line. Regenerable cache; SHOULD be gitignored. | No |
| `.opentide/states/deployment/` | Deployment state: one `<uuid>.json` shard (`deployment.state::1.0`) per rule holding the Defender for Endpoint, SentinelOne, and CrowdStrike rule ids per tenant. Authoritative; MUST be committed. | No |
| `.opentide/schemas/` | Generated JSON Schema | No |
| `.opentide/templates/` | Generated YAML templates | No |
| `.opentide/exports/` | Generated exports | No |
| `.opentide/inflight/` | CI preview shards for open PR/MR object changes | No |

### Documentation mirror paths

| Key | Default path |
|-----|--------------|
| `paths.docs.root` | `docs/` |
| `paths.docs.rules` | `docs/rules/` |
| `paths.docs.objectives` | `docs/objectives/` |
| `paths.docs.threats` | `docs/threats/` |

### Generated schema artifacts

| Family | Artifact filename |
|--------|-------------------|
| threat | `threat.1.0.schema.json` |
| objective | `objective.1.0.schema.json` |
| objective | `objective.1.1.schema.json` |
| rule | `rule.1.0.schema.json` |
| visibility | `visibility.1.0.schema.json` |
| router | `opentide.schema.json` |
| inflight shard | `inflight.shard.1.0.schema.json` |

Inflight shard schema source of truth: [schemas/inflight.shard.1.0.schema.json](../schemas/inflight.shard.1.0.schema.json). Deployment state shard schema source of truth: [schemas/deployment.state.1.0.schema.json](../schemas/deployment.state.1.0.schema.json). Generated copies MAY be emitted to `.opentide/schemas/` by `opentide generate schemas` when supported.

`visibility.1.0.schema.json` is **not** an object family — there are no `visibility` objects under `objects/`. It is the schema used to validate the client `visibility.toml` [configuration](configuration.md), emitted here alongside the object schemas. `opentide.schema.json` is the IDE router that dispatches object YAML to the correct object schema by `metadata.schema`.

### Generated template artifacts

| Family | Template filename |
|--------|-------------------|
| threat | `threat.1.0.template.yaml` |
| objective | `objective.1.0.template.yaml` |
| objective | `objective.1.1.template.yaml` |
| rule | `rule.1.0.template.yaml` |

### Export artifacts

| Key | Filename |
|-----|----------|
| `artifacts.exports.revisions` | `revisions.export.json` |
| `artifacts.exports.objects` | `objects.export.json` |
| `artifacts.exports.attack_layer` | `attack-navigator.json` |

### Other paths

| Key | Default |
|-----|---------|
| `paths.opentide.root` | `.opentide/` |
| `paths.opentide.schemas` | `.opentide/schemas/` |
| `paths.opentide.templates` | `.opentide/templates/` |
| `paths.exports.root` | `.opentide/exports/` |
| `paths.objects.snippet_file` | `.vscode/model-templates.code-snippets` |

### Example workspace tree

```
detection-repo/
├── objects/
│   ├── threats/
│   ├── objectives/
│   └── rules/
├── docs/
│   ├── rules/
│   ├── threats/
│   └── objectives/
├── .opentide/
│   ├── configurations/
│   │   └── platforms/
│   ├── schemas/
│   ├── templates/
│   ├── exports/
│   ├── inflight/
│   └── states/
│       ├── deployment/
│       │   └── <uuid>.json
│       └── sharing.jsonl
├── .vscode/
├── .github/workflows/
├── README.md
└── .gitignore
```

### Inflight preview shards

CI writes one JSON file per changed object UUID under `.opentide/inflight/<uuid>.json` on pull requests and merge requests. Shards use schema `inflight.shard::1.0` and wrap the parsed object document plus PR/MR metadata:

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | Always `inflight.shard::1.0` |
| `written_at` | string (ISO-8601) | When the shard was written |
| `object` | object | Full parsed threat, objective, or rule document |
| `change` | object | PR/MR provenance (`platform`, `number`, `url`, `title`, `head_ref`, `base_ref`, `head_sha`, `source_path`, `recorded_at`) |

Consumers overlay shards onto the committed registry when the shard object `metadata.version` is greater than the committed version, or equal with a wrapped shard (preview wins on ties). After merge to the default branch, `opentide generate inflight prune` removes shards superseded by committed YAML.

#### CI metadata sources

| Platform | Detected when | Primary env vars |
|----------|---------------|------------------|
| GitHub Actions | `GITHUB_ACTIONS` set | `GITHUB_EVENT_PATH` (pull_request payload), `GITHUB_HEAD_REF`, `GITHUB_BASE_REF`, `GITHUB_SHA` |
| GitLab CI | `CI` set (and not GitHub/Azure) | `CI_MERGE_REQUEST_IID`, `CI_PROJECT_URL`, `CI_MERGE_REQUEST_TITLE`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, `CI_COMMIT_SHA` |
| Azure Pipelines | `TF_BUILD` set | `SYSTEM_PULLREQUEST_PULLREQUESTNUMBER` or `SYSTEM_PULLREQUEST_PULLREQUESTID`, `SYSTEM_PULLREQUEST_PULLREQUESTURI`, `SYSTEM_PULLREQUEST_PULLREQUESTTITLE`, `SYSTEM_PULLREQUEST_SOURCEBRANCH`, `SYSTEM_PULLREQUEST_TARGETBRANCH`, `BUILD_SOURCEVERSION` |
| Local | none of the above | `INFLIGHT_CHANGE_JSON` optional override |

`change.source_path` is the object YAML path relative to the workspace root (`OPENTIDE_REPO_ROOT`).

#### CI jobs

| Job id | Trigger | Command |
|--------|---------|---------|
| `inflight_shards` | pull request / merge request | `opentide generate inflight` |
| `inflight_prune` | push to default branch | `opentide generate inflight prune` |
| `share` | push to the default branch only, and only when setup selected the sharing stage | `opentide share push --changed` |
| `deploy_production` | push to the default branch | `opentide deploy --plan PRODUCTION`, then the deployment-state write-back whenever the deploy started ([below](#production-deployment-state)) |

`share` is the production release. Setup defaults the stage off (`--no-sharing`; the wizard checkbox is unchecked). `opentide setup` MUST NOT emit it, or any other `opentide share` command, on a pull request or merge request. The trigger, the setup choice, and the diff are specified in [sharing.md](sharing.md#setup).

### Production deployment state

The production deploy job (`opentide deploy --plan PRODUCTION` on the default branch) is the only generated job that commits deployment state. `opentide setup` and `opentide setup ci` MUST generate it to meet [deployment-state.md CI requirements 1–7](deployment-state.md#continuous-integration):

1. Queue production jobs without dropping runs (no GitHub `concurrency` group, GitLab `resource_group`, Azure the strongest available lock, documented).
2. Before the dry run and the deploy, overlay `.opentide/states/deployment/` from the default-branch tip.
3. Run the write-back whenever the deploy started, including after a failure, a cancellation, or a timeout.
4. Stage shards independently of rule files; commit rule files only when `opentide validate --strict` passes on exactly those files, read NUL-delimited.
5. On a rebase conflict, replay this run's state delta per platform and tenant (`opentide deploy replay-state`); a concurrent change to the same binding is `deployment_state_conflict` and fails the job.
6. On every terminal write-back failure, print the state diff and push the commit to `refs/opentide/deployment-state/<commit>` before failing.
7. Log every recorded id as `external_id_recorded` at `WARNING`.

Staging, pull-request, and merge-request deploy jobs MUST NOT commit deployment state. A create on Defender for Endpoint, SentinelOne, or CrowdStrike in those jobs is refused with `deployment_state_unpersisted` before the vendor call ([deployment-state.md](deployment-state.md#the-run-cannot-persist-state)).

## Relationships

- [configuration.md](configuration.md) — how `paths.toml` is merged and overridden
- [deployment-state.md](deployment-state.md) — `.opentide/states/deployment/` and the production write-back
- [versioning.md](versioning.md) — schema artifact naming
- Object specs — where instances are stored

## Defaults & overrides

Bundled `paths.toml` ships in the opentide package. Clients MAY override path values via `.opentide/configurations/paths.toml`. See [configuration.md](configuration.md).

## Examples

Object fixtures assume the default layout: rules under `objects/rules/`, etc.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.4 | 2026-10-19 | `objective::1.1` schema and template artifacts beside `objective::1.0` ([RFC 0011](../rfcs/0011-signal-reuse.md)). |
| 1.3 | 2026-10-19 | Object instances are the YAML files placed directly in each family directory. A file in a subfolder is not an instance and is neither deployed nor shared ([specifications#16](https://github.com/opentidehq/specifications/pull/16), [opentide#312](https://github.com/opentidehq/opentide/issues/312)). |
| 1.2 | 2026-10-16 | The production deploy job has no GitHub Actions `concurrency` group ([specifications#43](https://github.com/opentidehq/specifications/issues/43)). |
| 1.1 | 2026-10-16 | `.opentide/states/deployment/` holds committed deployment-state shards; `.opentide/states/` is never ignored whole and setup ignores `sharing.jsonl` only. The production deploy job serialises, overlays the default branch's state, and writes it back, and staging jobs cannot create on state-backed platforms ([RFC 0010](../rfcs/0010-deployment-external-ids.md)). |
| 1.0 | 2026-09-28 | Optional CI stage `share` runs `opentide share push --changed` on a push to the default branch. |
| 1.0 | 2026-09-28 | Sharing uses one client file, `sharing.toml`, and one generated ledger, `.opentide/states/sharing.jsonl`. |
| 1.0 | 2026-06-25 | Initial spec from opentide `paths.toml` |
