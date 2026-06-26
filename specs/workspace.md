---
spec: workspace
version: "1.0"
schema_id: null
status: normative
supersedes: null
---

# Workspace layout

## Summary

Defines the standard detection-repository directory layout scaffolded by `opentide setup` and used for object storage, generated artifacts, documentation mirrors, and client configuration overrides.

## Requirements

- A healthy OpenTide workspace MUST contain `objects/` with subdirectories for each core object family.
- Generated artifacts MUST live under `.opentide/` — not committed as hand-edited sources.
- Client configuration overrides MUST live only under `.opentide/configurations/`.
- Object YAML files MUST reside in the paths defined by merged `paths.toml` configuration.
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
| rule | `rule.1.0.schema.json` |
| visibility | `visibility.1.0.schema.json` |
| router | `opentide.schema.json` |
| inflight shard | `inflight.shard.1.0.schema.json` |

Inflight shard schema source of truth: [schemas/inflight.shard.1.0.schema.json](../schemas/inflight.shard.1.0.schema.json). Generated copies MAY be emitted to `.opentide/schemas/` by `opentide generate schemas` when supported.

### Generated template artifacts

| Family | Template filename |
|--------|-------------------|
| threat | `threat.1.0.template.yaml` |
| objective | `objective.1.0.template.yaml` |
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
│   └── inflight/
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

## Relationships

- [configuration.md](configuration.md) — how `paths.toml` is merged and overridden
- [versioning.md](versioning.md) — schema artifact naming
- Object specs — where instances are stored

## Defaults & overrides

Bundled `paths.toml` ships in the opentide package. Clients MAY override path values via `.opentide/configurations/paths.toml`. See [configuration.md](configuration.md).

## Examples

Object fixtures assume the default layout: rules under `objects/rules/`, etc.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-06-25 | Initial spec from opentide `paths.toml` |
