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
| `.opentide/inflight/` | CI preview shards (future) | No |

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
