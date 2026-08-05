# OpenTide Specifications

This repository defines **normative OpenTide specifications** — not a documentation website.

| Content | Location |
|---------|----------|
| Normative specs | [`specs/`](specs/) |
| Canonical vocabularies | [`vocabularies/`](vocabularies/) |
| Conformance fixtures | [`fixtures/`](fixtures/) |
| Change proposals | [`rfcs/`](rfcs/) |

The [opentide](https://github.com/OpenTideHQ/opentide) implementation consumes these specs. JSON Schema is generated from Pydantic models in opentide; it is an artifact, not the source of truth.

Published reading experience (opentide.org) lives in a separate **website** repo. This repo is a versioned specification library for authors, maintainers, and agents.

## Quick links

- [Spec index](SPECS.md)
- [Governance & change process](GOVERNANCE.md)
- [Agent guide](AGENTS.md)
- [RFC 0001 — Authority model](rfcs/0001-authority-model.md)

## Versioning

There is no framework-wide version. Each spec carries its own `version` in frontmatter (e.g. `rule` 1.0). Object instances use semver in `metadata.version`; schema revisions use `metadata.schema` (e.g. `rule::1.0`).

## License

Specifications are licensed under [CC-BY-4.0](LICENSE).
