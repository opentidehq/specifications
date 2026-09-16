# Changelog

Per-spec change history. Breaking changes require a new spec file version and an RFC.

## versioning 1.0

- Initial normative spec bootstrapped from opentide `SCHEMA_REVISION.md`.

## metadata 1.0

- Initial normative spec bootstrapped from opentide `models/metadata.py`.

## threat 1.0

- Correct `threat.impact` and `threat.leverage` to non-empty `list[string]`; semicolon-packed strings are invalid and MUST NOT collapse to the first token ([#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Correct `threat.actors` to `list[ThreatActor]` with scoped `name`; pin path is `threat.actors.name` ([#11](https://github.com/OpenTideHQ/specifications/issues/11)).
- Initial normative spec bootstrapped from opentide `models/threat.py`.

## objective 1.0

- Initial normative spec bootstrapped from opentide `models/objective.py`.

## rule 1.0

- Initial normative spec bootstrapped from opentide `models/rule.py` (exemplar template).

## workspace 1.0

- Initial normative spec bootstrapped from opentide `paths.toml`.

## configuration 1.0

- Initial normative spec bootstrapped from opentide `core/files.py`.

## vocabulary format 1.0

- Initial normative spec bootstrapped from opentide `vocabulary.schema.json`.

## vocabulary catalog 1.0

- Initial catalog of 36 bundled vocabularies copied from opentide.

## deployment 1.0

- Initial normative spec bootstrapped from opentide `deployment.toml`.

## metaschema-keywords 1.0

- Initial normative spec bootstrapped from opentide `generation/schema_pipeline.py`.

## platforms 1.0

- Initial capability matrix for seven bundled platforms.

## validation 1.0

- Document specifications-repo fixture checker codes for `threat::1.0` list and `ThreatActor` encoding ([#11](https://github.com/OpenTideHQ/specifications/issues/11), [#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Initial normative spec bootstrapped from opentide validation pipeline.
