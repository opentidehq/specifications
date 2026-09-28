# Changelog

Per-spec change history. Breaking changes require a new spec file version and an RFC.

## versioning 1.0

- Initial normative spec bootstrapped from opentide `SCHEMA_REVISION.md`.

## metadata 1.1

- Optional `metadata.pap` ([RFC 0005](rfcs/0005-sharing-system.md)). `metadata.organisation.uuid` is the default sharing publishing organisation.

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

- Client sharing file `sharing.toml`, plus generated `.opentide/sharing/state.json` and preview output under `.opentide/exports/sharing/<name>/`.
- Initial normative spec bootstrapped from opentide `paths.toml`.

## configuration 1.0

- `sharing.toml` is overridable. Its top-level arrays of tables (`[[misp]]`) merge by `name`; every other array still replaces. `sharing/` is not a configuration location.
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

## sharing 1.0

- Sharing system ([RFC 0005](rfcs/0005-sharing-system.md)). One `sharing.toml` whose top level holds only integration arrays (`[[misp]]`; `[[opencti]]` reserved for a later connector). Each block carries its own selection and `max_tlp`; there are no global keys.

## sharing-misp 1.0

- MISP connector `sharing::misp::1.0`. Document transport via upstream `opentide` template version 5.
- Minimal `[[misp]]` block: `name`, `enabled`, `url`, `api_key`, `max_tlp`, `object_types`, `rule_statuses`, optional `organisation_uuid`, `publish`, `verify_ssl`.
- Publishing organisation from `metadata.organisation.uuid`, overridable per block. Distribution derived from `metadata.tlp`; no sharing groups, file mode, title prefix, or extra tags in 1.0.

## validation 1.0

- `sharing-config` checker codes and fixtures for `[[misp]]` blocks, including the merge-by-`name` fixture.
- Document specifications-repo fixture checker codes for `threat::1.0` list and `ThreatActor` encoding ([#11](https://github.com/OpenTideHQ/specifications/issues/11), [#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Initial normative spec bootstrapped from opentide validation pipeline.
