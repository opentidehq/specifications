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

## objective 1.1

- New schema `objective::1.1` ([RFC 0007](rfcs/0007-signal-reuse.md)). A signal entry may be a definition or `reuse: <signal-uuid>`, binding a signal defined on another objective already in the repository. `objective::1.0` stays normative for definition-only objectives and is not deprecated.

## objective 1.0

- Signal bindings are `objective::1.1`. Field tables unchanged ([RFC 0007](rfcs/0007-signal-reuse.md)).
- Initial normative spec bootstrapped from opentide `models/objective.py`.

## rule 1.0

- `detection_model` may name `objective::1.0` or `objective::1.1`. Indirect coverage comes from `reuse` ([RFC 0007](rfcs/0007-signal-reuse.md)).
- Initial normative spec bootstrapped from opentide `models/rule.py` (exemplar template).

## workspace 1.0

- `objective.1.1.schema.json` and `objective.1.1.template.yaml` beside the 1.0 artifacts ([RFC 0007](rfcs/0007-signal-reuse.md)).
- CI stage `share`, written only when setup selects it: `opentide share push --changed` on a push to the default branch ([RFC 0006](rfcs/0006-sharing-ci.md)).
- Client sharing file `sharing.toml`, plus one generated ledger, `.opentide/states/sharing.jsonl`. `preview` writes no files.
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

- `signal` model vocabulary for `objective::1.1` `reuse` ([RFC 0007](rfcs/0007-signal-reuse.md)).
- Initial normative spec bootstrapped from opentide `generation/schema_pipeline.py`.

## platforms 1.0

- Initial capability matrix for seven bundled platforms.

## sharing 1.0

- Production CI stage ([RFC 0006](rfcs/0006-sharing-ci.md)). `opentide setup` and `opentide setup ci` offer a sharing stage, default off (`--sharing` / `--no-sharing`, wizard checkbox "Sharing on the default branch"). When selected, the stage runs `opentide share push --changed` on a push to the default branch and does not run on a pull request or merge request. `--changed` uses the `deploy --plan PRODUCTION` diff across threat, objective, and rule files.
- Sharing system ([RFC 0005](rfcs/0005-sharing-system.md)). One `sharing.toml` whose top level holds only integration arrays (`[[misp]]`; `[[opencti]]` reserved for a later connector). Each block carries its own selection and `max_tlp`; there are no global keys. Current share state is `.opentide/states/sharing.jsonl`, one line per object and destination, with a `state` of `synced` or `retracted`.

## sharing-misp 1.0

- `objective::1.1` `opentide-relation` values include the owner of each `reuse` binding ([RFC 0007](rfcs/0007-signal-reuse.md)).
- MISP connector `sharing::misp::1.0`. Document transport via upstream `opentide` template version 5.
- Minimal `[[misp]]` block: required `name`, `url`, `api_key`, and `max_tlp`; optional `enabled`, `object_types`, `rule_statuses`, `organisation_uuid`, `publish`, `verify_ssl`.
- Publishing organisation from the block override, otherwise `metadata.organisation.uuid`. An object with neither fails. No fallback to the API key's organisation.
- Distribution derived from `metadata.tlp`. `max_tlp = "red"` shares TLP:RED. No sharing groups, file mode, title prefix, or extra tags in 1.0.
- `content_hash` is the SHA-256 of the verbatim UTF-8 object document, lowercase hex.

## validation 1.0

- Checker codes for `objective::1.1` bindings: `signal_entry_mixed`, `invalid_uuid` on `reuse`, `binding_requires_1_1` ([RFC 0007](rfcs/0007-signal-reuse.md)).
- `sharing-config` checker codes and fixtures for `[[misp]]` blocks, including the merge-by-`name` fixture.
- Document specifications-repo fixture checker codes for `threat::1.0` list and `ThreatActor` encoding ([#11](https://github.com/OpenTideHQ/specifications/issues/11), [#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Initial normative spec bootstrapped from opentide validation pipeline.
