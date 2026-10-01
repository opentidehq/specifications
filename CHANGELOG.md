# Changelog

Per-spec change history. Breaking changes require a new spec file version and an RFC.

## versioning 1.1

- Every supported schema revision works for validation, deployment, documentation, export, query checks, promotion, sharing, and editor validation. A missing schema is an error. Migration is explicit and does not change `metadata.version`.

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

- Initial normative spec bootstrapped from opentide `generation/schema_pipeline.py`.

## platforms 1.0

- Field tables mark every key `yes` or `optional` for static validation. Exclusion `query` is required (an empty string is accepted). Sentinel, SentinelOne, CrowdStrike, and HarfangLab loaders drop unmapped keys; Defender, Splunk, and Carbon Black reject an unknown key at the block root. The Splunk loader drops unknown keys inside `scheduling`. Generated JSON Schema defaults `schema` to the legacy identifier, and the Splunk and Carbon Black overlays reject the canonical `platform::<identifier>::1.0` with a legacy `pattern`.
- Per-platform field contracts for the seven bundled blocks (`platform::<identifier>::1.0`). Static validation, registry load, and deploy are specified separately. Generated JSON Schema is not the field contract.
- Initial capability matrix for seven bundled platforms.

## platform-sentinel 1.0

- `platform::sentinel::1.0`. KQL analytics rule: `query`, `scheduling`, `alert`, plus grouping, entities, exclusions, template, and trigger. `grouping` is required at deploy and optional at validation.

## platform-defender-for-endpoint 1.0

- `platform::defender_for_endpoint::1.0`. KQL custom detection: `query`, `alert.category`, `impacted_entities`, `scheduling` (`NRT`, `1H`, `3H`, `12H`, `24H`), response actions, and exclusions. Registry load requires `scope`.

## platform-splunk 1.0

- `platform::splunk::1.0`. SPL saved search with scheduling, trigger, notable, risk, and email. `splunk::2.x` flat keys normalise onto this layout for both validate and deploy.

## platform-sentinel-one 1.0

- `platform::sentinel_one::1.0`. STAR rule: `Single Event` or `Correlation`, optional response and details.

## platform-carbon-black-cloud 1.0

- `platform::carbon_black_cloud::1.0`. Lucene IOC on an existing watchlist report. Severity comes from `response.alert_severity`.

## platform-crowdstrike 1.0

- `platform::crowdstrike::1.0`. Correlation rule: filter `query`, `details.trigger` (`verbose` or `summary`), `details.outcome` (`detection` or `incident`), and `schedule`. No query validator.

## platform-harfanglab 1.0

- `platform::harfanglab::1.0`. Sigma or YARA rule. Identity is `metadata.uuid`. No query validator. Deploy requires one of `sigma` or `yara`; validation does not.

## sharing 1.0

- Production CI stage ([RFC 0006](rfcs/0006-sharing-ci.md)). `opentide setup` and `opentide setup ci` offer a sharing stage, default off (`--sharing` / `--no-sharing`, wizard checkbox "Sharing on the default branch"). When selected, the stage runs `opentide share push --changed` on a push to the default branch and does not run on a pull request or merge request. `--changed` uses the `deploy --plan PRODUCTION` diff across threat, objective, and rule files.
- Sharing system ([RFC 0005](rfcs/0005-sharing-system.md)). One `sharing.toml` whose top level holds only integration arrays (`[[misp]]`; `[[opencti]]` reserved for a later connector). Each block carries its own selection and `max_tlp`; there are no global keys. Current share state is `.opentide/states/sharing.jsonl`, one line per object and destination, with a `state` of `synced` or `retracted`.

## sharing-misp 1.0

- MISP connector `sharing::misp::1.0`. Document transport via upstream `opentide` template version 5.
- Minimal `[[misp]]` block: required `name`, `url`, `api_key`, and `max_tlp`; optional `enabled`, `object_types`, `rule_statuses`, `organisation_uuid`, `publish`, `verify_ssl`.
- Publishing organisation from the block override, otherwise `metadata.organisation.uuid`. An object with neither fails. No fallback to the API key's organisation.
- Distribution derived from `metadata.tlp`. `max_tlp = "red"` shares TLP:RED. No sharing groups, file mode, title prefix, or extra tags in 1.0.
- `content_hash` is the SHA-256 of the verbatim UTF-8 object document, lowercase hex.

## validation 1.0

- `sharing-config` checker codes and fixtures for `[[misp]]` blocks, including the merge-by-`name` fixture.
- Document specifications-repo fixture checker codes for `threat::1.0` list and `ThreatActor` encoding ([#11](https://github.com/OpenTideHQ/specifications/issues/11), [#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Initial normative spec bootstrapped from opentide validation pipeline.
