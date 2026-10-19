# Changelog

Per-spec change history. Breaking changes require a new spec file version and an RFC.

## versioning 1.1

- Every supported schema revision works for validation, deployment, documentation, export, query checks, promotion, sharing, and editor validation. A missing schema is an error. Migration is explicit and does not change `metadata.version` ([specifications#27](https://github.com/OpenTideHQ/specifications/pull/27); implementation gap: [opentide#394](https://github.com/OpenTideHQ/opentide/issues/394)).

## versioning 1.0

- Initial normative spec bootstrapped from opentide `SCHEMA_REVISION.md`.

## metadata 1.2

- Optional `metadata.reviewed` on `rule::1.1` only ([RFC 0008](rfcs/0008-rule-reviewed-date.md)). `rule::1.0`, `threat::1.0`, and `objective::1.0` reject the field.

## metadata 1.1

- Optional `metadata.pap` ([RFC 0005](rfcs/0005-sharing-system.md)). `metadata.organisation.uuid` is the default sharing publishing organisation.

## metadata 1.0

- Initial normative spec bootstrapped from opentide `models/metadata.py`.

## threat 1.0

- Correct `threat.surface` to stage-scoped values (`<stage>::<key>`, e.g. `OS::Windows::Desktop`). The vocabulary groups keys under stages and the same key name is defined under two of them — `VPN`, `VPN::OpenVPN`, `VPN::WireGuard`, `Wireless` and `Industrial` are each both `Infrastructure` and `Protocol` — so a bare key name was ambiguous and those five values were unreachable. The prior description asserting values "are not prefixed with the stage id" was wrong and is corrected in place; no vocabulary version bump, as `surface::1.0` key names are unchanged and only the authored encoding is corrected.
- Bump `threat.actors.name` pin to `actors::1.1`. The 220 galaxy clusters added at `actors::1.1` were present in the vocabulary but unreachable behind the `actors::1.0` pin, so a correctly-authored MISP cluster UUID was reported as an unknown vocabulary value. Additive minor; `actors::1.0` keys are unaffected.
- Correct `threat.impact` and `threat.leverage` to non-empty `list[string]`; semicolon-packed strings are invalid and MUST NOT collapse to the first token ([#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Correct `threat.actors` to `list[ThreatActor]` with scoped `name`; pin path is `threat.actors.name` ([#11](https://github.com/OpenTideHQ/specifications/issues/11)).
- Initial normative spec bootstrapped from opentide `models/threat.py`.

## objective 1.0

- `objective.signals[].effort` is an integer implementation-effort score from 1 to 10 and is no longer pinned to the `efforts` vocabulary. The type said integer while the pin named four string categories, so no authored value could satisfy both ([#42](https://github.com/OpenTideHQ/specifications/issues/42)).
- `objective.signals[].entities` is stage-scoped: an authored value is `<stage>::<key>` (`Host::Process`). Seven of the 28 keys are defined under two stages, so the bare key name could not tell a host account from a cloud account and seven values were unreachable. Stage ids are capitalised to `Host`, `Network`, `Cloud`. No key changes, so `signal.entities::1.0` is unaffected ([RFC 0005](rfcs/0005-scoped-signal-entities.md)).
- Initial normative spec bootstrapped from opentide `models/objective.py`.

## rule 1.1

- Minor MDR revision `rule::1.1` with optional `metadata.reviewed` ([RFC 0008](rfcs/0008-rule-reviewed-date.md)). `rule::1.0` remains normative. A consumer treats `rule::1.0`, a missing `reviewed`, or a `reviewed` instant older than a supplied window as unreviewed.

## rule 1.0

- Initial normative spec bootstrapped from opentide `models/rule.py` (exemplar template).

## workspace 1.3

- An object instance is a YAML file placed directly in its family directory; a file in a subfolder is not an instance and MUST NOT be deployed or shared ([specifications#16](https://github.com/OpenTideHQ/specifications/pull/16), [opentide#312](https://github.com/OpenTideHQ/opentide/issues/312)).

## workspace 1.2

- The production deploy job queues without dropping runs: GitHub Actions has no `concurrency` group, because GitHub cancels a pending run and its commit's diff would never deploy ([specifications#43](https://github.com/OpenTideHQ/specifications/issues/43)).

## workspace 1.1

- `.opentide/states/deployment/` holds committed deployment-state shards ([RFC 0010](rfcs/0010-deployment-external-ids.md)). `.opentide/states/sharing.jsonl` stays a gitignored cache, and `.opentide/states/` is never ignored as a whole.
- The production deploy job (`deploy_production`) serialises, overlays the default branch's deployment state before deploying, and writes it back whenever the deploy started. Staging, pull-request, and merge-request jobs cannot create on Defender for Endpoint, SentinelOne, or CrowdStrike.

## workspace 1.0

- CI stage `share`, written only when setup selects it: `opentide share push --changed` on a push to the default branch ([RFC 0006](rfcs/0006-sharing-ci.md)).
- Client sharing file `sharing.toml`, plus one generated ledger, `.opentide/states/sharing.jsonl`. `preview` writes no files.
- Initial normative spec bootstrapped from opentide `paths.toml`.

## configuration 1.0

- `sharing.toml` is overridable. Its top-level arrays of tables (`[[misp]]`) merge by `name`; every other array still replaces. `sharing/` is not a configuration location.
- Initial normative spec bootstrapped from opentide `core/files.py`.

## vocabulary format 1.0

- Staged vocabularies state one prefixing rule: a field bound to a staged vocabulary declares `tide.vocab.scoped` and authors `<stage>::<key>`. Records that a key name may itself contain `::`, and that resolution is therefore raw-first; and that scoping triggers no contract revision under RFC 0003.
- Initial normative spec bootstrapped from opentide `vocabulary.schema.json`.

## vocabulary catalog 1.0

- `responders.vocab.toml` is retired. It shipped with `keys = []` while `response.responders` was pinned to it, so every authored value failed validation and no instance could fix it (vocabularies are not locally extensible). The alert handling team is per-organisation configuration: the field is free text defaulted from `[deployment] default_responders` (opentide#507).
- Initial catalog of 36 bundled vocabularies copied from opentide.

## deployment 1.2

- `opentide deploy` selects only the rule files placed directly in the configured rules directory ([specifications#16](https://github.com/OpenTideHQ/specifications/pull/16)).

## deployment 1.1

- Update, disablement, and deletion on Defender for Endpoint, SentinelOne, and CrowdStrike use the tenant binding in deployment state. A create needs a destination that is not ignored and a run that can persist state. `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` as a warning ([RFC 0010](rfcs/0010-deployment-external-ids.md)).

## deployment 1.0

- Initial normative spec bootstrapped from opentide `deployment.toml`.

## deployment-state 1.1

- CI requirement 1: GitHub Actions MUST NOT put the production job in a `concurrency` group. GitHub cancels an older pending run even with `cancel-in-progress: false`, and the cancelled commit's diff-scoped deploy would be lost silently. Overlapping runs are bounded by the overlay and replay requirements, which report `deployment_state_conflict` ([specifications#43](https://github.com/OpenTideHQ/specifications/issues/43)). The shard schema `deployment.state::1.0` is unchanged.

## deployment-state 1.0

- Committed per-rule vendor-id shards (`deployment.state::1.0`) at `.opentide/states/deployment/<uuid>.json` for Defender for Endpoint, SentinelOne, and CrowdStrike, with a lowercase canonical filename, string ids, and a canonical writer form ([RFC 0010](rfcs/0010-deployment-external-ids.md)).
- Mandatory migration (`opentide deploy migrate-state`): state-backed bindings move to shards; legacy keys on every other platform are removed as `external_id_unused`.
- Fail-closed deployment: `external_id_in_rule` on every path; `deployment_state_ignored` and `deployment_state_unpersisted` refuse creates before the vendor call; `external_id_missing` is a warning.
- CI persistence: serialised production jobs, default-branch state overlay, write-back on failure, cancellation, and timeout, per-tenant conflict replay (`deployment_state_conflict`), and a `refs/opentide/deployment-state/<commit>` side ref on every terminal failure.
- The complete diagnostic catalogue and exit semantics. JSON Schema `schemas/deployment.state.1.0.schema.json` and fixtures under `fixtures/deployment/`.

## metaschema-keywords 1.0

- Initial normative spec bootstrapped from opentide `generation/schema_pipeline.py`.

## platforms 1.1

- Platform blocks carry no external ids. `rule_id`, `rule_id_bundle`, and the `rule_id::<tenant>` loader alias are removed from every block and fail `external_id_in_rule`. Defender for Endpoint, SentinelOne, and CrowdStrike ids live in deployment state ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Elastic ([RFC 0007](rfcs/0007-elastic-security-platform.md)) addresses rules by `metadata.uuid` and never stores an external id. Platform `schema_id`s stay `::1.0`.

## platforms 1.0

- Field tables mark every key `yes` or `optional` for static validation. Exclusion `query` is required (an empty string is accepted). Sentinel, SentinelOne, CrowdStrike, and HarfangLab loaders drop unmapped keys; Defender, Splunk, and Carbon Black reject an unknown key at the block root. The Splunk loader drops unknown keys inside `scheduling`. Generated JSON Schema defaults `schema` to the legacy identifier, and the Splunk and Carbon Black overlays reject the canonical `platform::<identifier>::1.0` with a legacy `pattern`.
- Per-platform field contracts for the seven bundled blocks (`platform::<identifier>::1.0`). Static validation, registry load, and deploy are specified separately. Generated JSON Schema is not the field contract.
- Initial capability matrix for seven bundled platforms.

## platform-sentinel 1.0

- `platform::sentinel::1.0`. KQL analytics rule: `query`, `scheduling`, `alert`, plus grouping, entities, exclusions, template, and trigger. `grouping` is required at deploy and optional at validation.

## platform-defender-for-endpoint 1.1

- `rule_id` removed. The Defender rule id is read from and written to deployment state; `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Schema id unchanged.

## platform-defender-for-endpoint 1.0

- `platform::defender_for_endpoint::1.0`. KQL custom detection: `query`, `alert.category`, `impacted_entities`, `scheduling` (`NRT`, `1H`, `3H`, `12H`, `24H`), response actions, and exclusions. Registry load requires `scope`.

## platform-splunk 1.0

- `platform::splunk::1.0`. SPL saved search with scheduling, trigger, notable, risk, and email. `splunk::2.x` flat keys normalise onto this layout for both validate and deploy.

## platform-sentinel-one 1.1

- `rule_id_bundle` removed. The STAR rule id is read from and written to deployment state; `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Schema id unchanged.

## platform-sentinel-one 1.0

- `platform::sentinel_one::1.0`. STAR rule: `Single Event` or `Correlation`, optional response and details.

## platform-carbon-black-cloud 1.1

- `rule_id_bundle` removed. Legacy external-id keys fail `external_id_in_rule`; migration removes them as `external_id_unused`. Identity is unchanged: `metadata.uuid` for the IOC, the title for the report ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Schema id unchanged.

## platform-carbon-black-cloud 1.0

- `platform::carbon_black_cloud::1.0`. Lucene IOC on an existing watchlist report. Severity comes from `response.alert_severity`.

## platform-crowdstrike 1.1

- `rule_id_bundle` removed. The Falcon rule id is read from and written to deployment state; `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` ([RFC 0010](rfcs/0010-deployment-external-ids.md)). `DISABLEMENT` sends `inactive` and every other deployed strategy `active`; the note recording the reversed mapping is removed. Schema id unchanged.

## platform-crowdstrike 1.0

- `platform::crowdstrike::1.0`. Correlation rule: filter `query`, `details.trigger` (`verbose` or `summary`), `details.outcome` (`detection` or `incident`), and `schedule`. No query validator.

## platform-harfanglab 1.1

- `rule_id_bundle` removed. Legacy external-id keys fail `external_id_in_rule`; migration removes them as `external_id_unused`. Identity stays `metadata.uuid` ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Schema id unchanged.

## platform-harfanglab 1.0

- `platform::harfanglab::1.0`. Sigma or YARA rule. Identity is `metadata.uuid`. No query validator. Deploy requires one of `sigma` or `yara`; validation does not.

## sharing 1.1

- `.opentide/states/` holds sharing's regenerable cache and deployment's committed shards. A future subsystem states whether its state is a cache or an authoritative record and whether it is committed ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Ledger fields are unchanged.

## sharing 1.0

- Production CI stage ([RFC 0006](rfcs/0006-sharing-ci.md)). `opentide setup` and `opentide setup ci` offer a sharing stage, default off (`--sharing` / `--no-sharing`, wizard checkbox "Sharing on the default branch"). When selected, the stage runs `opentide share push --changed` on a push to the default branch and does not run on a pull request or merge request. `--changed` uses the `deploy --plan PRODUCTION` diff across threat, objective, and rule files.
- Sharing system ([RFC 0005](rfcs/0005-sharing-system.md)). One `sharing.toml` whose top level holds only integration arrays (`[[misp]]`; `[[opencti]]` reserved for a later connector). Each block carries its own selection and `max_tlp`; there are no global keys. Current share state is `.opentide/states/sharing.jsonl`, one line per object and destination, with a `state` of `synced` or `retracted`.

## sharing-misp 1.0

- MISP connector `sharing::misp::1.0`. Document transport via upstream `opentide` template version 5.
- Minimal `[[misp]]` block: required `name`, `url`, `api_key`, and `max_tlp`; optional `enabled`, `object_types`, `rule_statuses`, `organisation_uuid`, `publish`, `verify_ssl`.
- Publishing organisation from the block override, otherwise `metadata.organisation.uuid`. An object with neither fails. No fallback to the API key's organisation.
- Distribution derived from `metadata.tlp`. `max_tlp = "red"` shares TLP:RED. No sharing groups, file mode, title prefix, or extra tags in 1.0.
- `content_hash` is the SHA-256 of the verbatim UTF-8 object document, lowercase hex.

## validation 1.1

- `external_id_in_rule` for a legacy external-id key at the root of any platform block, replacing the generic unknown-key error. Full-workspace validation checks every deployment-state shard, orphans included. Every `--file` target must match an object ([RFC 0010](rfcs/0010-deployment-external-ids.md)).
- Fixture checker `scripts/deployment_state_fixtures.py` and codes for `fixtures/deployment/`.

## validation 1.0

- Fixture checker codes `invalid_reviewed` and `reviewed_not_in_schema` for `metadata.reviewed` ([RFC 0008](rfcs/0008-rule-reviewed-date.md)).
- `sharing-config` checker codes and fixtures for `[[misp]]` blocks, including the merge-by-`name` fixture.
- Document specifications-repo fixture checker codes for `threat::1.0` list and `ThreatActor` encoding ([#11](https://github.com/OpenTideHQ/specifications/issues/11), [#12](https://github.com/OpenTideHQ/specifications/issues/12)).
- Initial normative spec bootstrapped from opentide validation pipeline.
