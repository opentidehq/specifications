# Changelog

Per-spec change history. Breaking changes require a new spec file version and an RFC.

## versioning 1.1

- Every supported schema revision works for validation, deployment, documentation, export, query checks, promotion, sharing, and editor validation. A missing schema is an error. Migration is explicit and does not change `metadata.version` ([specifications#27](https://github.com/opentidehq/specifications/pull/27); implementation gap: [opentide#394](https://github.com/opentidehq/opentide/issues/394)).

## versioning 1.0

- Initial normative spec bootstrapped from opentide `SCHEMA_REVISION.md`.

## metadata 1.2

- Optional `metadata.reviewed` on `rule::1.1` only ([RFC 0008](rfcs/0008-rule-reviewed-date.md)). `rule::1.0`, `threat::1.0`, and `objective::1.0` reject the field.

## metadata 1.1

- Optional `metadata.pap` ([RFC 0005](rfcs/0005-sharing-system.md)). `metadata.organisation.uuid` is the default sharing publishing organisation.

## metadata 1.0

- Initial normative spec bootstrapped from opentide `models/metadata.py`.

## threat 1.0

- Bump `threat.mitre_attack` pin to `att&ck::1.2` (ATT&CK 20.0). Additive minor; `att&ck::1.1` keys are unaffected ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- Correct `threat.surface` to stage-scoped values (`<stage>::<key>`, e.g. `OS::Windows::Desktop`). The vocabulary groups keys under stages and the same key name is defined under two of them — `VPN`, `VPN::OpenVPN`, `VPN::WireGuard`, `Wireless` and `Industrial` are each both `Infrastructure` and `Protocol` — so a bare key name was ambiguous and those five values were unreachable. The prior description asserting values "are not prefixed with the stage id" was wrong and is corrected in place; no vocabulary version bump, as `surface::1.0` key names are unchanged and only the authored encoding is corrected.
- Bump `threat.actors.name` pin to `actors::1.1`. The 220 galaxy clusters added at `actors::1.1` were present in the vocabulary but unreachable behind the `actors::1.0` pin, so a correctly-authored MISP cluster UUID was reported as an unknown vocabulary value. Additive minor; `actors::1.0` keys are unaffected.
- Correct `threat.impact` and `threat.leverage` to non-empty `list[string]`; semicolon-packed strings are invalid and MUST NOT collapse to the first token ([#12](https://github.com/opentidehq/specifications/issues/12)).
- Correct `threat.actors` to `list[ThreatActor]` with scoped `name`; pin path is `threat.actors.name` ([#11](https://github.com/opentidehq/specifications/issues/11)).
- Initial normative spec bootstrapped from opentide `models/threat.py`.

## objective 1.1

- `objective.mitre_attack` is pinned to `att&ck::1.2` (ATT&CK 20.0), as in `objective::1.0` ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- Draft schema `objective::1.1` ([RFC 0011](rfcs/0011-signal-reuse.md)). A signal entry may be a definition or `reuse: <signal-uuid>`, binding a signal defined on another objective already in the repository. `objective::1.0` stays normative for definition-only objectives and is not deprecated.

## objective 1.0

- Bump `objective.mitre_attack` pin to `att&ck::1.2` (ATT&CK 20.0). Additive minor; `att&ck::1.1` keys are unaffected ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- Rules reference an objective, or a signal defined under it, through `detection_model`.
- Signal bindings are `objective::1.1`. Field tables unchanged ([RFC 0011](rfcs/0011-signal-reuse.md)).
- `objective.signals[].effort` is an integer implementation-effort score from 1 to 10 and is no longer pinned to the `efforts` vocabulary. The type said integer while the pin named four string categories, so no authored value could satisfy both ([#42](https://github.com/opentidehq/specifications/issues/42)).
- `objective.signals[].entities` is stage-scoped: an authored value is `<stage>::<key>` (`Host::Process`). Seven of the 28 keys are defined under two stages, so the bare key name could not tell a host account from a cloud account and seven values were unreachable. Stage ids are capitalised to `Host`, `Network`, `Cloud`. No key changes, so `signal.entities::1.0` is unaffected ([RFC 0005](rfcs/0005-scoped-signal-entities.md)).
- Initial normative spec bootstrapped from opentide `models/objective.py`.

## rule 1.1

- Optional `response.procedure.searches[].language`, so an Elastic hunt can say which language its `query` is in: `kuery`, `lucene`, `eql`, or `esql`, the names elastic-1.0 uses. It is set only with `system: elastic`; every other system implies its language. Omitted means unknown and not analysed, as before ([specifications#58](https://github.com/opentidehq/specifications/issues/58)). Additive; `schema_id` stays `rule::1.1`. New fixtures `fixtures/valid/rule-1.1-search-language.yaml` (an ES|QL hunt) and `fixtures/invalid/rule-search-language.yaml`.
- Bump `techniques` pin to `att&ck::1.2` (ATT&CK 20.0). Additive minor; `att&ck::1.1` keys are unaffected ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- `configurations.elastic` (`ElasticConfig`, `platform::elastic::1.0`) is added ([RFC 0007](rfcs/0007-elastic-security-platform.md)). Additive; `schema_id` stays `rule::1.1`.
- Correct `detection_model`: it references an objective UUID or the UUID of any signal defined under an objective. Both are referenceable by design; a signal reference implements that signal, and its owning objective is the rule's objective. The objective-only wording was wrong. New fixture `fixtures/cross-object/rule-references-signal.yaml`.
- `detection_model` may name `objective::1.0` or `objective::1.1`. Indirect coverage comes from `reuse` ([RFC 0011](rfcs/0011-signal-reuse.md)).
- Minor MDR revision `rule::1.1` with optional `metadata.reviewed` ([RFC 0008](rfcs/0008-rule-reviewed-date.md)). `rule::1.0` remains normative. A consumer treats `rule::1.0`, a missing `reviewed`, or a `reviewed` instant older than a supplied window as unreviewed.

## rule 1.0

- Optional `response.procedure.searches[].language`, so an Elastic hunt can say which language its `query` is in: `kuery`, `lucene`, `eql`, or `esql`, the names elastic-1.0 uses. It is set only with `system: elastic`; every other system implies its language. Omitted means unknown and not analysed, as before ([specifications#58](https://github.com/opentidehq/specifications/issues/58)). Additive; `schema_id` stays `rule::1.0`. New fixtures `fixtures/valid/rule-1.1-search-language.yaml` (an ES|QL hunt) and `fixtures/invalid/rule-search-language.yaml`.
- Bump `techniques` pin to `att&ck::1.2` (ATT&CK 20.0). Additive minor; `att&ck::1.1` keys are unaffected ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- `configurations.elastic` (`ElasticConfig`, `platform::elastic::1.0`) is added ([RFC 0007](rfcs/0007-elastic-security-platform.md)). Additive; every existing rule stays valid and `schema_id` stays `rule::1.0`.
- Correct `detection_model`: it references an objective UUID or the UUID of any signal defined under an objective. Both are referenceable by design; a signal reference implements that signal, and its owning objective is the rule's objective. The objective-only wording was wrong. New fixture `fixtures/cross-object/rule-references-signal.yaml`.
- `detection_model` may name `objective::1.0` or `objective::1.1`. Indirect coverage comes from `reuse` ([RFC 0011](rfcs/0011-signal-reuse.md)).
- Initial normative spec bootstrapped from opentide `models/rule.py` (exemplar template).

## workspace 1.5

- The production deploy job runs `opentide deploy --strategy RELEASE`. opentide 0.17.0 removed deployment plans (`--plan`); the job and its requirements are unchanged.

## workspace 1.4

- `objective.1.1.schema.json` and `objective.1.1.template.yaml` beside the 1.0 artifacts ([RFC 0011](rfcs/0011-signal-reuse.md)).

## workspace 1.3

- An object instance is a YAML file placed directly in its family directory; a file in a subfolder is not an instance and MUST NOT be deployed or shared ([specifications#16](https://github.com/opentidehq/specifications/pull/16), [opentide#312](https://github.com/opentidehq/opentide/issues/312)).

## workspace 1.2

- The production deploy job queues without dropping runs: GitHub Actions has no `concurrency` group, because GitHub cancels a pending run and its commit's diff would never deploy ([specifications#43](https://github.com/opentidehq/specifications/issues/43)).

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

- `removed` excludes a key from contracts at or above its revision. The key table said "at or below", contradicting Contract resolution (`removed > M.m`); the rule itself is unchanged. Document the `source`, `source_version` and `source_fetched_at` provenance keys that generated vocabularies carry.
- Staged vocabularies state one prefixing rule: a field bound to a staged vocabulary declares `tide.vocab.scoped` and authors `<stage>::<key>`. Records that a key name may itself contain `::`, and that resolution is therefore raw-first; and that scoping triggers no contract revision under RFC 0003.
- Initial normative spec bootstrapped from opentide `vocabulary.schema.json`.

## vocabulary catalog 1.0

- `att&ck` restored to ATT&CK 19.2 at `1.1` and refreshed to ATT&CK 20.0 at `1.2` ([opentide#568](https://github.com/opentidehq/opentide/issues/568)). The canonical copy was ATT&CK v17 with no key at `1.1` while every technique pin named `att&ck::1.1`, so T1685–T1690, T1059.013 and the other v18/v19 techniques were rejected. `1.1` adds 60 keys (the set opentide 0.9.0–0.12.1 shipped) and `1.2` adds 19 (T1696–T1701 and sub-techniques, T1685.007, T1608.007, T1476, T0869.001/.002). 27 IDs that ATT&CK revoked or deprecated (T1562 and its sub-techniques, T1070.001/.002, T1656, T1672, eleven ICS techniques) get `removed = "2.0"`, so they still resolve under every `att&ck::1.x` pin. Live keys use the v19 tactics `Stealth` (TA0005, formerly Defense Evasion) and `Defense Impairment` (TA0112); RFC 0007's tactic table follows, and maps the legacy `Defense Evasion` stage of removed keys to `Stealth`. Six techniques take MITRE's renames (for example T1211 "Exploitation for Stealth"). Enterprise sub-technique names keep the `Parent: Sub` form. The header gains `source = "mitre-attack"` and `source_version = "20.0"`.
- The `att&ck` header `stages` list is the ATT&CK 20.0 enterprise matrix: `Stealth` and `Defense Impairment` replace `Defense Evasion`, and the `Priviledge Escalation` typo is fixed. Generated schema docs render only a key's stages that the header lists, so live keys staged `Stealth`, `Defense Impairment` or `Privilege Escalation` lost those stages. Key data is unchanged.
- `att&ck.groups` adds 41 groups at `1.1` and 2 at `1.2`; `mitigations` adds 1 at `1.1`; `datasources` adds 4 at `1.1`. No schema pins these vocabularies.
- `scripts/validate.py` rejects a pin `field::M.m` that no key of `field` is introduced or removed at, so a pin can no longer name an empty minor. A removal-only major (`att&ck::2.0`) stays pinnable.
- `responders.vocab.toml` is retired. It shipped with `keys = []` while `response.responders` was pinned to it, so every authored value failed validation and no instance could fix it (vocabularies are not locally extensible). The alert handling team is per-organisation configuration: the field is free text defaulted from `[deployment] default_responders` (opentide#507).
- Initial catalog of 36 bundled vocabularies copied from opentide.

## deployment 1.3

- `UNIVERSAL` is listed as a status `strategy`: the rule is deployed to both staging/preview and production targets. opentide already accepted it; the strategy table did not list it. Additive, no bundled status uses it.
- The `deployment_state_unpersisted` row names a CI run by its strategies (any run but a `RELEASE` run on a push) instead of a deployment plan.

## deployment 1.2

- `opentide deploy` selects only the rule files placed directly in the configured rules directory ([specifications#16](https://github.com/opentidehq/specifications/pull/16)).

## deployment 1.1

- Update, disablement, and deletion on Defender for Endpoint, SentinelOne, and CrowdStrike use the tenant binding in deployment state. A create needs a destination that is not ignored and a run that can persist state. `DISABLEMENT` and `DELETION` without a binding report `external_id_missing` as a warning ([RFC 0010](rfcs/0010-deployment-external-ids.md)).

## deployment 1.0

- Initial normative spec bootstrapped from opentide `deployment.toml`.

## deployment-state 1.2

- A run that cannot persist state is any CI run but a release run on a push: a deploy whose run strategies include `RELEASE`, outside a pull or merge request pipeline. It was defined by the deployment plan (`PRODUCTION`), which opentide 0.17.0 removed. The generated jobs behave as before; the shard schema `deployment.state::1.0` is unchanged.

## deployment-state 1.1

- CI requirement 1: GitHub Actions MUST NOT put the production job in a `concurrency` group. GitHub cancels an older pending run even with `cancel-in-progress: false`, and the cancelled commit's diff-scoped deploy would be lost silently. Overlapping runs are bounded by the overlay and replay requirements, which report `deployment_state_conflict` ([specifications#43](https://github.com/opentidehq/specifications/issues/43)). The shard schema `deployment.state::1.0` is unchanged.

## deployment-state 1.0

- Committed per-rule vendor-id shards (`deployment.state::1.0`) at `.opentide/states/deployment/<uuid>.json` for Defender for Endpoint, SentinelOne, and CrowdStrike, with a lowercase canonical filename, string ids, and a canonical writer form ([RFC 0010](rfcs/0010-deployment-external-ids.md)).
- Mandatory migration (`opentide deploy migrate-state`): state-backed bindings move to shards; legacy keys on every other platform are removed as `external_id_unused`.
- Fail-closed deployment: `external_id_in_rule` on every path; `deployment_state_ignored` and `deployment_state_unpersisted` refuse creates before the vendor call; `external_id_missing` is a warning.
- CI persistence: serialised production jobs, default-branch state overlay, write-back on failure, cancellation, and timeout, per-tenant conflict replay (`deployment_state_conflict`), and a `refs/opentide/deployment-state/<commit>` side ref on every terminal failure.
- The complete diagnostic catalogue and exit semantics. JSON Schema `schemas/deployment.state.1.0.schema.json` and fixtures under `fixtures/deployment/`.

## metaschema-keywords 1.2

- `signal` model vocabulary for `objective::1.1` `reuse` ([RFC 0011](rfcs/0011-signal-reuse.md)). The `objective` vocabulary bound to `detection_model` keeps listing every objective and every signal defined under one.

## metaschema-keywords 1.0

- Initial normative spec bootstrapped from opentide `generation/schema_pipeline.py`.

## platforms 1.3

- A block's omitted `tenants` means every tenant the run reaches, not the deployment plan's selection; opentide 0.17.0 removed deployment plans. Field tables unchanged.

## platforms 1.2

- Elastic Security (`elastic`) joins the capability matrix as the eighth platform ([RFC 0007](rfcs/0007-elastic-security-platform.md), [specifications#17](https://github.com/opentidehq/specifications/issues/17)). It deploys, and it validates queries live only, through Kibana rule preview plus Elasticsearch checks, for KQL, Lucene, EQL, and ES|QL. It is in the query-validation allowlist, its static-validation bar is `type`, `status`, `query` (except `machine_learning`), and the type object, and it joins the `Nowhere` rows of the external-id table. Its generated-schema `pattern` rejects the canonical `platform::elastic::1.0`, like Splunk's and Carbon Black's.
- `validate query` is a tenant check on every platform in the query-validation allowlist: `--live`, and without it the command refuses. `crowdstrike` and `harfanglab` still report `supported: false`.

## platforms 1.1

- Platform blocks carry no external ids. `rule_id`, `rule_id_bundle`, and the `rule_id::<tenant>` loader alias are removed from every block and fail `external_id_in_rule`. Defender for Endpoint, SentinelOne, and CrowdStrike ids live in deployment state ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Elastic ([RFC 0007](rfcs/0007-elastic-security-platform.md)) addresses rules by `metadata.uuid` and never stores an external id. Platform `schema_id`s stay `::1.0`.

## platforms 1.0

- Field tables mark every key `yes` or `optional` for static validation. Exclusion `query` is required (an empty string is accepted). Sentinel, SentinelOne, CrowdStrike, and HarfangLab loaders drop unmapped keys; Defender, Splunk, and Carbon Black reject an unknown key at the block root. The Splunk loader drops unknown keys inside `scheduling`. Generated JSON Schema defaults `schema` to the legacy identifier, and the Splunk and Carbon Black overlays reject the canonical `platform::<identifier>::1.0` with a legacy `pattern`.
- Per-platform field contracts for the seven bundled blocks (`platform::<identifier>::1.0`). Static validation, registry load, and deploy are specified separately. Generated JSON Schema is not the field contract.
- Initial capability matrix for seven bundled platforms.

## platform-sentinel 1.1

- `tactics`: Stealth, Defense Impairment (ATT&CK v19), and the ICS Evasion tactic deploy as `DefenseEvasion`. A stage with no Sentinel tactic is dropped ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- Durations (`scheduling.frequency`, `scheduling.lookback`, `alert.suppression`, `grouping.alert.grouping_lookback`): ISO 8601 stays the documented form, and shorthand, single-unit or compound (`30m`, `1h10m`, `1d2h`, `2m30s`), is accepted and converted to ISO 8601 at deploy, with the shorthand grammar of `platform::elastic::1.0` ([opentide#564](https://github.com/opentidehq/opentide/pull/564) and the opentide 0.16.0 follow-up, which makes shorthand case-sensitive and adds seconds). Schema id unchanged.

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

## platform-elastic 1.1

- Advisories carry stable codes, one per condition: `lookback_zero`, `lookback_long`, `threshold_lookback`, `esql_metadata_id`, `eql_maxspan_window`, `eql_maxspan_lookback`, `risk_band`, and `technique_not_enterprise`. The EQL `maxspan` advisory is split into `eql_maxspan_window` and `eql_maxspan_lookback`, and `threshold_lookback` is separate from `lookback_long`; opentide's log events merged each pair. A non-aggregating ES|QL query has no `STATS` step; `INLINE STATS` keeps rows and does not count. Kibana 9.4 and later add `METADATA _id` themselves, so `esql_metadata_id` matters for 8.19 through 9.3 ([specifications#57](https://github.com/opentidehq/specifications/issues/57)). Schema id unchanged.

## platform-elastic 1.0

- The ATT&CK tactic table follows `att&ck::1.2` (ATT&CK 20.0): TA0005 is `Stealth` and `Defense Impairment` is TA0112, as in RFC 0007. Removed keys still staged `Defense Evasion` map to `Stealth` through a legacy-stage table. With the old `Defense Evasion` row, techniques staged only in the v19 tactics emitted no `threat` entry ([opentide#568](https://github.com/opentidehq/opentide/issues/568)).
- `platform::elastic::1.0` ([RFC 0007](rfcs/0007-elastic-security-platform.md), [specifications#17](https://github.com/opentidehq/specifications/issues/17)). Elastic Security detection rule through the Kibana detection engine API: seven rule types (`query`, `eql`, `esql`, `threshold`, `new_terms`, `threat_match`, `machine_learning`), grouped author blocks for scheduling, severity, risk, suppression, guides, exceptions, overrides, and actions, and fourteen constraint codes. `status` is required on the block. Identity is `metadata.uuid` as the Kibana `rule_id`; nothing is stored.
- Durations are single-unit shorthand (`5m`), compound shorthand (`1h10m`, `1d2h`, `2m30s`; units in `d`, `h`, `m`, `s` order, each at most once, lower case), or ISO 8601, all equivalent; Kibana receives a single-unit value ([opentide#564](https://github.com/opentidehq/opentide/pull/564)).
- `kill-process` and `suspend-process` without `field` compile to `config: {field: process.entity_id, overwrite: true}`, because Kibana rejects them without `config` ([opentide#562](https://github.com/opentidehq/opentide/pull/562)).
- Live query validation through Kibana rule preview, and the Elasticsearch checks (ES|QL pre-flight, aggregation, timestamp, and indicator match fields) before every deploy. No offline check.
- Fixtures `fixtures/valid/rule-elastic-1.0.yaml`, `fixtures/invalid/rule-elastic-esql-index.yaml`, and `fixtures/platforms/elastic.yaml`.

## sharing 1.3

- `--changed` and the production release name the production deploy by its run strategy (`opentide deploy --strategy RELEASE` on a push) instead of `--plan PRODUCTION`, which opentide 0.17.0 removed. The commit range is unchanged.

## sharing 1.2

- `rule_statuses` matches the statuses of a rule's enabled platform blocks (`configurations.<platform>` with `enabled: true`), which deploy uses and promotion rewrites. The root `status` is matched only when no enabled block has one ([opentide#583](https://github.com/opentidehq/opentide/issues/583)).

## sharing 1.1

- `.opentide/states/` holds sharing's regenerable cache and deployment's committed shards. A future subsystem states whether its state is a cache or an authoritative record and whether it is committed ([RFC 0010](rfcs/0010-deployment-external-ids.md)). Ledger fields are unchanged.

## sharing 1.0

- Production CI stage ([RFC 0006](rfcs/0006-sharing-ci.md)). `opentide setup` and `opentide setup ci` offer a sharing stage, default off (`--sharing` / `--no-sharing`, wizard checkbox "Sharing on the default branch"). When selected, the stage runs `opentide share push --changed` on a push to the default branch and does not run on a pull request or merge request. `--changed` uses the `deploy --plan PRODUCTION` diff across threat, objective, and rule files.
- Sharing system ([RFC 0005](rfcs/0005-sharing-system.md)). One `sharing.toml` whose top level holds only integration arrays (`[[misp]]`; `[[opencti]]` reserved for a later connector). Each block carries its own selection and `max_tlp`; there are no global keys. Current share state is `.opentide/states/sharing.jsonl`, one line per object and destination, with a `state` of `synced` or `retracted`.

## sharing-misp 1.0

- `objective::1.1` `opentide-relation` values include the owner of each `reuse` binding ([RFC 0011](rfcs/0011-signal-reuse.md)).
- MISP connector `sharing::misp::1.0`. Document transport via upstream `opentide` template version 5.
- Minimal `[[misp]]` block: required `name`, `url`, `api_key`, and `max_tlp`; optional `enabled`, `object_types`, `rule_statuses`, `organisation_uuid`, `publish`, `verify_ssl`.
- Publishing organisation from the block override, otherwise `metadata.organisation.uuid`. An object with neither fails. No fallback to the API key's organisation.
- Distribution derived from `metadata.tlp`. `max_tlp = "red"` shares TLP:RED. No sharing groups, file mode, title prefix, or extra tags in 1.0.
- `content_hash` is the SHA-256 of the verbatim UTF-8 object document, lowercase hex.

## validation 1.4

- Fixture checker code `search_language`: `response.procedure.searches[].language` set with a system other than `elastic`, or with a value other than `kuery`, `lucene`, `eql`, or `esql` ([specifications#58](https://github.com/opentidehq/specifications/issues/58)).
- Platform advisories: the eight Elastic advisory codes are warnings, reported under the same code by the CLI and editors ([specifications#57](https://github.com/opentidehq/specifications/issues/57)).

## validation 1.3

- `elastic` joins query validation, live only: Kibana rule preview plus the Elasticsearch checks. The command is `opentide validate query --platform <id> --live` on every platform in the query-validation allowlist; without `--live` it refuses and never reports a pass ([RFC 0007](rfcs/0007-elastic-security-platform.md)).
- The fixture checker applies three Elastic constraint codes (`language`, `esql_source`, `suppression_shape`) to `configurations.elastic` blocks; `fixtures/invalid/rule-elastic-esql-index.yaml` reports all three and is registered under `esql_source`.

## validation 1.2

- Checker codes for `objective::1.1` bindings: `signal_entry_mixed`, `invalid_uuid` on `reuse`, `binding_requires_1_1` ([RFC 0011](rfcs/0011-signal-reuse.md)).

## validation 1.1

- `external_id_in_rule` for a legacy external-id key at the root of any platform block, replacing the generic unknown-key error. Full-workspace validation checks every deployment-state shard, orphans included. Every `--file` target must match an object ([RFC 0010](rfcs/0010-deployment-external-ids.md)).
- Fixture checker `scripts/deployment_state_fixtures.py` and codes for `fixtures/deployment/`.

## validation 1.0

- Fixture checker codes `invalid_reviewed` and `reviewed_not_in_schema` for `metadata.reviewed` ([RFC 0008](rfcs/0008-rule-reviewed-date.md)).
- `sharing-config` checker codes and fixtures for `[[misp]]` blocks, including the merge-by-`name` fixture.
- Document specifications-repo fixture checker codes for `threat::1.0` list and `ThreatActor` encoding ([#11](https://github.com/opentidehq/specifications/issues/11), [#12](https://github.com/opentidehq/specifications/issues/12)).
- Initial normative spec bootstrapped from opentide validation pipeline.
