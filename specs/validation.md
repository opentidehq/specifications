---
spec: validation
version: "1.13"
schema_id: null
status: normative
supersedes: null
---

# Validation

## Summary

opentide validates detection content through a structured pipeline: ID uniqueness, UUID format, Pydantic schema validation, vocabulary conformance, deprecated field warnings, and cross-object reference checks. Optional checks include CVE scanning and per-platform query validation.

## Requirements

- `opentide validate` MUST run default checks: `id-uniqueness`, `uuid-format`, `schema`.
- Schema validation MUST load each object via `metadata.schema` and validate against the registered Pydantic model.
- Vocabulary validation MUST walk metaschema `tide.vocab` annotations for each object type.
- UUID values MUST be UUID version 4.
- Object UUIDs MUST be unique across the workspace registry.
- Cross-object references MUST resolve to existing objects when checked.
- Threat `chaining` relationships MUST reference valid targets when checked.
- Query validation MUST only be offered for platforms in the query-validation allowlist (see [platforms/index.md](platforms/index.md)).
- Platforms without query validators MUST return `supported: false` — not fake success.
- The schema check MUST report `external_id_in_rule` for `rule_id`, `rule_id_bundle`, or `rule_id::<tenant>` at the root of any platform block and MUST suppress the redundant generic unknown-key diagnostic for that same field.
- Full-workspace validation MUST validate every deployment-state shard under `.opentide/states/deployment/`, including orphan shards whose `object_uuid` is not in the registry. A missing shard is not an error.

## Definition

### Check types (`ValidateCheck`)

| Check | Identifier | Default | Description |
|-------|------------|---------|-------------|
| ID uniqueness | `id-uniqueness` | yes | No duplicate `metadata.uuid` across YAML files |
| UUID format | `uuid-format` | yes | Every UUID must be valid UUIDv4 |
| Schema | `schema` | yes | Pydantic model validation + vocab + cross-ref |
| CVE | `cve` | no | CVE reference integrity (optional flag) |
| Sharing config | `sharing-config` | no | `sharing.toml` integration blocks: required keys, unique names, known keys, `max_tlp`, `object_types`, and `organisation_uuid`. On for `opentide share push`. |

### Schema check sub-steps

When `schema` is enabled, for each in-scope object the implementation MUST, in order:

1. **Load and model-validate** — resolve the object's `metadata.schema` and validate it against the registered model.
2. **Vocabulary** — check controlled-vocabulary fields against the indexed metaschema vocabulary annotations.
3. **Deprecation** — flag deprecated fields as warnings.
4. **References** — resolve `references` links to existing objects.
5. **Chaining** — resolve chaining relationships (threat vectors only).

The model-validation step reports a legacy external-id key as `external_id_in_rule` rather than as an unknown key ([platforms/index.md](platforms/index.md#external-rule-ids)). The key is checked at the root of every platform block only; a key of the same name nested inside `alert`, `query`, `exclusions`, or another field is not a legacy key.

Steps 4 and 5 resolve cross-object links; they run whenever the `schema` check runs against a full workspace scope where the referenced objects are present.

### Validation scope

| Mode | Behavior |
|------|----------|
| `full` | All objects in the workspace index |
| `narrow` | Filter by `--file`, `--uuid`, and/or `--type` |

When `--file`, `--uuid`, or `--type` filters match no objects, validation MUST emit a `scope_no_match` error rather than silently passing — a filter that selects nothing is treated as a mistake, not a success. With several `--file` targets, validation MUST fail when any one of them matches no object, even if the others do. The production write-back relies on this to commit only rule files that were actually validated ([deployment-state.md](deployment-state.md#continuous-integration)).

### Deployment state

In `full` scope, validation MUST read every `*.json` file under `.opentide/states/deployment/` and report the [deployment-state](deployment-state.md#diagnostics) codes: `deployment_state_shape`, `deployment_state_platform`, and `deployment_state_uuid_mismatch` (including two files that canonicalise to one uuid). Orphan shards are validated like any other. A rule with no shard is not an error. `narrow` scope MAY check only the shards of the selected rules plus any shard file passed directly.

| Code | Severity | When |
|------|----------|------|
| `external_id_in_rule` | error | A legacy external-id key at the root of a platform block |
| `deployment_state_shape` | error | A shard is unreadable or violates `deployment.state::1.0` |
| `deployment_state_platform` | error | A shard names a platform that is not state-backed |
| `deployment_state_uuid_mismatch` | error | A shard's filename and `object_uuid` disagree or are not lowercase canonical |

### Platform advisories

A platform spec MAY list advisories: conditions that validation SHOULD report as a warning without rejecting the rule. Each has a stable code, and the CLI and editors MUST report a finding under that code. Codes are unique across platform specs: a later spec MUST NOT reuse a code for a different condition, and picks a new one instead. An advisory never sets `VALIDATION_ERROR_RAISED`.

| Code | Severity | When |
|------|----------|------|
| `lookback_zero` | warning | Elastic: `scheduling.lookback` is zero |
| `lookback_long` | warning | Elastic: `scheduling.lookback` exceeds `1h` |
| `threshold_lookback` | warning | Elastic: a `threshold` rule's `lookback` exceeds its `interval` |
| `esql_metadata_id` | warning | Elastic: a non-aggregating ES\|QL query (no `STATS` step) lacks `METADATA _id` |
| `eql_maxspan_window` | warning | Elastic: an EQL `maxspan` exceeds `interval` + `lookback` |
| `eql_maxspan_lookback` | warning | Elastic: an EQL `maxspan` exceeds `lookback` but not `interval` + `lookback` |
| `risk_band` | warning | Elastic: an explicit risk score is outside its severity's band |
| `technique_not_enterprise` | warning | Elastic: the rule names a technique that is not Enterprise ATT&CK, which deploy skips |
| `sysdig_list_self_reference` | warning | Sysdig: a block list names itself, which Falco keeps as a literal value |
| `bitdefender_registry_full_hive` | warning | Bitdefender: a `Registry.Key` value starts with a full hive name, so the rule never triggers |
| `bitdefender_contains_no_wildcard` | warning | Bitdefender: a `contains` value has neither `*` nor `?` |
| `bitdefender_severity_collapsed` | warning | Bitdefender: `Critical` or `Informational` severity sent as GravityZone `High` or `Low` |
| `graylog_overlapping_window` | warning | Graylog: a filter's `schedule.window` is longer than `schedule.every`, so each message alerts once per overlapping run |
| `graylog_all_streams` | warning | Graylog: no streams or stream categories on the block or the tenant |
| `graylog_title_duplicate` | warning | Graylog: two enabled blocks resolve to one event definition title |
| `exabeam_outcome_silent` | warning | Exabeam: `outcome: none` and no `email`, so the rule only writes a `rule-trigger` event |
| `exabeam_correlation_window` | warning | Exabeam: two or more sequences, and `correlation.within` is not more than the time the ordered sequences need (the sum of their windows plus one minute per sequence after the first) |
| `google_secops_risk_score_missing` | warning | Google SecOps: `outcome` assigns no `$risk_score`, so every detection gets the instance's default score |
| `google_secops_rule_id_literal` | warning | Google SecOps: `events` or `condition` compares `detection.detection.rule_id` with a literal `ru_…` id, which differs per tenant |
| `google_secops_live_frequency_unavailable` | warning | Google SecOps: `run_frequency: LIVE` on a rule with two or more event variables, which deploy refuses (`LIVE` is for single-event rules) |
| `harfanglab_yara_context` | warning | HarfangLab: a YARA rule's meta `context` is not a comma-joined list of `file`, `memory`, `file.pe`, `file.elf`, `file.macho` |

The conditions and their reasons are in [elastic-1.0](platforms/elastic-1.0.md#advisories), [sysdig-1.0](platforms/sysdig-1.0.md#advisories), [bitdefender-1.0](platforms/bitdefender-1.0.md#advisories), [graylog-1.0](platforms/graylog-1.0.md#advisories), [google-secops-1.0](platforms/google-secops-1.0.md#advisories), and [harfanglab-1.0](platforms/harfanglab-1.0.md#yara-profile).

### Language diagnostics

A language spec MAY define diagnostics with stable codes. Its errors fail static validation like a constraint code. Its warnings are reported like advisories and never set `VALIDATION_ERROR_RAISED`. The Graylog dialect of the Lucene engine adds `graylog_leading_wildcard`, `graylog_regex_unsupported`, and `graylog_open_range` (errors) and `graylog_regex_operator`, `graylog_regex_quote`, `graylog_double_backslash`, and `graylog_analyzed_field` (warnings) ([graylog-1.0](platforms/graylog-1.0.md#query-diagnostics)). The YARA codes are in [yara-1.0](languages/yara-1.0.md#diagnostics): every `yara_*` error fails the rule, and the warnings are `yara_x_incompatible`, `yara_slow_pattern`, `yara_entrypoint_deprecated`, `yara_suspicious_expression`, `yara_module_unconfirmed`, and `yara_meta_missing`. The Exabeam Query Language codes are in [exabeam-1.0](languages/exabeam-1.0.md#diagnostics): every `exabeam_*` language error fails the rule, and its warnings are `exabeam_mixed_boolean`, `exabeam_implicit_and`, `exabeam_single_group`, `exabeam_pipe_misuse`, `exabeam_wildcard_in_phrase`, `exabeam_unquoted_value`, `exabeam_legacy_regex`, `exabeam_unknown_field`, `exabeam_string_field_number`, and `exabeam_unknown_value`. The YARA-L codes are in [yara-l-1.0](languages/yara-l-1.0.md#diagnostics): every `yaral_*` error fails the rule, and the warnings are `yaral_deprecated_field`, `yaral_unfiltered_event`, `yaral_leading_wildcard_regex`, `yaral_reference_list_deprecated`, and `yaral_string_escape`.

### Query validation

Commands: `opentide validate query` (offline, the default) and `opentide validate query --platform <id> --live` (the tenant check).

**Offline**, the analysis engine parses each query in its platform's language, with no tenant, credentials, or network. It is the `queries` check of `opentide validate` on its own, and it also takes a query file (`.kql`, `.spl`, `.yar`, ...). A platform with no offline parser (`sentinel_one`) refuses offline and names `--live`. HarfangLab and Bitdefender YARA (`.yar`, `.yara`), Google SecOps YARA-L (`.yaral`, `.yl2`), the Sysdig Falco condition, Graylog queries (`.lucene` under `--platform graylog`, the Graylog dialect), and the Exabeam Query Language (sequence queries, `system: exabeam` hunts, `.exabeam` files) are checked offline.

**`--live`** sends a platform's rule queries to its tenants. The table is the `--live` allowlist:

| Platform | Supported |
|----------|-----------|
| `sentinel` | yes |
| `defender_for_endpoint` | yes |
| `splunk` | yes |
| `sentinel_one` | yes |
| `carbon_black_cloud` | yes |
| `elastic` | yes, live only: Kibana rule preview and the Elasticsearch checks ([elastic-1.0](platforms/elastic-1.0.md#query-validation)) |
| `google_secops` | yes: `verifyRuleText` compiles the assembled rule and creates nothing ([google-secops-1.0](platforms/google-secops-1.0.md#query-validation)). YARA-L is also checked offline |
| `crowdstrike` | no |
| `harfanglab` | no. YARA is checked offline ([harfanglab-1.0](platforms/harfanglab-1.0.md#query-validation)) |
| `sysdig` | no. The Falco condition is checked offline ([sysdig-1.0](platforms/sysdig-1.0.md#query-validation)) |
| `bitdefender` | no. Constraints, criteria, and YARA are checked offline by `opentide validate` ([bitdefender-1.0](platforms/bitdefender-1.0.md#query-validation)) |
| `graylog` | yes: `POST /api/search/validate`, on Graylog 6.3 to 7.2 ([graylog-1.0](platforms/graylog-1.0.md#query-validation)) |
| `exabeam` | yes, the filter only: Exabeam Search over the last 15 minutes; the rule's condition is checked offline ([exabeam-1.0](platforms/exabeam-1.0.md#query-validation)) |

`--live` requires platform credentials and enabled configuration, and validates deployed or planned rule queries against the live platform API. `crowdstrike`, `harfanglab`, `sysdig`, and `bitdefender` report `supported: false` for `--live` ([platforms](platforms/index.md#query-validation-platforms)) and MUST NOT report a pass. An offline check MUST NOT be reported as a tenant check. Elastic's query language (KQL, Lucene, EQL, or ES|QL) comes from each rule's block: its `type`, and `language` for the types that take one.

### Specifications-repo fixture checker

This repository’s CI (`scripts/object_fixtures.py`) is **not** `opentide validate`. It proves object-spec field types against fixtures without a Pydantic runtime. Codes below are checker codes; they are distinct from the `ValidateCheck` identifiers (`uuid-format`, `schema`, …).

| Fixture | Checker code |
|---------|--------------|
| [fixtures/invalid/threat-impact-as-string.yaml](../fixtures/invalid/threat-impact-as-string.yaml) | `field_not_list` |
| [fixtures/invalid/threat-leverage-semicolon.yaml](../fixtures/invalid/threat-leverage-semicolon.yaml) | `packed_vocab_string` |
| [fixtures/invalid/threat-impact-semicolon.yaml](../fixtures/invalid/threat-impact-semicolon.yaml) | `packed_vocab_string` |
| [fixtures/invalid/threat-leverage-semicolon-list-item.yaml](../fixtures/invalid/threat-leverage-semicolon-list-item.yaml) | `packed_vocab_string` |
| [fixtures/invalid/threat-impact-empty.yaml](../fixtures/invalid/threat-impact-empty.yaml) | `empty_vocab_list` |
| [fixtures/invalid/threat-leverage-empty.yaml](../fixtures/invalid/threat-leverage-empty.yaml) | `empty_vocab_list` |
| [fixtures/invalid/threat-leverage-high.yaml](../fixtures/invalid/threat-leverage-high.yaml) | `unknown_vocab_value` |
| [fixtures/invalid/threat-actors-string-list.yaml](../fixtures/invalid/threat-actors-string-list.yaml) | `actors_not_objects` |
| [fixtures/invalid/threat-actors-not-list.yaml](../fixtures/invalid/threat-actors-not-list.yaml) | `actors_not_objects` |
| [fixtures/invalid/threat-actor-missing-name.yaml](../fixtures/invalid/threat-actor-missing-name.yaml) | `actor_missing_name` |
| [fixtures/invalid/threat-actor-unscoped.yaml](../fixtures/invalid/threat-actor-unscoped.yaml) | `actor_unscoped` |
| [fixtures/invalid/threat-actor-wrong-stage.yaml](../fixtures/invalid/threat-actor-wrong-stage.yaml) | `actor_unknown` |
| [fixtures/invalid/threat-missing-body.yaml](../fixtures/invalid/threat-missing-body.yaml) | `missing_threat_body` |
| [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml) | `invalid_uuid` |
| [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml) | `unknown_schema` |
| [fixtures/invalid/rule-missing-metadata.yaml](../fixtures/invalid/rule-missing-metadata.yaml) | `missing_metadata` |
| [fixtures/invalid/rule-reviewed-bad-date.yaml](../fixtures/invalid/rule-reviewed-bad-date.yaml) | `invalid_reviewed` |
| [fixtures/invalid/rule-1.0-reviewed.yaml](../fixtures/invalid/rule-1.0-reviewed.yaml) | `reviewed_not_in_schema` |
| [fixtures/invalid/objective-no-signals.yaml](../fixtures/invalid/objective-no-signals.yaml) | `empty_signals` |
| [fixtures/invalid/objective-signal-entry-mixed.yaml](../fixtures/invalid/objective-signal-entry-mixed.yaml) | `signal_entry_mixed` |
| [fixtures/invalid/objective-signal-bad-uuid.yaml](../fixtures/invalid/objective-signal-bad-uuid.yaml) | `invalid_uuid` |
| [fixtures/invalid/objective-1.0-signal-binding.yaml](../fixtures/invalid/objective-1.0-signal-binding.yaml) | `binding_requires_1_1` |
| [fixtures/invalid/rule-elastic-esql-index.yaml](../fixtures/invalid/rule-elastic-esql-index.yaml) | `esql_source` (also `language` and `suppression_shape`) |
| [fixtures/invalid/rule-search-language.yaml](../fixtures/invalid/rule-search-language.yaml) | `search_language` |
| [fixtures/invalid/rule-sysdig-tuning-output.yaml](../fixtures/invalid/rule-sysdig-tuning-output.yaml) | `sysdig_tuning_keys` (also `sysdig_exception_shape`) |
| [fixtures/invalid/rule-harfanglab-sigma-and-yara.yaml](../fixtures/invalid/rule-harfanglab-sigma-and-yara.yaml) | `harfanglab_rule_kind` |
| [fixtures/invalid/rule-harfanglab-yara-both-forms.yaml](../fixtures/invalid/rule-harfanglab-yara-both-forms.yaml) | `harfanglab_yara_form` |
| [fixtures/invalid/rule-harfanglab-yara-include.yaml](../fixtures/invalid/rule-harfanglab-yara-include.yaml) | `yara_include` |
| [fixtures/invalid/rule-yara-signature-alias.yaml](../fixtures/invalid/rule-yara-signature-alias.yaml) | `yara_signature_alias` |
| [fixtures/invalid/rule-bitdefender-two-kinds.yaml](../fixtures/invalid/rule-bitdefender-two-kinds.yaml) | `bitdefender_rule_kind` |
| [fixtures/invalid/rule-bitdefender-exclusion.yaml](../fixtures/invalid/rule-bitdefender-exclusion.yaml) | `bitdefender_rule_kind` |
| [fixtures/invalid/rule-bitdefender-criterion-field.yaml](../fixtures/invalid/rule-bitdefender-criterion-field.yaml) | `bitdefender_criterion_field` |
| [fixtures/invalid/rule-bitdefender-kill-on-yara.yaml](../fixtures/invalid/rule-bitdefender-kill-on-yara.yaml) | `bitdefender_action_scope` |
| [fixtures/invalid/rule-graylog-condition.yaml](../fixtures/invalid/rule-graylog-condition.yaml) | `graylog_aggregation` |
| [fixtures/invalid/rule-graylog-event-field.yaml](../fixtures/invalid/rule-graylog-event-field.yaml) | `graylog_event_field` |
| [fixtures/invalid/rule-graylog-event-key.yaml](../fixtures/invalid/rule-graylog-event-key.yaml) | `graylog_event_key` |
| [fixtures/invalid/rule-graylog-schedule.yaml](../fixtures/invalid/rule-graylog-schedule.yaml) | `graylog_schedule` |
| [fixtures/invalid/rule-exabeam-correlation-single.yaml](../fixtures/invalid/rule-exabeam-correlation-single.yaml) | `exabeam_correlation` |
| [fixtures/invalid/rule-exabeam-threshold-operator.yaml](../fixtures/invalid/rule-exabeam-threshold-operator.yaml) | `exabeam_threshold_operator` |
| [fixtures/invalid/rule-exabeam-context-table-threshold.yaml](../fixtures/invalid/rule-exabeam-context-table-threshold.yaml) | `exabeam_context_table_trigger` |
| [fixtures/invalid/rule-exabeam-delay.yaml](../fixtures/invalid/rule-exabeam-delay.yaml) | `exabeam_duration` |
| [fixtures/invalid/rule-exabeam-advanced-query.yaml](../fixtures/invalid/rule-exabeam-advanced-query.yaml) | `exabeam_advanced_in_rule` (a language code) |
| [fixtures/invalid/rule-google-secops-section-header.yaml](../fixtures/invalid/rule-google-secops-section-header.yaml) | `yaral_section_header` |
| [fixtures/invalid/rule-google-secops-condition-comment.yaml](../fixtures/invalid/rule-google-secops-condition-comment.yaml) | `yaral_section_empty` |
| [fixtures/invalid/rule-google-secops-sliding-no-pivot.yaml](../fixtures/invalid/rule-google-secops-sliding-no-pivot.yaml) | `yaral_match_shape` |
| [fixtures/invalid/rule-google-secops-missing-condition.yaml](../fixtures/invalid/rule-google-secops-missing-condition.yaml) | `yaral_section_missing` |
| [fixtures/invalid/rule-google-secops-hourly.yaml](../fixtures/invalid/rule-google-secops-hourly.yaml) | `google_secops_run_frequency` (also `google_secops_schedule`) |
| [fixtures/invalid/rule-google-secops-meta-reserved.yaml](../fixtures/invalid/rule-google-secops-meta-reserved.yaml) | `google_secops_meta_key` |
| [fixtures/sharing/invalid/unknown-distribution.toml](../fixtures/sharing/invalid/unknown-distribution.toml) | `unknown_key` |
| [fixtures/sharing/invalid/legacy-targets-table.toml](../fixtures/sharing/invalid/legacy-targets-table.toml) | `unknown_key` |
| [fixtures/sharing/invalid/duplicate-name.toml](../fixtures/sharing/invalid/duplicate-name.toml) | `duplicate_name` |
| [fixtures/sharing/invalid/missing-url.toml](../fixtures/sharing/invalid/missing-url.toml) | `missing_field` |
| [fixtures/sharing/invalid/bad-name.toml](../fixtures/sharing/invalid/bad-name.toml) | `name_invalid` |
| [fixtures/sharing/invalid/bad-max-tlp.toml](../fixtures/sharing/invalid/bad-max-tlp.toml) | `max_tlp_unknown` |
| [fixtures/sharing/invalid/missing-max-tlp.toml](../fixtures/sharing/invalid/missing-max-tlp.toml) | `missing_field` |
| [fixtures/sharing/invalid/bad-organisation-uuid.toml](../fixtures/sharing/invalid/bad-organisation-uuid.toml) | `organisation_uuid_invalid` |
| [fixtures/sharing/invalid/bad-object-type.toml](../fixtures/sharing/invalid/bad-object-type.toml) | `object_type_unknown` |
| [fixtures/deployment/invalid/bad-schema.json](../fixtures/deployment/invalid/bad-schema.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/uuid-mismatch.json](../fixtures/deployment/invalid/uuid-mismatch.json) | `deployment_state_uuid_mismatch` |
| [fixtures/deployment/invalid/noncanonical-uuid.json](../fixtures/deployment/invalid/noncanonical-uuid.json) | `deployment_state_uuid_mismatch` |
| [fixtures/deployment/invalid/numeric-id.json](../fixtures/deployment/invalid/numeric-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/leading-zero-defender-id.json](../fixtures/deployment/invalid/leading-zero-defender-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/empty-id.json](../fixtures/deployment/invalid/empty-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/whitespace-tenant.json](../fixtures/deployment/invalid/whitespace-tenant.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/unsupported-platform.json](../fixtures/deployment/invalid/unsupported-platform.json) | `deployment_state_platform` |
| [fixtures/deployment/invalid/bitdefender-bad-id.json](../fixtures/deployment/invalid/bitdefender-bad-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/bitdefender-uppercase-id.json](../fixtures/deployment/invalid/bitdefender-uppercase-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/graylog-bad-id.json](../fixtures/deployment/invalid/graylog-bad-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/exabeam-bad-id.json](../fixtures/deployment/invalid/exabeam-bad-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/exabeam-uppercase-id.json](../fixtures/deployment/invalid/exabeam-uppercase-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/google-secops-bare-uuid.json](../fixtures/deployment/invalid/google-secops-bare-uuid.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/google-secops-revision-id.json](../fixtures/deployment/invalid/google-secops-revision-id.json) | `deployment_state_shape` |
| [fixtures/deployment/invalid/rule-with-rule-id.yaml](../fixtures/deployment/invalid/rule-with-rule-id.yaml) | `external_id_in_rule` |
| [fixtures/deployment/invalid/rule-with-rule-id-tenant.yaml](../fixtures/deployment/invalid/rule-with-rule-id-tenant.yaml) | `external_id_in_rule` |
| [fixtures/deployment/invalid/rule-with-rule-id-bundle.yaml](../fixtures/deployment/invalid/rule-with-rule-id-bundle.yaml) | `external_id_in_rule` |

Deployment fixtures (`scripts/deployment_state_fixtures.py`) are checked against [schemas/deployment.state.1.0.schema.json](../schemas/deployment.state.1.0.schema.json) plus the filename rules the schema cannot see. Each invalid shard fixture is checked under the shard filename the checker assigns to it (a uuid that differs from `object_uuid` for `uuid-mismatch.json`, the uppercase spelling for `noncanonical-uuid.json`, the valid name otherwise). The valid shard must be byte-identical to writer output, and no rule fixture in `fixtures/valid/`, `fixtures/platforms/`, or `fixtures/cross-object/` may carry a legacy external-id key.

Sharing fixtures (`scripts/sharing_fixtures.py`) also prove the merge rule: [override.toml](../fixtures/sharing/valid/override.toml) merged by `name` onto [sharing.toml](../fixtures/sharing/valid/sharing.toml) MUST equal [merged.toml](../fixtures/sharing/valid/merged.toml).

On a rule's `configurations.elastic` block the checker applies three of the [Elastic constraint codes](platforms/elastic-1.0.md#constraints), the ones the invalid Elastic fixture exercises: `language`, `esql_source`, and `suppression_shape`. They are the platform's own codes, so the checker and `opentide validate` report the same name. The other Elastic codes, and every other platform block, are left to opentide.

On a rule's `configurations.sysdig` block the checker applies the [Sysdig constraint codes](platforms/sysdig-1.0.md#constraints) that need no Falco parser: `sysdig_rule_shape`, `sysdig_tuning_keys`, `sysdig_priority`, `sysdig_source`, `sysdig_exception_shape`, `sysdig_definition_name`, and `sysdig_definition_duplicate`. `sysdig_definition_order` and `sysdig_list_in_value` need the Falco tokenizer and are left to opentide.

On a rule's `configurations.bitdefender` block the checker applies the [Bitdefender constraint codes](platforms/bitdefender-1.0.md#constraints) that need only the spec's EDR field table: `bitdefender_rule_kind`, `bitdefender_target`, `bitdefender_criterion_shape`, `bitdefender_criterion_field` (for `process`, `file`, `connection`, and `registry`), `bitdefender_criterion_relation`, `bitdefender_criterion_value`, `bitdefender_action_scope`, `bitdefender_targets_shape`, `bitdefender_severity`, `bitdefender_yara_ascii`, and `bitdefender_yara_size`, plus the parser-free YARA codes on `yara.signature`. `bitdefender_criteria_combination` and the workspace check `bitdefender_name_duplicate` are left to opentide.

On a rule's `configurations.graylog` block the checker applies the [Graylog constraint codes](platforms/graylog-1.0.md#constraints) that need no query parser: `graylog_query_blank`, `graylog_list_shape`, `graylog_schedule` (a cron expression's field count only), `graylog_event_limit`, `graylog_aggregation` (the full condition grammar), `graylog_event_field`, `graylog_event_key`, `graylog_priority`, and `graylog_field_name`. The query's codes need the Graylog dialect and are left to the analysis engine.

On a rule's `configurations.exabeam` block the checker applies every [Exabeam constraint code](platforms/exabeam-1.0.md#constraints) but the workspace check `exabeam_name_duplicate`, reports an unknown key (as `unknown_field`) at the key's own path, and, on each sequence `query` (profile `rule`) and each `system: exabeam` hunt (profile `search`), the [Exabeam Query Language](languages/exabeam-1.0.md#diagnostics) errors that need no field catalogue, through the reference checker `scripts/exabeam_language.py`.
On a rule's `configurations.google_secops` block the checker applies the [Google SecOps constraint codes](platforms/google-secops-1.0.md#constraints) that need no YARA-L parser: `google_secops_rule_name`, `google_secops_severity`, `google_secops_run_frequency`, `google_secops_schedule`, and `google_secops_meta_key`. On its sections it applies the [YARA-L codes](languages/yara-l-1.0.md#diagnostics) that need no parser: `yaral_section_alias`, `yaral_section_empty`, `yaral_section_header`, `yaral_section_missing`, `yaral_match_shape`, `yaral_match_window`, and `yaral_option`. The workspace check `google_secops_name_duplicate` and the other YARA-L codes are left to opentide and the analysis engine.

On a rule's `configurations.harfanglab` block the checker applies `harfanglab_rule_kind`, `harfanglab_yara_form`, and `harfanglab_yara_section_header`. On any `yara.signature` it applies the [YARA codes](languages/yara-1.0.md#diagnostics) that need no YARA parser: `yara_signature_alias`, `yara_include`, `yara_empty_signature`, and `yara_duplicate_rule`. The other YARA codes are left to the analysis engine.

On a rule's `response.procedure.searches[]` the checker reports `search_language` when `language` is set with a `system` other than `elastic`, or with a value other than `kuery`, `lucene`, `eql`, or `esql` ([rule-1.1](objects/rule-1.1.md#searches-responsesearch)).

A packed semicolon string that happens to start with a valid token MUST still fail `packed_vocab_string`. Accepting only the first token is lossy and non-compliant.

### Issue severities

| Severity | Examples |
|----------|----------|
| `error` | Schema failure, duplicate UUID, invalid UUID, broken cross-ref, `external_id_in_rule`, invalid deployment-state shard |
| `warning` | Deprecated field usage, a [platform advisory](#platform-advisories) |

### Environment signals

| Variable | Set when |
|----------|----------|
| `VALIDATION_ERROR_RAISED` | One or more errors |
| `VALIDATION_WARNING_RAISED` | One or more warnings |

### Parallel execution

Validation MAY parallelize per-object work and ID scans; worker count is resolved from object count and optional `--workers` flag.

## Relationships

- [metadata.md](metadata.md) — UUID and schema requirements
- [versioning.md](versioning.md) — schema routing at validation time
- [vocabularies/format.md](vocabularies/format.md) — vocabulary conformance
- [metaschema-keywords.md](metaschema-keywords.md) — `tide.vocab`, `tide.meta.deprecation`
- [platforms/index.md](platforms/index.md) — query validation allowlist, external rule ids
- [deployment-state.md](deployment-state.md) — shard format and diagnostic codes
- Object specs — field requirements validated by Pydantic

## Defaults & overrides

Validation uses merged configuration for vocabulary and status enums. No separate validation config file. Scope defaults to full workspace.

## Examples

| Fixture | Expected result |
|---------|-----------------|
| [fixtures/valid/rule-1.0.yaml](../fixtures/valid/rule-1.0.yaml) | Passes `uuid-format` + `schema` (`opentide validate`) |
| [fixtures/valid/threat-1.0.yaml](../fixtures/valid/threat-1.0.yaml) | Passes `threat::1.0` lists (`impact`, `leverage`) and `list[ThreatActor]` |
| [fixtures/invalid/rule-bad-uuid.yaml](../fixtures/invalid/rule-bad-uuid.yaml) | Fails `uuid-format` (`opentide validate`); checker code `invalid_uuid` |
| [fixtures/invalid/rule-unknown-schema.yaml](../fixtures/invalid/rule-unknown-schema.yaml) | Fails `schema` (`opentide validate`); checker code `unknown_schema` |
| [fixtures/cross-object/rule-references-objective.yaml](../fixtures/cross-object/rule-references-objective.yaml) | Passes when sibling objective fixture present |
| [fixtures/deployment/valid/00000000-0000-4000-8003-000000000010.json](../fixtures/deployment/valid/00000000-0000-4000-8003-000000000010.json) | Valid `deployment.state::1.0` shard in writer form |
| [fixtures/deployment/invalid/rule-with-rule-id-tenant.yaml](../fixtures/deployment/invalid/rule-with-rule-id-tenant.yaml) | Fails `schema` with `external_id_in_rule` |

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.13 | 2026-11-12 | `google_secops` joins the `--live` allowlist: `verifyRuleText` compiles the assembled rule without creating it ([google-secops-1.0](platforms/google-secops-1.0.md), [RFC 0019](../rfcs/0019-google-secops-yara-l.md)). YARA-L (`.yaral`) is checked offline ([yara-l-1.0](languages/yara-l-1.0.md)); its codes join [language diagnostics](#language-diagnostics). Advisories `google_secops_risk_score_missing`, `google_secops_rule_id_literal`, and `google_secops_live_frequency_unavailable`. The fixture checker applies five Google SecOps constraint codes and seven YARA-L codes on the block's sections. |
| 1.10 | 2026-11-11 | `graylog` is in the `--live` allowlist through `POST /api/search/validate`, and Graylog queries (Lucene, Graylog dialect) are checked offline ([graylog-1.0](platforms/graylog-1.0.md), [RFC 0017](../rfcs/0017-graylog-platform.md)). Three Graylog advisories, and six Graylog dialect codes for the query. The fixture checker applies nine Graylog constraint codes. |
| 1.11 | 2026-11-11 | `graylog_open_range` joins the Graylog dialect errors ([graylog-1.0](platforms/graylog-1.0.md#query-diagnostics), version 1.1). |
| 1.12 | 2026-11-12 | `exabeam` ([RFC 0018](../rfcs/0018-exabeam-platform.md)) joins the `--live` allowlist for its filters, through Exabeam Search, and is checked offline against the [Exabeam Query Language](languages/exabeam-1.0.md). Advisories `exabeam_outcome_silent` and `exabeam_correlation_window`; the language's diagnostics. The fixture checker applies the Exabeam constraint codes and the language errors the reference checker proves. |
| 1.9 | 2026-11-10 | [Query validation](#query-validation) matches `opentide validate query` as it ships (since opentide 0.19): offline by default with the analysis engine, the `queries` check on its own plus query files; `--live` is the tenant check and its allowlist. HarfangLab and Bitdefender YARA (`.yar`, `.yara`) and the Sysdig Falco condition are checked offline; `--live` stays `supported: false` for `crowdstrike`, `harfanglab`, `sysdig`, and `bitdefender`. Replaces "no offline mode on any platform". |
| 1.8 | 2026-11-10 | `harfanglab_yara_context` accepts any comma-joined list of `file`, `memory`, `file.pe`, `file.elf`, `file.macho` ([harfanglab-1.0](platforms/harfanglab-1.0.md#yara-profile) 1.3). |
| 1.7 | 2026-11-10 | `bitdefender` is excluded from query validation (`supported: false`) and checked offline by `opentide validate` ([bitdefender-1.0](platforms/bitdefender-1.0.md), [RFC 0016](../rfcs/0016-bitdefender-gravityzone-platform.md)). Advisories `bitdefender_registry_full_hive`, `bitdefender_contains_no_wildcard`, and `bitdefender_severity_collapsed`. The fixture checker applies eleven Bitdefender constraint codes. |
| 1.6 | 2026-11-10 | [Language diagnostics](#language-diagnostics): the YARA language's errors and warnings ([yara-1.0](languages/yara-1.0.md), [RFC 0015](../rfcs/0015-yara-language.md)). Advisory `harfanglab_yara_context`. HarfangLab YARA is checked offline by `opentide validate`; `validate query` stays `supported: false`. The fixture checker applies three HarfangLab codes and four YARA codes. |
| 1.5 | 2026-11-03 | [Platform advisories](#platform-advisories): `sysdig_list_self_reference` ([sysdig-1.0](platforms/sysdig-1.0.md#advisories)). |
| 1.5 | 2026-11-02 | `sysdig` is excluded from query validation (`supported: false`); its Falco condition is checked offline by `opentide validate` ([sysdig-1.0](platforms/sysdig-1.0.md#query-validation)). `validate query` has no offline mode on any platform. The fixture checker applies seven Sysdig constraint codes to `configurations.sysdig` blocks. |
| 1.4 | 2026-10-23 | Fixture checker code `search_language` for `response.procedure.searches[].language` ([specifications#58](https://github.com/opentidehq/specifications/issues/58)). |
| 1.4 | 2026-10-23 | [Platform advisories](#platform-advisories): the eight Elastic advisory codes are warnings ([elastic-1.0](platforms/elastic-1.0.md#advisories), [specifications#57](https://github.com/opentidehq/specifications/issues/57)). |
| 1.3 | 2026-10-19 | `elastic` joins query validation, live only through Kibana rule preview and the Elasticsearch checks ([elastic-1.0](platforms/elastic-1.0.md)). The command is `validate query --live` on every platform in the query-validation allowlist; without `--live` it refuses. The fixture checker applies three Elastic constraint codes (`language`, `esql_source`, `suppression_shape`) to `configurations.elastic` blocks. |
| 1.2 | 2026-10-19 | `objective::1.1` signal binding codes ([RFC 0011](../rfcs/0011-signal-reuse.md)). The fixture checker proves `signal_entry_mixed`, `invalid_uuid` on `reuse`, and `binding_requires_1_1`. `unresolved_signal`, `self_signal`, `duplicate_signal`, `duplicate_signal_uuid`, and `signal_tlp` are `opentide validate` against the workspace library. |
| 1.1 | 2026-10-16 | `external_id_in_rule` replaces the generic unknown-key error for legacy external-id keys; full-workspace validation checks every deployment-state shard, orphans included; every `--file` target must match an object; deployment fixture checker codes ([RFC 0010](../rfcs/0010-deployment-external-ids.md)). |
| 1.0 | 2026-09-30 | Fixture checker codes `invalid_reviewed` and `reviewed_not_in_schema` ([RFC 0008](../rfcs/0008-rule-reviewed-date.md)). |
| 1.0 | 2026-09-28 | `sharing-config` checker codes for `[[misp]]` integration blocks. |
| 1.0 | 2026-09-16 | Document specifications-repo fixture checker codes for `threat::1.0` list/`ThreatActor` encoding ([#11](https://github.com/opentidehq/specifications/issues/11), [#12](https://github.com/opentidehq/specifications/issues/12)). |
| 1.0 | 2026-06-25 | Initial spec from opentide `validation/session.py` |
