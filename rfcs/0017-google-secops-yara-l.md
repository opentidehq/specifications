# RFC 0017: Google Security Operations and the YARA-L language

- **RFC:** 0017
- **Title:** Google Security Operations (SIEM) detection platform and the YARA-L 2.0 language
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-11
- **Accepted:** 2026-11-12, after review moved the block to one key per section and the open questions below were resolved. The normative text is [specs/platforms/google-secops-1.0.md](../specs/platforms/google-secops-1.0.md) and [specs/languages/yara-l-1.0.md](../specs/languages/yara-l-1.0.md).
- **Related:** [RFC 0010](0010-deployment-external-ids.md) (deployment state), [RFC 0015](0015-yara-language.md) (the language-spec pattern), [RFC 0007](0007-elastic-security-platform.md) (live validation and the ATT&CK tactic table)
- **Implementation:** opentidehq/opentide (the `google_secops` platform, `opentide query` runner); opentidehq/language-server (the `yaral` engine, grammar, catalogues, and highlighting); opentidehq/website (synced specs, the `yaral` grammar for code blocks)

## Summary

Add an eleventh detection platform, `google_secops` (display name **Google Security Operations (SIEM)**, schema `platform::google_secops::1.0`), and a language spec for **YARA-L 2.0** (`language-yara-l` 1.0).

- The block holds the rule's **sections as keys**: `events`, `outcome`, and `condition` (and `setup`, `export`) as YARA-L text, and `match` and `options` as YAML objects. Deploy assembles the rule: `rule <derived name> {`, a generated `meta:` section (author, description, severity, priority, ATT&CK technique ids, `opentide_uuid`, `opentide_version`, extra keys), then each section under its label.
- Deploy goes through the Chronicle API **v1**: `verifyRuleText`, `rules.create`, `rules.patch` (text), and `rules.updateDeployment` (enabled, alerting, run frequency, archive). The rule id (`ru_<uuid>`) lives in [deployment state](../specs/deployment-state.md).
- `PREVIEW` deploys a running, **non-alerting** rule; `RELEASE` an alerting one. `DELETION` archives by default and never deletes detections.
- `verifyRuleText` is a real tenant compile that creates nothing, so `google_secops` joins the `--live` allowlist. The analysis engine checks YARA-L offline with 28 error and 5 warning codes, from a UDM field catalogue and a function catalogue generated from Google's pages.
- YARA-L is highlighted with the existing HighlightSpec captures; no capture is added.
- Hunts (`response.procedure.searches[]` with `system: google_secops`) are YARA-L searches, checked under a `search` profile and runnable with `opentide query` through `udmSearch`.

The change is additive. It adds `configurations.google_secops`, a deployment-state platform, a language spec, and a row in the `--live` allowlist.

## Motivation

Google SecOps is one of the large cloud SIEMs, and opentide cannot reach it. Its rules live in the console or in Google's `content_manager` scripts, which manage text and run state but carry no objective, threat, review, or lifecycle. YARA-L is also the only major SIEM language with no open grammar of quality, no linter, and no language server: editors get Google's 2024 TextMate grammar at best. A spec-first integration gives detection engineers the same loop as on Elastic: offline diagnostics while typing, a tenant compile in CI, and a state-backed deploy.

## Research

Sources are Google's documentation under `docs.cloud.google.com/chronicle/docs/` (fetched 2026-11-11; `cloud.google.com/chronicle/docs` now redirects there), the Chronicle REST reference, and Google's own tooling: [`chronicle/detection-rules`](https://github.com/chronicle/detection-rules) (Apache-2.0: 948 community rules, `STYLE_GUIDE.md`, `tools/content_manager`) and [`google/secops-wrapper`](https://github.com/google/secops-wrapper) (Apache-2.0, `secops` on PyPI).

### Chronicle API

| Item | Fact | Source |
|------|------|--------|
| Version | Rules and deployments are GA in **v1**. `verifyRuleText` moved to v1 on 2026-05-28. `udmSearch`, `:search`, and `validateQuery` are in v1 too. Test runs (`legacy:legacyRunTestRule`) exist only in `v1alpha`. | [REST reference](https://cloud.google.com/chronicle/docs/reference/rest) |
| Endpoint | `https://<location>-chronicle.googleapis.com` (`us`, `eu`, `europe`, and Google Cloud regions such as `europe-west2`) | same |
| Resource | `projects/{project}/locations/{location}/instances/{customer id}` | same |
| Auth | OAuth 2.0, scope `https://www.googleapis.com/auth/cloud-platform` or `…/auth/chronicle`; service account or workload identity. IAM permissions per method (`chronicle.rules.create`, `chronicle.rules.verifyRuleText`, `chronicle.ruleDeployments.update`, …). | each method page |
| `Rule` | `name` (`…/rules/ru_<uuid>`), `revisionId` (`v_<10 digits>_<9 digits>`), `text`, `etag`, `scope`, and output-only `displayName`, `author`, `severity.displayName`, `metadata` (all from `meta`), `type` (`SINGLE_EVENT`, `MULTI_EVENT`), `allowedRunFrequencies`, `compilationState`, `compilationDiagnostics`, `referenceLists`, `timeWindowDuration` | [Rule](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.rules) |
| Create | `POST …/rules` with a `Rule`; only `text` (and `scope`) are input | [create](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.rules/create) |
| Update | `PATCH …/rules/{rule}?updateMask=…`. A changed text is a new revision. A stale `etag` fails with `ABORTED`. | [patch](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.rules/patch) |
| Delete | `DELETE …/rules/{rule}`. Without `force` it fails when the rule has detections or retrohunts; `force=true` deletes those too. The deployment is always deleted. | [delete](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.rules/delete) |
| `RuleDeployment` | `…/rules/{rule}/deployment`: `enabled`, `alerting`, `archived` (only with `enabled: false`; while archived, nothing else changes), `runFrequency`, `scheduleCustomizations` (`ensureEnrichmentCompleteness`, `lateArrivingDataAdjustment`, sent under the `runFrequency` mask), and output-only `executionState`, `producerRules`, `consumerRules`. Updates are not atomic. | [RuleDeployment](https://cloud.google.com/chronicle/docs/reference/rest/v1/RuleDeployment), [updateDeployment](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.rules/updateDeployment) |
| `RunFrequency` | `LIVE` (single-event, including windowed), `LIVE_CUSTOMIZABLE` (every 10 minutes, multi-event windows under 1 hour), `HOURLY_CUSTOMIZABLE` (windows up to 2 days), `DAILY` (window/10, windows over 2 days), legacy `HOURLY`. Google remaps a value a rule cannot use. | [Rule](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.rules#RunFrequency) |
| `verifyRuleText` | `POST {instance}:verifyRuleText` with `{ruleText}` → `{success, compilationDiagnostics[{message, position{startLine, startColumn, endLine, endColumn}}, severity WARNING\|ERROR, uri], allowedRunFrequencies, nearRealTimeLiveRuleEligible, inputsUsed}`. A refused rule is HTTP 200 without `success`. Positions are 1-based and may be empty. | [verifyRuleText](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances/verifyRuleText), `content_manager` README |
| `udmSearch` | `GET {instance}:udmSearch` with `query`, `timeRange`, `limit` (≤ 10,000), `queryDialect` (`YL2` — the default — or `SQL`); returns `events`, `moreDataAvailable`, and `stats`; read-only | [udmSearch](https://cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances/udmSearch) |
| Legacy API | The Backstory Detection Engine API (`/v2/detect/rules`, `:verifyRule`) is deprecated; it is discontinued on 2027-07-20 | [Detection Engine API](https://cloud.google.com/chronicle/docs/reference/detection-engine-api) |
| Quotas | Per-method quotas are shown in the Cloud console only. Google's `content_manager` sleeps 60 s on HTTP 429. | `content_manager` |

### Rule metadata

- `meta` is required, `key = "value"` pairs. Google extracts `author` and `severity` into `Rule.author` and `Rule.severity`; all keys appear in `Rule.metadata` and as detection labels ([meta syntax](https://cloud.google.com/chronicle/docs/yara-l/meta-syntax), [outcome syntax](https://cloud.google.com/chronicle/docs/yara-l/outcome-syntax)).
- The MITRE ATT&CK coverage page reads meta `technique` as comma-separated ids (`technique = "T1548,T1134.001"`); `tactic` and `technique` become read-only `google.mitre.*` tags ([MITRE dashboard](https://cloud.google.com/chronicle/docs/detection/mitre-dashboard)).
- The community style guide requires `author`, `description`, `severity` and `priority` (each `Info`, `Low`, `Medium`, `High`, or `Critical`), `tactic` and `technique` ids, and `.yaral` files. Severity values across the 948 community rules are Title-case.
- `$risk_score` in `outcome` sets `security_result.risk_score`; without it Google uses 40 on an alerting rule and 15 otherwise.

### YARA-L

The language pages ([getting started](https://cloud.google.com/chronicle/docs/yara-l/getting-started), [expressions](https://cloud.google.com/chronicle/docs/yara-l/expressions), [match](https://cloud.google.com/chronicle/docs/yara-l/match-syntax), [outcome](https://cloud.google.com/chronicle/docs/yara-l/outcome-syntax), [condition](https://cloud.google.com/chronicle/docs/yara-l/condition-syntax), [options](https://cloud.google.com/chronicle/docs/yara-l/options-syntax), [windowing](https://cloud.google.com/chronicle/docs/yara-l/windowing-logic), [functions](https://cloud.google.com/chronicle/docs/yara-l/functions), [reference lists](https://cloud.google.com/chronicle/docs/yara-l/reference-list-syntax), [composite rules](https://cloud.google.com/chronicle/docs/yara-l/composite-detection-rules)) define:

- sections `meta`, `setup`, `events`, `match`, `outcome`, `condition`, `options`, `export` for rules; `dedup`, `order`, `limit`, `select`, `unselect`, and multi-stage `stage` blocks for search only;
- case-insensitive keywords; `//` and `/* */` comments; `"…"` strings with escapes, `` `…` `` raw strings, `/…/` RE2 regex literals with `nocase`; non-negative numbers; `m`, `h`, `d` durations;
- event variables (`$e.<UDM path>`, `$g.graph.<entity path>`, `$d.detection.<…>`), placeholders, `#` counts, `%list` reference lists and `%table.column` data tables;
- limits: 20 outcome variables, arrays of 25 values in rules, 10/5/5 `in` statements (7/4/2 in search), function nesting 20, 10,000 detections per rule version per day, composite depth 10;
- condition rules: `!` rather than `not` on event terms, `or` across at most 2 event variables in rules, non-existence needs a window and a bounded event;
- `nocase` is refused on enumerated fields; `window_start` and `window_end` are reserved.

Google publishes no grammar and no compiler. The keyword page also lists YARA's string keywords (`strings`, `ascii`, `wide`, …), a documentation copy that no YARA-L rule uses.

### Existing tooling

| Tool | What it is | Use here |
|------|------------|----------|
| [`chronicle/yara-l-extension`](https://github.com/chronicle/yara-l-extension) | Google's VS Code TextMate grammar (Apache-2.0), scope `source.yara-l`, `.yaral` and `.yl2`; last updated 2024, no `setup`, `export`, or `by` | Reference for token classes only |
| [`MXfive/tree-sitter-yaral`](https://github.com/MXfive/tree-sitter-yaral) | Unofficial tree-sitter grammar (MIT) 0.1.0, missing `by`, `of`, `if`, `setup`, `export` | Prior art; not vendored |
| `google/secops-wrapper` | Python SDK: rule CRUD, deployment, `validate_rule` (v1alpha, first diagnostic only), retrohunts | Shapes confirmed; opentide keeps its own `TenantSession` |
| `chronicle/detection-rules` `content_manager` | Rule text plus `rule_config.yaml` (`enabled`, `alerting`, `archived`, and ids written back) keyed by rule name | The run-state model this RFC follows; the ids move to deployment state |
| [`AttackIQ/pySigma-backend-secops`](https://github.com/AttackIQ/pySigma-backend-secops) | Sigma → UDM search and YARA-L (LGPL-3.0, beta) | Out of scope |

No YARA-L language server or linter exists.

## Detailed design

### 1. Spec layout

| Path | Content |
|------|---------|
| `specs/languages/yara-l-1.0.md` (new) | Text forms (`YaraLRule`, `YaraLSearch`), the block form (`YaraLSections`, `YaraLMatch`, `YaraLOptions`), the `rule` and `search` profiles, sections, lexical structure, expressions, `match`/`outcome`/`condition`/`options` rules, limits, UDM and function catalogues, diagnostics, highlighting |
| `specs/platforms/google-secops-1.0.md` (new) | Block, constraints, advisories, rule name, meta, severity, assembly, tenant setup, deploy, deletion, errors, query validation, `opentide query` |
| `specs/platforms/index.md` 1.8 | Eleventh platform; `--live` allowlist; static-validation bar; external ids |
| `specs/validation.md` 1.10 | `--live` row, advisories, language diagnostics, fixture checker |
| `specs/deployment-state.md` 1.5 | `google_secops` is state-backed: `ru_<uuid>` |
| `specs/objects/rule-1.0.md`, `rule-1.1.md` | `configurations.google_secops`; `system: google_secops` searches are YARA-L |

### 2. The block carries the sections, deploy assembles the rule

```yaml
configurations:
  google_secops:
    enabled: true
    schema: platform::google_secops::1.0
    status: STAGING               # shared; required
    name: ""                      # shared; the YARA-L rule name, empty → derived
    severity: High                # Info | Low | Medium | High | Critical; default from response.alert_severity
    priority: High                # default: severity
    alerting: null                # default: false under PREVIEW, true under RELEASE
    run_frequency: LIVE_CUSTOMIZABLE  # LIVE | LIVE_CUSTOMIZABLE | HOURLY_CUSTOMIZABLE | DAILY; default: first allowed
    schedule:                     # customizable frequencies only
      ensure_enrichment_completeness: true
      late_arriving_data_adjustment: 30m
    meta:                         # extra meta, after the derived keys
      data_source: Okta
    events: |                     # YARA-L text
      $fail.metadata.event_type = "USER_LOGIN"
      $fail.security_result.action = "BLOCK"
      $fail.target.user.userid = $user
      $success.metadata.event_type = "USER_LOGIN"
      $success.security_result.action = "ALLOW"
      $success.target.user.userid = $user
    match:                        # YAML: group_by, window, type (hop | tumbling | sliding), pivot, direction
      group_by: [$user]
      window: 30m
    outcome: |                    # YARA-L text
      $risk_score = max(80)
    condition: |                  # YARA-L text; a block scalar, because a plain `#fail` is a YAML comment
      #fail >= 10 and $success
    options:                      # YAML: allow_zero_values, suppression_window
      suppression_window: 1h
```

The rule name and the `meta` section are what opentide already knows: name, author, description, severity, ATT&CK. Writing them twice, once in Tide and once in YARA-L, would let them drift, and the YARA-L copy is the one analysts see. So opentide owns them, and the author owns the detection logic. The assembled text is fully determined by the rule file: `fixtures/platforms/google-secops/*.yaral` are its goldens, derived from the spec by `scripts/test_platform_google_secops.py`.

**Where the line between YAML and YARA-L falls.** Each section is its own key, so the rule's shape is the schema's business: a missing `condition` is a missing key, sections cannot come out of order, a pasted `rule` header is caught on the key it was pasted into, and each finding names its section (`configurations.google_secops.condition`). `match` and `options` are small closed shapes, a list of placeholders and a window, two typed options, so they are YAML objects that JSON Schema validates and editors complete. `events`, `outcome`, and `condition` are expression languages and stay text, one block scalar each. Splitting them further into YAML lists or maps breaks on YAML's own syntax: `$tactic = "Discovery"` as a map entry `tactic: "Discovery"` loses the quotes that make it a string literal, a regex with `: ` turns a list item into a mapping, and a plain `#fail >= 10` is a YAML comment. That last trap applies to `condition` even as one text, so a null or blank section is its own error (`yaral_section_empty`) with a message that names the `#`.

Each section text is sent verbatim, indented four spaces under its label. A line of a section maps to a fixed line of the assembled rule, so a `verifyRuleText` diagnostic lands on its line in the YAML. This is the HarfangLab decomposed-YARA pattern: one injection spanning several scalars, with the header, meta, labels, `match`, and `options` as generated text.

### 3. Run state follows the status strategy

| Strategy | Deployment |
|----------|------------|
| `PREVIEW` | `enabled: true`, `alerting: false` unless the block sets `alerting` |
| `RELEASE`, `UNIVERSAL` | `enabled: true`, `alerting: true` unless the block sets it |
| `DISABLEMENT` | `enabled: false`, `alerting: false`; the text is still kept current |
| `DELETION` | archive (default), or delete without `force` |

A staging rule therefore runs on live data and records detections, which is how Google itself recommends evaluating a rule, without raising alerts. `run_frequency` defaults to the first frequency `verifyRuleText` allows, in the order `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE`, `DAILY`, so a block that names none gets the fastest one Google accepts for its shape.

### 4. Identity and deployment state

The rule id is assigned at create and is the only stable handle: Google does not document rule names as unique, and listing to find a rule is forbidden by deployment state. `google_secops` is state-backed, with the id stored as `ru_<uuid>`, never as a revision (`@v_…`) or a full resource name, since the instance comes from the tenant. The JSON Schema gains `$defs/secopsRuleTenants`.

### 5. Deletion never destroys detections

Detections are the audit record of what a rule found. `force=true` deletes them, so opentide never sends it. The default `deletion = "archive"` disables and archives the rule and keeps the binding, so a later deploy unarchives the same rule with its history. `deletion = "delete"` removes a rule that has nothing attached; when Google refuses, deploy archives instead and warns.

### 6. Validation in three layers

| Layer | Where | What |
|-------|-------|------|
| Static | `opentide validate`, editors | Platform constraints (`google_secops_*`), the YARA-L engine (`yaral_*`) on the sections as assembled |
| Live | `opentide validate query --live` | `verifyRuleText` on the assembled text; diagnostics mapped to YAML positions; `allowedRunFrequencies` checked against the block |
| Deploy | `opentide deploy` | `verifyRuleText` before every create and text update |

The engine is an approximation of a closed compiler, so its error list is limited to what Google's pages state and Google's compiler refuses. Anything Google's pages leave unsaid stays a warning or is not reported. Reference lists, data tables, and composite producer names live in the tenant and are never reported unknown: only `verifyRuleText` resolves them.

### 7. Analysis engine (language-server)

| Item | Design |
|------|--------|
| Language id | `yaral`; suffixes `.yaral`, `.yl2` |
| Grammar | `grammars/tree-sitter-opentide-yaral`, written for this spec (sections incl. `setup`/`export`, hop/tumbling/sliding windows, `!` terms, maps, `%table.column`, multi-stage search). `MXfive/tree-sitter-yaral` is too incomplete to vendor. |
| Crate | `opentide-yaral`: profiles, section checks, scope (event variables, placeholders, outcomes), condition shape, window bounds, outcome aggregation, regex (RE2 syntax via `regex-syntax`), UDM and function lookups |
| Catalogues | `catalogs/yaral/udm.toml` (field, type, repeated, enum values, deprecated) and `catalogs/yaral/functions.toml` (signature, availability), generated by `scripts/sync_yaral_catalogs.py` from Google's pages, like the GravityZone criteria |
| Highlighting | `highlights/queries/yaral/highlights.scm` mapping to existing captures ([yara-l-1.0](../specs/languages/yara-l-1.0.md#highlighting)); `generate-highlights` emits `yaral.tmLanguage.json`, Monaco, and Helix |
| Injection | the section texts of `configurations.google_secops` as one injection (the `rule` profile, with the generated header, meta, labels, `match`, and `options` as synthetic text) and `response.procedure.searches[].query` with `system: google_secops` (the `search` profile) |
| Editor features | Completion of UDM paths after `$e.`, enum values after `metadata.event_type =`, functions after a namespace; hover with the UDM type and Google's function docs; signature help |
| Oracle | No offline reference exists. A scheduled CI job runs the conformance corpus through `verifyRuleText` on a sandbox tenant when credentials are present, and `scripts/oracles/README.md` says so. |
| Corpus | `testdata/conformance/external/yaral/`: community rules from `chronicle/detection-rules` (Apache-2.0) and `.broken.` twins |

### 8. opentide

| Item | Design |
|------|--------|
| Models | `GoogleSecopsConfig`, `GoogleSecopsSchedule`, tenant setup with `$ENV` credentials |
| Client | `TenantSession` with Google OAuth (service-account JSON or ADC), regional endpoint, retry on 429/503 |
| Compiler | Rule name, meta, severity, ATT&CK via the Elastic tactic table, assembly; golden tests on the fixtures |
| Deployer | Deployment-state decisions; verify → create → bind → deployment; text diff before patch; archive/unarchive; delete without force |
| Validators | `OFFLINE_QUERY_LANGUAGES["google_secops"] = ("yaral",)`; live validator on `verifyRuleText` with position mapping |
| Runner | `opentide query --platform google_secops` on `udmSearch` |
| Surfaces | Bundled TOML, template, `opentide setup` prompt, docs, MCP `validate_query` |

## Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| L1 | `tree-sitter-opentide-yaral` grammar, corpus gate, external corpus | language-server | 4–5 |
| L2 | UDM and function catalogue sync script and data | language-server | 2–3 |
| L3 | `opentide-yaral` engine: profiles, scope, condition, windows, outcomes, UDM/function/regex checks, codes | language-server | 6–8 |
| L4 | Highlights, injection (synthetic header), completion, hover, signature help | language-server | 3–4 |
| L5 | `verifyRuleText` oracle job | language-server | 1–2 |
| O1 | Models, tenant setup, Google auth on `TenantSession` | opentide | 2–3 |
| O2 | Compiler and golden tests | opentide | 2 |
| O3 | Deployer on deployment state (create, update, run state, archive, delete, errors) with a fake API | opentide | 4–5 |
| O4 | Live validator, `opentide query` runner | opentide | 2–3 |
| O5 | Wiring, bundled TOML, template, docs, MCP, e2e | opentide | 3 |
| W1 | Website: `yaral` grammar for code blocks, platform page | website | 1 |

About 30–40 person-days. The platform can ship before the engine with structural checks and `--live`, as Bitdefender did before the YARA engine.

## Drawbacks

- **The offline engine approximates a closed compiler.** Google can accept or refuse what the engine does not, and pages disagree (window bounds, `in` limits). `--live` is the authority, and CI should run it.
- **Copy-paste from Google's console needs a split.** A community rule must lose its header and `meta`, and each section moves under its own key, with `match` and `options` rewritten as YAML. An import command can do that mechanically (unresolved).
- **UDM catalogue drift.** A field Google adds is an error until the sync script runs.

## Alternatives

- **The whole rule verbatim in the block** (a `YaraSignature`-style `rule` text). Rejected: name, description, severity, and ATT&CK would be written twice and drift, and deploy would have to either rewrite the author's `meta` (forbidden for verbatim text) or leave Google's view of the rule unrelated to the Tide rule.
- **One text for the whole body** (`query: |` holding `events:` through `options:`). Rejected after review: section order, required sections, and pasted headers become text-scanning codes instead of schema, findings cannot name their section, and `match` and `options` lose typed validation and completion.
- **Predicates and outcomes as YAML lists or maps** (`events: [- $e.metadata.event_type = …]`, `outcome: {risk_score: max(80)}`). Rejected: YAML reads string literals, regexes, and `#` counts as its own syntax ([section 2](#2-the-block-carries-the-sections-deploy-assembles-the-rule)), and YARA-L comments and multi-line expressions do not survive.
- **Identity by rule name or by an `opentide_uuid` meta lookup.** Rejected by deployment state, and Google does not document names as unique.
- **`DELETION` with `force=true`.** Rejected: it destroys detections.
- **Mapping PREVIEW to a disabled rule.** Rejected: a disabled rule produces no evidence. Non-alerting runs are Google's own staging mechanism.
- **Vendoring `MXfive/tree-sitter-yaral` or Google's TextMate grammar.** Rejected: both miss current syntax, and neither has the node structure the checks need.
- **GoogleSQL rules** (`ruleLanguage: GOOGLE_SQL`, preview). Deferred: a second language in the same block is an additive `language` key once it is GA.

## Resolved questions

Each question open at the first draft, with the evidence and the decision the specs now carry.

| Question | Evidence | Decision |
|----------|----------|----------|
| Hop-window bound: 48 hours or 14 days? | `match` syntax says 48 hours. The run-frequency pages run multi-event rules with windows over 48 hours at window/10, `RunFrequency.DAILY` exists for windows over 2 days, and composite detections state "All detection rules have a maximum match window of 14 days". The 48-hour table is stale. | Rules: hop and sliding windows 1m–14d. Searches: 1m–48h. Tumbling (pre-GA): 1m–72h, as its own page says. `verifyRuleText` remains the authority for a tenant. |
| How does meta `severity` reach a detection, and what is `priority`? | `verifyRuleText` and `Rule` show `severity.displayName` extracted verbatim from meta. `SecurityResult.priority` is "not populated when the SecurityResult appears in a detection". No page maps the string to the detection severity enum. | opentide writes Google's community spelling (`Info`…`Critical`) and documents it as a label. Alert weight is `$risk_score`, which Google documents, and the `google_secops_risk_score_missing` advisory asks for it. `priority` is a label. |
| May `export` precede `options`? | The data-tables page: writing to a data table "must be the final action of the query". No example shows both. | `export` is the last section. Deploy writes `options` then `export`; in a `.yaral` file, `export` before `options` is `yaral_section_order`. |
| Rule-name length limit and uniqueness | No page documents either. Google's `content_manager` extracts `[A-Za-z0-9_]+` and treats names as case-insensitively unique. | No length check (none documented; `verifyRuleText` reports one if Google has it). `google_secops_name_duplicate` compares names case-insensitively. |
| `udmSearch` version and dialect; `opentide query --rule` | `udmSearch` is in v1 with `queryDialect` `YL2` (default) or `SQL`. A rule differs from a search in repeated-field semantics (unnested in rules, implicit `any` in search) and sliding windows (rules only). | `opentide query` uses v1 `udmSearch` with `queryDialect=YL2`. `--rule` is not supported: running a rule's sections as a search would return different results from the rule. Hunts are the search form. |
| `opentide import` for `.yaral` files | Mechanical: split header, meta, and sections; render `match`/`options` back to YAML. | Follow-up, not part of 1.0: it adds a command, not a field, so it needs no change to these specs. |
| Retrohunts | `POST /v1/{rule}/retrohunts` is a long-running operation that writes detections. | Follow-up command (`opentide hunt`), outside `deploy` and `query`. |
| Hunt validation against a tenant | `GET /v1/{instance}:validateQuery` validates search text. | Follow-up: hunts are checked offline under the `search` profile in 1.0. |
| Curated rules (`ur_…`) and findings refinements | Console objects with no opentide counterpart. | Out of scope. |
| GoogleSQL rules (`ruleLanguage: GOOGLE_SQL`) | Preview since 2026-09. | Deferred: an additive `language` key once GA. |

## References

- Research sources in [Research](#research)
- [RFC 0010](0010-deployment-external-ids.md), [RFC 0015](0015-yara-language.md), [RFC 0016](0016-bitdefender-gravityzone-platform.md), [RFC 0007](0007-elastic-security-platform.md)
