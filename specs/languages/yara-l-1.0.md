---
spec: language-yara-l
version: "1.1"
schema_id: null
status: normative
supersedes: null
---

# YARA-L language

## Summary

YARA-L 2.0 is the detection and search language of Google Security Operations (Google SecOps, formerly Chronicle). This spec defines it once for opentide: the text forms a platform block or a file carries, the dialect the analysis engine accepts, the diagnostics it reports, the profiles that separate a rule from a search, and how the language is highlighted.

The contract is YARA-L as the Google SecOps rules engine compiles it, as Google documents it at [cloud.google.com/chronicle/docs/yara-l](https://cloud.google.com/chronicle/docs/yara-l/getting-started) (fetched 2026-11-11). Google publishes no grammar, no compiler, and no reference parser. The analysis engine (language-server) is therefore an offline approximation: it reports the [errors](#errors) below, which Google's compiler also refuses, and never claims a compile. The tenant's own compiler, `verifyRuleText`, is the live check ([google-secops-1.0](../platforms/google-secops-1.0.md#query-validation)). Design and research are in [RFC 0017](../../rfcs/0017-google-secops-yara-l.md).

YARA-L shares its name and little else with [YARA](yara-1.0.md). Google's keyword page lists YARA's string keywords (`strings`, `ascii`, `wide`, `filesize`, …); no YARA-L rule uses them, and this spec does not reserve them. It matches events, not bytes. No YARA code applies to it, and no `yara_*` code is reused.

## Requirements

- A platform block that deploys a YARA-L rule MUST carry [`YaraLSections`](#yaralsections): one key per rule section, `events` and `condition` required. Deploy assembles the [`YaraLRule`](#yaralrule) from them: the `rule` header and `meta:` from the opentide rule, then each section under its label, in [order](#sections).
- `events`, `outcome`, `condition`, `setup`, and `export` MUST be YARA-L text. `match` and `options` MUST be YAML objects, validated by their field tables. A section text MUST NOT hold a section label, a `rule` header, or braces around a rule (`yaral_section_header`).
- A section key that is present with no text (YAML `null`, or blank) MUST fail with `yaral_section_empty`. A plain YAML scalar that starts with `#` is a YAML comment, so `condition: #fail > 3` loads as null; the message MUST say so.
- A YAML alias at a section key MUST fail with `yaral_section_alias`. Each text is written out in the block, as a [`YaraSignature`](yara-1.0.md#yarasignature) is.
- Deploy MUST send each section text verbatim. It MAY normalise line endings to `\n`, drop leading and trailing blank lines, and indent each non-blank line by four spaces. It MUST NOT add, remove, reorder, or rewrite an expression, a comment, or a literal of a section.
- Static validation MUST report every [error](#errors) as a failure and every [warning](#warnings) without failing the rule.
- Static validation MUST check a block's sections as the one rule deploy assembles, so a finding has the same verdict in the block and in a `.yaral` file, and a variable bound in `events` is in scope in `match`, `outcome`, and `condition`. A finding inside a section text MUST be reported at its line and column in the YAML; a finding in `match` or `options` at that key; a finding that only the generated header or meta can raise is a platform constraint code instead.
- The engine MUST NOT report a reference list, a data table, a rule name in a composite rule, or a curated rule as unknown. They live in the tenant.
- YARA-L is checked offline by `opentide validate` and by `opentide validate query` without `--live` (a block's sections, or a `.yaral` file). `--live` is the tenant compile (`verifyRuleText`). An offline result MUST NOT be reported as a tenant check.

## Definition

### Text forms

| Form | Where | Content |
|------|-------|---------|
| `YaraLRule` | a `.yaral` file; the text deploy sends | One rule: `rule <name> {`, `meta:`, then the [sections](#sections), then `}`. Comments may precede and follow it. |
| `YaraLSections` | `configurations.google_secops` (its `events`, `match`, `outcome`, `condition`, `options`, `setup`, `export` keys) | One rule's sections as separate keys. No `rule` header and no `meta`. |
| `YaraLSearch` | `response.procedure.searches[].query` with `system: google_secops`; `opentide query --platform google_secops` | A YARA-L search: the `events` predicates, with or without the `events:` label, then the optional search sections. |

A file holds one rule. Google stores one rule per resource, and `verifyRuleText` takes one. A second `rule` in a file is `yaral_parse_error`.

#### YaraLRule

```
rule <identifier> {
  meta:
    <key> = "<value>"
    ...
  events:
    ...
  [match:
    ...]
  [outcome:
    ...]
  condition:
    ...
  [options:
    ...]
}
```

#### YaraLSections

| Key | Type | Required | Section | Content |
|-----|------|----------|---------|---------|
| `setup` | string | no | `setup:` | YARA-L text |
| `events` | string | yes | `events:` | YARA-L text: predicates, placeholder assignments, joins |
| `match` | [YaraLMatch](#yaralmatch) | with two or more event variables | `match:` | A YAML object |
| `outcome` | string | no | `outcome:` | YARA-L text: `$name = <expression>` lines |
| `condition` | string | yes | `condition:` | YARA-L text: one boolean expression |
| `options` | [YaraLOptions](#yaraloptions) | no | `options:` | A YAML object |
| `export` | string | no | `export:` | YARA-L text: `%table.write_row(…)` calls |

The order of the keys in the YAML does not matter: deploy writes the sections in [section order](#sections). Write the texts as block scalars (`|`). A plain or quoted scalar works but YAML rewrites it: a plain one loses everything after ` #`, and a double-quoted one consumes its backslashes.

Section texts stay text, not YAML lists or maps. An expression that YAML would load as a mapping or a quoted string (`$tactic = "Discovery"` as `tactic: "Discovery"` loses its quotes) cannot be told apart from a literal, and YARA-L comments, regexes, and multi-line expressions would not survive. `match` and `options` are the two closed shapes YAML can type exactly.

#### YaraLMatch

| Field | Type | Required | Default | Rendered |
|-------|------|----------|---------|----------|
| `group_by` | list[string] | yes | — | The placeholders, each `$name`, non-empty, no repeats, joined with `, ` |
| `window` | duration | yes | — | `<n>m`, `<n>h`, or `<n>d`, within the [bounds](#match) of `type` |
| `type` | string | no | `hop` | `hop` → `over`, `tumbling` → `by`, `sliding` → `over … before\|after $pivot` |
| `pivot` | string | with `sliding` | — | The event variable the window is anchored on, `$name` |
| `direction` | string | with `sliding` | — | `before` or `after` |

`{group_by: [$user, $ip], window: 30m}` renders `$user, $ip over 30m`; `{group_by: [$host], window: 1h, type: tumbling}` renders `$host by 1h`; `{group_by: [$user], window: 5m, type: sliding, pivot: $login, direction: after}` renders `$user over 5m after $login`. A shape outside this table (no `group_by`, `pivot` without `sliding`, `sliding` without `pivot` and `direction`, a name that is not `$identifier`) is `yaral_match_shape`.

#### YaraLOptions

| Field | Type | Default | Rendered |
|-------|------|---------|----------|
| `allow_zero_values` | boolean | `false` | `allow_zero_values = true` |
| `suppression_window` | duration (`m`, `h`, `d`) | none | `suppression_window = 1h` |

Only keys that are set are rendered, in this order. Any other key, or a value of the wrong type, is `yaral_option`.

### Profiles

A profile names which sections, functions, and data a text may use. The engine picks it from where the text is.

| Profile | Used by | Sections | `meta` |
|---------|---------|----------|--------|
| `rule` | `YaraLRule`, `YaraLSections` | `meta`, `setup`, `events`, `match`, `outcome`, `condition`, `options`, `export` | required in a `YaraLRule`; generated for `YaraLSections` |
| `search` | `YaraLSearch` | `events` (label optional), `match`, `outcome`, `condition`, `dedup`, `order`, `limit`, `select`, `unselect`, and up to four named `stage <name> { … }` blocks with a root query (multi-stage search) | optional and ignored, as Google's getting-started table says |

### Sections

Sections appear at most once, in this order. A section out of order or repeated is `yaral_section_order`. A section the profile does not have is `yaral_section_unavailable`.

| # | Section | `rule` | `search` | Content |
|---|---------|--------|----------|---------|
| 1 | `meta` | required (`YaraLRule`) | — | `key = "value"` lines. Keys are identifiers, values double-quoted strings. A key appears once (`yaral_meta_duplicate`). |
| 2 | `setup` | optional | — | Entity-graph enrichment from data tables: `graph_override`, `graph_append`, `graph_exclude` |
| 3 | `events` | required | required, except in a stage or root query that reads only earlier stages (`$stage.field`), which may hold only `match`, `outcome`, and the later sections | Predicates on event variables, placeholder assignments, function calls. Lines are joined by an implicit `and`. A search may join two stages with `cross join $a, $b`. |
| 4 | `match` | optional; required with two or more event variables (`yaral_multi_event_match`) | optional | `<placeholders> over <window>`, `by <window>`, or `over <window> before\|after $pivot` |
| 5 | `outcome` | optional | optional | `$name = <expression>` assignments, at most 20 (`yaral_outcome_limit`) |
| 6 | `condition` | required | optional | Boolean expression over event variables, placeholders (`#name` counts), and outcome variables |
| 7 | `options` | optional | — | `allow_zero_values = true\|false`, `suppression_window = <duration>` |
| 8 | `export` | optional | optional | `%table.write_row(column: $value, …)`: write a data-table row per detection or result; only outcome variables |
| 9 | `dedup` | — | optional | Placeholders or field paths |
| 10 | `order` | — | optional | `<expr> asc\|desc`, comma-separated |
| 11 | `limit` | — | optional | A positive integer |
| 12 | `select`, `unselect` | — | optional | Field paths |

`export` is the last section of a rule: Google states that writing to a data table "must be the final action of the query" ([data tables](https://cloud.google.com/chronicle/docs/investigation/data-tables)). `export` before `options` is `yaral_section_order`.

A section label is its name followed by `:`, case-insensitive like every keyword.

### Lexical structure

| Token | Syntax |
|-------|--------|
| Comment | `// …` to end of line; `/* … */`, not nested |
| Keyword | case-insensitive, in any mix of cases (`and`, `AND`, `aNd`): `rule`, the section names, `and`, `or`, `not`, `nocase`, `in`, `regex`, `cidr`, `any`, `all`, `over`, `by`, `before`, `after`, `if`, `of`, `true`, `false`, and in search `asc`, `desc`. YARA-L has no `null` and no `is null`: a missing field is its zero value (`""`, `0`, `false`, the first enum value). |
| Identifier | `[A-Za-z_][A-Za-z0-9_]*`. A keyword is not an identifier (`yaral_reserved_identifier`). |
| Event or placeholder variable | `$` identifier: `$e`, `$user`. `$window_start` and `$window_end` are reserved (`yaral_reserved_identifier`). |
| Outcome variable | `$` identifier assigned in `outcome` |
| Count | `#` identifier: the number of events of an event variable, or of distinct values of a placeholder, in a match |
| Reference list | `%` identifier |
| Data table column | `%` identifier `.` identifier |
| Window bound | `window_start`, `window_end` (bare) in `outcome`, `condition`, and `order`, with a `match` window |
| String | `"…"` with the escapes `\\`, `\"`, `\n`, `\r`, `\t`; `` `…` `` raw, no escapes. Any other escape is the warning `yaral_string_escape`: Google documents only these, yet its own examples and community rules use `\.`, `\T`, and `\L`, so the compiler's verdict is not known offline. |
| Regular expression | `/…/`, optionally followed by `nocase`. RE2 syntax (`yaral_regex`). `\/` is a literal slash. |
| Integer, float | non-negative decimal: `5`, `3.5`. A sign is the unary operator. |
| Duration | integer then `m`, `h`, or `d`, no space: `10m`, `1h`, `2d`. A search also takes `w` (7 days) and `mo` (30 days), and the unit words `minute`, `hour`, `day`, `week`, `month` with an optional count (`by day`, `over every 2 hour`), as Google's statistics and multi-stage pages write them; every unit is bound-checked by its length in minutes. |
| Operators | `=`, `!=`, `<`, `<=`, `>`, `>=`, `+`, `-`, `*`, `/`; `[ ]` for map and array index; `.` for field paths and function namespaces |

Precedence from highest: `not` (and `!`), `and`, `or`. In `events`, lines are joined by an implicit `and`, which binds after any explicit `or` on a line.

### Expressions

- **Field path.** `$e.<path>` where `<path>` is a UDM field ([UDM catalogue](#udm-catalogue)), optionally prefixed by `udm.` or `graph.` (entity context) and indexed by `["key"]` on map fields (`additional.fields`, `ingestion_labels`, `detection_fields`) or by an integer on repeated fields.
- **Comparison.** `<a> <op> <b>`, with `nocase` after a string or regex comparison. A field compared with a regex literal matches as `re.regex`.
- **Repeated fields.** `any` and `all` before a comparison of a repeated field. Neither applies to a map index (`yaral_type`).
- **Membership.** `<expr> in %list`, `in regex %list`, `in cidr %list`, `in %table.column`, each optionally preceded by `not`.
- **Placeholder assignment.** `$p = <expr>` in `events`. A function on one side binds the placeholder; the function's arguments come from one event variable at most.
- **Join.** `$e1.<path> = $e2.<path>`, or two assignments to one placeholder.
- **Conditional.** `if(<bool>, <then>)` and `if(<bool>, <then>, <else>)` in `outcome`.
- **Function call.** `<namespace>.<name>(<args>)`, from the [function catalogue](#function-catalogue).

### `match`

| Form | Window | Bounds |
|------|--------|--------|
| `$a, $b over <d>` | hop | rule: `1m` ≤ d ≤ `14d`; search: `1m` ≤ d ≤ `48h` |
| `$a, $b over <d> before $pivot` / `after $pivot` | sliding, anchored on a UDM event variable (never an entity) | rule: `1m` ≤ d ≤ `14d`; search: `1m` ≤ d ≤ `48h` |
| `$a, $b by <d>` | tumbling (Google: pre-GA) | rule: `1m` ≤ d ≤ `72h`; search: `1m` ≤ d ≤ `30d` without a join, `48h` with one. A search joins when it has a `cross join`, two or more event variables, or event predicates together with reads of an earlier stage |

Google's pages disagree on the hop bound: `match` syntax says 48 hours, while the run-frequency reference (`DAILY` for windows over 2 days) and composite detections allow 14 days. The engine follows the rules engine: 14 days for a rule, 48 hours for a search ([RFC 0017](../../rfcs/0017-google-secops-yara-l.md#resolved-questions)).

A window outside its bounds, or with a unit other than `m`, `h`, or `d`, is `yaral_match_window`. Under `rule`, every name before `over` or `by` MUST be a placeholder bound in `events` (`yaral_match_variable`). Under `search`, a bare UDM path (`principal.ip`) also groups, and the window is optional. In a search, predicates name fields without an event variable (`metadata.event_type = "USER_LOGIN"`); `$e.`-prefixed paths are also accepted, and so are the grouped fields of Google's [search syntax reference](https://cloud.google.com/chronicle/docs/investigation/search-syntax-reference) (`ip`, `hostname`, `user`, `hash`, …), `raw = /…/` for raw-log search, and top-level maps (`labels["k"]`). Google drops zero values of match placeholders unless `options: allow_zero_values = true`; the engine reports nothing for this.

### `outcome`

At most 20 outcome variables. With a `match` section, an outcome that reads an event field, or a placeholder that is not a `match` variable, MUST wrap it in an aggregation (`yaral_outcome_aggregation`). Under `rule` the aggregations are `count`, `count_distinct`, `sum`, `max`, `min`, `array`, and `array_distinct`, plus the `window.*` functions (`window.avg`, `window.stddev`, `window.first`, …); `array` and `array_distinct` keep at most 25 values. Under `search`, `avg`, `stddev`, `earliest`, and `latest` are also aggregations, and arrays keep 1,000 values. A bare `avg` in a rule is `yaral_function_unavailable`. An outcome variable used in another outcome is not aggregated again (`yaral_outcome_aggregation`). An outcome MUST NOT introduce a placeholder or an event variable that `events` does not define (`yaral_undefined_variable`).

Outcome names with platform meaning:

| Variable | Meaning |
|----------|---------|
| `$risk_score` | Integer or float, stored in `security_result.risk_score`. Without it Google uses the instance's default: 40 on an alerting rule and 15 otherwise, unless the instance's settings change them. |
| `$risk_entity_to_score`, `$risk_entity_to_score_<suffix>` | The user or asset the risk score is attributed to |
| `$suppression_key` | The key `options: suppression_window` suppresses on, for single-event rules |

### `condition`

- Every event variable of `events` MUST be referenced by `condition`, directly (`$e`, `#e`) or through a placeholder or outcome variable it binds, as Google's condition page allows; a name in `condition` MUST be defined (`yaral_undefined_variable`).
- `$e` means `#e > 0`. Bounded terms are `$e` and `#e > n`; unbounded terms are `!$e`, `#e = 0`, and `#e < n`.
- Event and placeholder terms are negated with `!`, never `not`, and are never separated by commas (`yaral_condition_shape`).
- `or` may join at most 2 event variables in a rule, and 3 in a search; `or` is refused in an unbounded condition, and an `or` among event and placeholder terms needs the whole group in parentheses (`yaral_condition_shape`).
- An unbounded term (non-existence) needs a `match` window and at least one bounded UDM event variable (`yaral_condition_shape`). Google delays such rules by an extra hour.
- Outcome terms compare strings with `=` and `!=` only; a list outcome is tested with `arrays.contains`.
- Outcome variables may be combined with `and`, `or`, and `not` after the event terms.

### `options`

| Key | Value | Default |
|-----|-------|---------|
| `allow_zero_values` | `true` or `false` | `false` |
| `suppression_window` | a positive duration (`5m`, `1h`, `24h`) | `0` (off) |

Any other key, or a value of the wrong kind, is `yaral_option`. In a rule with a `match` window, `suppression_window` must be longer than the window (`yaral_option`); a single-event rule suppresses on its `$suppression_key` outcome. Neither option applies when Google tests a rule. Google's page gives no upper bound for `suppression_window`; the engine accepts any positive duration and reports none.

### Reference lists and data tables

Data tables (`%table.column`) replace reference lists, which Google retires in 2027 (`yaral_reference_list_deprecated`). Limits per rule, from [reference list syntax](https://cloud.google.com/chronicle/docs/yara-l/reference-list-syntax): at most 10 `in` statements in total, at most 5 with `regex`, and at most 5 with `cidr` (`yaral_reference_list_limit`). Google documents a stricter 7, 4, and 2 for search and dashboards; under the `search` profile those apply. List and table names are never checked offline.

### Function catalogue

The engine ships Google's function list with each function's namespace, arity, argument and result types, and availability (rules, search, dashboards). Namespaces: `arrays`, `bytes`, `cast`, `hash`, `math`, `metrics`, `net`, `optimization`, `re`, `strings`, `timestamp`, `window`, plus the bare `group` and `if`. Two functions used on Google's syntax pages but missing from its functions page, `arrays.contains` and `cast.as_uint`, are in the catalogue with that evidence. Every `metrics.*` function on Google's [metrics functions](https://cloud.google.com/chronicle/docs/detection/metrics-functions) page is catalogued, with its named arguments: `period:`, `window:`, `metric:`, `agg:`, and `filter:`, whose value is a boolean expression over the metric's own fields (`value_sum > 10 AND event_count_sum > 2`), and grouping arguments that take `*`. `math.round` takes one or two arguments.

- An unknown namespace or function, or the wrong number of arguments, is `yaral_unknown_function`.
- A function the profile does not offer is `yaral_function_unavailable`. Under `rule`, that is `group` and `math.round`; under `search`, `hash.fingerprint2011`, `hash.sha256`, `math.geo_distance`, `metrics.*`, and `optimization.sample_rate`. The `window.*` functions are offered in both profiles: the functions page marks most of them rules-only, but Google's own multi-stage, dashboard, and SPL-transition searches use `window.avg`, `window.stddev`, `window.median`, `window.first`, and `window.last`.

The catalogue is generated from [YARA-L functions](https://cloud.google.com/chronicle/docs/yara-l/functions) by a sync script in language-server (`catalogs/yaral/functions.toml`), as the GravityZone criteria are.

### UDM catalogue

Field paths are checked against the Unified Data Model: the event model (`metadata`, `principal`, `src`, `target`, `intermediary`, `observer`, `about`, `network`, `security_result`, `extensions`, `additional`), the entity model under `graph`, and the detection model under `detection` (composite rules). The catalogue lists each field's type, whether it repeats, and the values of each enumerated field (`metadata.event_type`, `security_result.action`, …). It is generated from Google's [UDM field list](https://cloud.google.com/chronicle/docs/reference/udm-field-list) (`catalogs/yaral/udm.toml`).

- A path that names a field the model does not have is `yaral_unknown_udm_field`. Google's compiler refuses it ("field … does not exist").
- A string compared with an enumerated field that is not one of its values is `yaral_enum_value`.
- A field marked deprecated in the catalogue is `yaral_deprecated_field` (warning).
- Under a map index, and under `additional.fields`, keys are free: nothing is checked.

### Diagnostics

#### Errors

| Code | Condition |
|------|-----------|
| `yaral_parse_error` | Syntax error, including a second `rule` in one text |
| `yaral_section_header` | A section text holds a section label, a `rule` header, or braces around a rule |
| `yaral_section_empty` | A section key with no text: YAML `null` (a plain scalar starting with `#` is a YAML comment) or blank |
| `yaral_section_alias` | A section key is a YAML alias instead of its own text |
| `yaral_section_missing` | A required section is absent: `meta` in a `YaraLRule`; `events` and `condition` in a rule, as a label in a file or a key in a block |
| `yaral_section_order` | A section is repeated or out of order in a `YaraLRule` |
| `yaral_section_unavailable` | A section the profile does not have (`dedup` in a rule, `options` in a search) |
| `yaral_meta_duplicate` | A meta key appears twice, or a meta value is not a double-quoted string |
| `yaral_reserved_identifier` | A keyword used as a rule name, meta key, or variable; `$window_start`, `$window_end` |
| `yaral_undefined_variable` | A `$name` or `#name` in `match`, `outcome`, `condition`, `export`, `dedup`, or `order` that `events` or `outcome` does not define; an event variable that `condition` references neither directly nor through a placeholder or outcome it binds |
| `yaral_multi_event_match` | Two or more event variables without a `match` section |
| `yaral_match_shape` | A `YaraLMatch` outside its field table |
| `yaral_match_variable` | A `match` name that is not a placeholder bound in `events` |
| `yaral_match_window` | A window outside the [bounds](#match) of its kind and profile, or with another unit |
| `yaral_condition_shape` | `not` or a comma on event and placeholder terms, `or` across more event variables than the profile allows, `or` in an unbounded condition, or non-existence without a window and a bounded event |
| `yaral_nocase_on_enum` | `nocase` on a comparison with an enumerated field |
| `yaral_outcome_limit` | More than 20 outcome variables |
| `yaral_outcome_aggregation` | In a text with `match`, an event field or a non-`match` placeholder used in `outcome` outside an aggregation; an aggregation of an outcome variable |
| `yaral_unknown_function` | Unknown function, or the wrong number of arguments |
| `yaral_function_unavailable` | A function the profile does not offer |
| `yaral_unknown_udm_field` | A field path the UDM catalogue does not have |
| `yaral_enum_value` | A value outside an enumerated field's values |
| `yaral_type` | An operator or function applied to the wrong type (`#e > "5"`, `any` or `all` on a map index, Label or Struct, `nocase` on a number) |
| `yaral_regex` | An invalid RE2 expression in a regex literal or `re.*` argument |
| `yaral_reference_list_limit` | More `in` statements than the profile allows |
| `yaral_option` | An unknown option, or a value of the wrong kind |
| `yaral_export_value` | An `export` `write_row` value Google does not export: in a rule, anything but an outcome variable; in a search, a `match` variable (a search may also write scalar fields, as Google's data-tables page shows) |
| `yaral_window_bound` | `window_start` or `window_end` in `events`, or in a text with no `match` window |

#### Warnings

| Code | Condition |
|------|-----------|
| `yaral_deprecated_field` | A UDM field the catalogue marks deprecated |
| `yaral_unfiltered_event` | An event variable with no equality on `metadata.event_type`, `metadata.log_type`, or `metadata.product_name`: the rule scans every event ([best practices](https://cloud.google.com/chronicle/docs/detection/yara-l-best-practices)) |
| `yaral_leading_wildcard_regex` | A regex that starts with `.*` and is not anchored: RE2 matches unanchored already, and the prefix only costs time |
| `yaral_string_escape` | An escape other than `\\`, `\"`, `\n`, `\r`, `\t` in a double-quoted string |
| `yaral_reference_list_deprecated` | A reference list (`%list` without a column). Google deprecates reference lists from May 2027 and migrates them to data tables by July 2027 ([deprecations](https://cloud.google.com/chronicle/docs/deprecations)) |

#### Checked by the tenant only

Google documents more compile errors than the engine reports. These pass offline and fail `verifyRuleText` (`--live`), which is the authority: an event variable joined to no other; arithmetic joins; a function-to-placeholder assignment over zero or two event variables; a placeholder used only with `!=`; entity-only rules and an entity as a sliding pivot; `any` on a scalar, in a join, in an assignment, or with a reference list, and index-with-`any` forms; `or` or `N of` with a tumbling window; conditions mixing UDM and non-UDM variables, or an unbounded `N of`; a string outcome compared with `<`; data-table `setup` limits (at most two operations, one per entity variable) and mixed `=`/`in` lookups; a parenthesised arithmetic expression at the start of a predicate and two `/` on one line; more than four stages, and a reference to an undefined stage; unsigned-integer arithmetic with an integer literal. The engine never reports one of these as another code.

Codes are stable. The language server's `docs/YARAL.md` maps each one to the Google page it comes from and the test that proves it, as `docs/YARA.md` does for YARA.

### Highlighting

YARA-L uses the frozen [HighlightSpec](https://github.com/opentidehq/language-server/blob/main/highlights/spec.toml) captures. It adds no capture.

| Token | Capture |
|-------|---------|
| Comments | `comment` |
| `rule`, section labels, `stage`, logical and window keywords, `nocase`, `any`, `all`, `of`, `in`, `regex`, `cidr`, `if`, `asc`, `desc` | `keyword` |
| `!` (on event terms), `=`, `!=`, `<`, `<=`, `>`, `>=`, arithmetic | `operator` |
| Rule name | `type` |
| Meta keys, option keys | `property` |
| `$e`, `$placeholder`, `$outcome`, `#count` | `variable` |
| UDM path segments after `$e.`, data table column after `%table.` | `property` |
| Platform outcome names (`$risk_score`, `$risk_entity_to_score*`, `$suppression_key`), `window_start`, `window_end`, `%list`, `%table` | `constant` |
| Function namespace (`strings` in `strings.to_lower`) | `type` |
| Function name, aggregation function | `function.builtin` |
| Strings, raw strings, regex literals, map keys | `string` |
| Integers, floats, durations | `number` |
| `true`, `false` | `boolean` |
| `{`, `}`, `(`, `)`, `[`, `]` | `punctuation.bracket` |
| `,`, `:` | `punctuation.delimiter` |

The language id is `yaral`, the file suffixes `.yaral` (Google's community convention) and `.yl2`, and the TextMate scope `source.yaral`. Google's own VS Code grammar uses `source.yara-l`; opentide's scope differs so both can be installed. In a Tide rule, the section texts of `configurations.google_secops` (`setup`, `events`, `outcome`, `condition`, `export`) are one YARA-L injection under the `rule` profile, spanning the scalars as the rule deploy assembles them; `match` and `options` are YAML, highlighted as Tide properties. `response.procedure.searches[].query` with `system: google_secops` is a YARA-L injection under the `search` profile.

## Relationships

- [google-secops-1.0](../platforms/google-secops-1.0.md): `configurations.google_secops` sections, the assembled rule, `verifyRuleText`
- [platforms](../platforms/index.md): capability matrix and static-validation bar
- [validation.md](../validation.md): language diagnostics, offline and live query validation
- [rule-1.1.md](../objects/rule-1.1.md): `response.procedure.searches[]`
- [RFC 0017](../../rfcs/0017-google-secops-yara-l.md): design and research
- [yara-1.0](yara-1.0.md): the language-spec pattern this follows. No code is shared.

## Defaults & overrides

| Setting | Default |
|---------|---------|
| Profile | `rule` for `YaraLRule` and `YaraLSections`; `search` for `YaraLSearch` |
| `match.type` | `hop` |
| UDM and function catalogues | the versions pinned in the analysis engine |

There are no overrides. A workspace cannot add UDM fields or functions: a custom field lives under `additional.fields`, which is not checked.

## Examples

Block sections (the `rule` profile):

```yaml
configurations:
  google_secops:
    enabled: true
    schema: platform::google_secops::1.0
    status: STAGING
    events: |
      $e.metadata.event_type = "PROCESS_LAUNCH"
      $e.principal.process.file.full_path = /\\(winword|excel|powerpnt)\.exe$/ nocase
      $e.target.process.file.full_path = /\\powershell\.exe$/ nocase
      $e.target.process.command_line = /\s-e(nc|ncodedcommand)?\s/ nocase
      $host = $e.principal.hostname
    outcome: |
      $risk_score = 70
      $command_line = $e.target.process.command_line
    condition: |
      $e
```

A multi-event rule, with `match` and `options` as YAML:

```yaml
    events: |
      $fail.metadata.event_type = "USER_LOGIN"
      $fail.security_result.action = "BLOCK"
      $fail.target.user.userid = $user
      $success.metadata.event_type = "USER_LOGIN"
      $success.security_result.action = "ALLOW"
      $success.target.user.userid = $user
    match:
      group_by: [$user]
      window: 30m
    condition: |
      #fail >= 10 and $success
    options:
      suppression_window: 1h
```

A hunt (the `search` profile):

```yaml
response:
  procedure:
    searches:
      - system: google_secops
        purpose: Encoded PowerShell started by Office, per host
        query: |
          metadata.event_type = "PROCESS_LAUNCH"
          target.process.command_line = /\s-enc\s/ nocase
          $host = principal.hostname
          match:
            $host
          outcome:
            $launches = count(metadata.id)
          order:
            $launches desc
```

Fixtures: [fixtures/platforms/google-secops.yaml](../../fixtures/platforms/google-secops.yaml), the rules under `fixtures/valid/rule-google-secops-*.yaml`, and the rule text deploy assembles from each under [fixtures/platforms/google-secops/](../../fixtures/platforms/google-secops/); invalid: [rule-google-secops-section-header.yaml](../../fixtures/invalid/rule-google-secops-section-header.yaml), [rule-google-secops-condition-comment.yaml](../../fixtures/invalid/rule-google-secops-condition-comment.yaml), [rule-google-secops-sliding-no-pivot.yaml](../../fixtures/invalid/rule-google-secops-sliding-no-pivot.yaml), [rule-google-secops-missing-condition.yaml](../../fixtures/invalid/rule-google-secops-missing-condition.yaml).

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.1 | 2026-11-12 | (Settled during implementation: `yaral_export_value` in a search refuses `match` variables only; what a search join is, for the tumbling bound; the `yaral_outcome_aggregation` row matches the prose.) From a conformance review that ran Google's 765 documented code blocks and 410 community rules through the engine: multi-stage searches (stages and roots that read earlier stages need no `events`, `cross join`, four stages), sliding windows and the `window.*` functions in search, search tumbling windows up to 30 days, `w` and `mo` bound-checked, search grouped fields, `raw`, and top-level maps, `meta` optional in a search, keywords case-insensitive in any mix, `metrics.*` with named arguments and `filter:`, `math.round` with one argument. `yaral_string_escape` is a warning; `yaral_nesting_depth` is removed (Google no longer documents the limit). New errors `yaral_export_value` and `yaral_window_bound`; `yaral_outcome_aggregation` covers non-match placeholders; `any`/`all` on a Struct map is `yaral_type`. A list of the compile errors only the tenant checks. |
| 1.0 | 2026-11-12 | Clarifications from the language-server implementation, checked against Google's pages and the 410 community rules: `condition` may reference an event variable through a placeholder or outcome it binds; `yaral_undefined_variable` also covers `export`, `dedup`, and `order`; function names are `hash.fingerprint2011` and `optimization.sample_rate`, and `arrays.contains` and `cast.as_uint` are catalogued; search durations take unit words; mixed-case keywords are a parse error. No code is added or removed. |
| 1.0 | 2026-11-11 | Initial language spec ([RFC 0017](../../rfcs/0017-google-secops-yara-l.md)): `YaraLRule`, `YaraLSections` (section texts as keys, `match` and `options` as YAML objects), and `YaraLSearch`; the `rule` and `search` profiles; sections, lexical structure, expressions, and limits from Google's YARA-L pages; UDM and function catalogues; 28 error and 4 warning codes; HighlightSpec mapping with no new capture. |
