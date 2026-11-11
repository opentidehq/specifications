---
spec: language-exabeam
version: "1.0"
schema_id: null
status: draft
supersedes: null
---

# Exabeam Query Language

## Summary

The Exabeam Query Language is the search language of Exabeam's New-Scale Security Operations Platform (the New-Scale SIEM). Exabeam's guides call it "EQL". opentide never does, because `eql` is Elastic's Event Query Language ([elastic-1.0](../platforms/elastic-1.0.md)). The opentide language id is **`exabeam`**, and a query file ends in **`.exabeam`**.

The language has two layers:

- the **filter**, "a limited subset of Lucene": `field:"value"` terms, `AND`/`OR`/`NOT`, lists, ranges, CIDR blocks, context-table lookups, and four functions (`RGX`, `RGXi`, `WLD`, `WLDi`);
- the **advanced operators**, a SQL-like layer for Search only: `SELECT`, `WHERE`, `GROUP-BY`, `ORDER-BY`, `LIMIT`, `AS`, pipes, `FOREACH`, the aggregations, and `RGX_EXTRACT`.

A correlation rule's sequence holds a filter ([exabeam-1.0 platform](../platforms/exabeam-1.0.md)). A hunt search (`response.procedure.searches[]` with `system: exabeam`) may use both layers. This spec defines the language once, with one [profile](#profiles) for each use. It is the contract for the analysis engine (language-server), which reports the [diagnostics](#diagnostics) in `opentide validate` and in editors, and for the [highlighting](#highlighting) editors show.

Exabeam publishes no grammar and no reference parser. The contract is Exabeam's Search guide and the correlation-rule API reference as fetched on 2026-11-11, checked against Exabeam's own published rules. Where the guides contradict each other, this spec picks one reading and says so. Research, sources, and the contradictions are in [RFC 0017](../../rfcs/0017-exabeam-platform.md).

## Requirements

- A query MUST be checked under exactly one profile: `rule` for a correlation-rule sequence `query`, `search` for a hunt search and a `.exabeam` file (unless the host names another).
- Static validation MUST report every [error](#errors) as a failure and every [warning](#warnings) without failing the rule ([validation](../validation.md#language-diagnostics)).
- Under the `rule` profile, the advanced operators MUST be refused with `exabeam_advanced_in_rule`. Every published correlation rule uses a filter only, and Exabeam disables "Convert to Rule" for a search that uses them.
- An implementation MUST NOT report an unknown field, context table, or column as an error. Fields come from the tenant's parsers and custom fields, and context tables exist only in the tenant. An unknown field is the warning `exabeam_unknown_field`.
- Deploy MUST send a query as written: the engine never rewrites one. It MAY trim leading and trailing whitespace.
- The engine MUST NOT claim that a query matches events or that a context table exists. That is a tenant check ([exabeam-1.0](../platforms/exabeam-1.0.md#query-validation)).

## Definition

### Profiles

| Profile | Used for | Layers |
|---------|----------|--------|
| `rule` | `configurations.exabeam.sequences[].query` | filter |
| `search` | `response.procedure.searches[].query` with `system: exabeam`; `.exabeam` files; `opentide query --platform exabeam` | filter and advanced operators |

A query is in the **advanced form** when it starts with `SELECT`, `WHERE`, `FROM`, or `FOREACH`, or has a `|`, a `GROUP-BY`, an `ORDER-BY`, or a trailing `LIMIT <n>` outside strings and brackets. Every other query is a filter.

### Lexical structure

| Element | Rule |
|---------|------|
| Whitespace | Spaces, tabs, and line breaks separate terms and are otherwise ignored. A query may span lines. |
| Comments | None. Exabeam documents no comment syntax: `//` and `#` are text. |
| Field name | `[A-Za-z_][A-Za-z0-9_]*`, with `.` between parts for structured fields (`geo_src_ip.country`). Custom fields start `c_`, metadata fields `m_`. Field names are compared case-insensitively by the engine; Exabeam writes them in lower case. |
| String | Double-quoted (`"…"`). A single-quoted string (`'…'`) is a free-text phrase. A backslash escapes `"`, `'`, `` ` ``, and `\`; any other backslash sequence stays as written, so a regular expression keeps its own escapes (`"\d+"`). |
| Exact keyword | Backticks inside a string: ``"`web application`"`` matches the phrase case-sensitively. |
| Number | `[+-]?digits[.digits]`, unquoted. A value Exabeam stores as a string (`event_code`) is quoted even when it is all digits. |
| Boolean | `true` and `false`, in any case. |
| Null | `null`, in any case. `field:null` matches a missing field. There is no `exists`. `NOT field:null` is the exists check. |
| IPv4 / IPv6 address | Unquoted (`10.0.0.1`). |
| Datetime | `YYYY-MM-DDThh:mm:ss[.sss][Z|±hh:mm]` (UTC when no zone), or epoch milliseconds, inside a range only |
| Filter operators | `AND`, `OR`, `NOT`, `TO`, `IN`, in any case. Exabeam recommends upper case. |
| Clause keywords | `SELECT`, `DISTINCT`, `FROM`, `WHERE`, `AS`, `GROUP-BY`, `ORDER-BY`, `ASC`, `DESC`, `LIMIT`, `FOREACH`. Each is written all upper case or all lower case. Mixed case is `exabeam_keyword_case`. `GROUP-BY` and `ORDER-BY` are one word. |
| Punctuation | `( ) [ ] { } , . |` and the comparison symbols `: = == < > <= >=` |

### Filter grammar

```ebnf
filter        = or_expr ;
or_expr       = and_expr , { "OR" , and_expr } ;
and_expr      = unary , { "AND" , unary } ;
unary         = "NOT" , unary | primary ;
primary       = "(" , or_expr , ")" | term ;
term          = field_term | context_term | call | free_text ;

field_term    = field , ( match_op , value | [ ":" | "=" ] , compare_op , number ) ;
match_op      = ":" | "=" | "==" ;
compare_op    = "<" | ">" | "<=" | ">=" ;
value         = string | scalar | list | range | cidr | call | "@" , field ;
scalar        = number | boolean | "null" | ip_address | bare_word ;
list          = "(" , list_item , { "," , list_item } , ")" ;
list_item     = string | scalar ;
range         = ( "[" | "{" ) , bound , "TO" , bound , ( "]" | "}" ) ;
bound         = "*" | number | ipv4_address | datetime | string ;
cidr          = "[" , ipv4_address , "/" , digit , [ digit ] , "]" ;
call          = filter_function , "(" , string , ")" ;
filter_function = "RGX" | "RGXi" | "WLD" | "WLDi" ;
context_term  = field , "IN" , string , [ "." , string ] ;
free_text     = string | bare_word ;
```

`AND` binds tighter than `OR`, as in Lucene and SQL. Exabeam does not document precedence, so mixing `AND` and `OR` at one level without parentheses is the warning `exabeam_mixed_boolean`.

Two terms side by side need an operator: `a NOT b` is invalid (`exabeam_implicit_operator`). Exabeam accepts it without an error, but its known-issues page calls it "invalid and not officially supported", with no defined meaning. Write `a AND NOT b` or `a OR NOT b`.

### Filter semantics

| Construct | Example | Meaning |
|-----------|---------|---------|
| Match | `vendor:"Exabeam"`, `vendor = "Exabeam"` | `:` and `=` are the same. A token match, case-insensitive. |
| Exact keyword | ``product:"`web application`"`` | Contains the phrase, case-sensitive |
| Exact full | `product=="web application"` | The whole value, case-sensitive |
| Wildcard in a value | `subject:"W*b"`, `subject:"W?b"` | `*` is any run of characters and `?` is one character. Not inside a phrase with spaces (`exabeam_wildcard_in_phrase`). |
| List | `user:("joe", "jane")` | Any of the values (an `OR`). One value in parentheses is `exabeam_single_value_list`, because the guides disagree on whether it is valid. |
| Comparison | `bytes_in > 1000`, `bytes_in: >1000` | Numeric |
| Range | `count:[1 TO 5]`, `count:{1 TO 5}`, `count:[1 TO *]` | `[ ]` inclusive, `{ }` exclusive, `*` open. Numbers, IPv4 addresses, or datetimes, low ≤ high. |
| CIDR | `src_ip:[10.0.0.0/8]` | IPv4 only |
| Null | `dest_port:null`, `NOT dest_port:null` | Missing, present |
| Regex | `url:RGX("^https?://")`, `RGXi(…)` | RE2 syntax, case-sensitive and case-insensitive |
| Wildcard function | `file_name:WLDi("*resume*")`, `WLD(…)` | `*`/`?` pattern, case-sensitive and case-insensitive |
| Context table | `user IN "Privileged Accounts"`, `src_ip IN "Admin Users"."IP Address"` | Case-insensitive exact match against a table (and a column). At most two per query, joined by `AND` or `AND NOT` only. |
| Free text | `"Admin login"`, `web` | Matches anywhere in the event. A bare word holds letters, digits, `_`, `-`, `*`, and `?` only. |

There is no `!=`, no `contains()`, `startswith()`, `endswith()`, `cidr()`, or `exists()`. The engine names the Exabeam form in the diagnostic: `NOT f:v` for `!=`, `WLD("*x*")` for contains, `RGX("^x")` for startswith, `RGX("x$")` for endswith, `[a.b.c.d/n]` for CIDR, and `NOT f:null` for exists.

Time fields (`time`, `approxLogTime`, `ingest_time`, `raw_log_time`) take a range only. Exabeam's Search has no exact match on time (`exabeam_time_exact`).

### Advanced grammar (`search` profile)

```ebnf
advanced      = statement , { "|" , statement } ;                 (* at most 5 pipes *)
statement     = foreach | clauses ;
foreach       = "FOREACH" , field , "[" , clauses , "]" ;
clauses       = [ select ] , [ from ] , [ where ] , [ "AS" , name ] ,
                [ group_by ] , [ order_by ] , [ limit ] ;          (* this order *)
select        = "SELECT" , [ "DISTINCT" ] , column , { "," , column } ;
column        = ( "*" | field | aggregate | extract ) , [ "AS" , name ] ;
aggregate     = ( "COUNT" | "MIN" | "MAX" | "SUM" | "AVG" ) , "(" , ( field | "*" ) , ")" ;   (* "*" for COUNT only *)
extract       = "RGX_EXTRACT" , "(" , [ field , "," ] , string , ")" ;                    (* at most 3 per query *)
from          = "FROM" , name ;
where         = [ "WHERE" ] , filter ;                              (* a bare filter is an implicit WHERE *)
group_by      = "GROUP-BY" , field , { "," , field } ;
order_by      = "ORDER-BY" , field , [ "ASC" | "DESC" ] , { "," , field , [ "ASC" | "DESC" ] } ;
limit         = "LIMIT" , positive_integer ;
```

Inside a `FOREACH` sub-query, `@field` is the current value of the iterated field. A `FOREACH` sub-query has no `GROUP-BY` or `ORDER-BY`. With `GROUP-BY`, `SELECT *` is not allowed, and every selected column that is not an aggregation is grouped. An `AS` name is not one of Exabeam's [reserved words](#reserved-words).

### Field catalogue

Field names come from Exabeam's Common Information Model: `Fields_Descriptions.md` and `cim.json` in [ExabeamLabs/CIMLibrary](https://github.com/ExabeamLabs/CIMLibrary). Those hold 1,130 typed fields, 84 subjects, 456 activity types, and the outcomes `success` and `fail`. The language server generates `catalogs/exabeam/` from them with a sync script, pinned by commit, as it generates the Falco and GravityZone catalogues. Platform fields that the CIM table omits (`approxLogTime`, `rawLogIds`, `ingest_time`, `raw_log_time`, `m_*`) are part of the catalogue.

The catalogue drives four things: hover and completion for fields, `activity_type`, `subject`, and `outcome` values; `exabeam_unknown_field`; `exabeam_string_field_number`; and the time-field rule. No catalogue finding is an error.

### Highlighting

Captures are from the language server's frozen HighlightSpec ([`highlights/spec.toml`](https://github.com/opentidehq/language-server/blob/main/highlights/spec.toml), legend 0.3.0). This language adds no capture.

| Token | Capture |
|-------|---------|
| `AND`, `OR`, `NOT`, `TO`, `IN`, and every clause keyword | `keyword` |
| `:`, `=`, `==`, `<`, `>`, `<=`, `>=`, `*` in `SELECT *` and `COUNT(*)` | `operator` |
| `|` between statements | `operator.pipe` |
| `RGX`, `RGXi`, `WLD`, `WLDi`, `COUNT`, `MIN`, `MAX`, `SUM`, `AVG`, `RGX_EXTRACT` | `function.builtin` |
| A field name (left of an operator, in `SELECT`, `GROUP-BY`, `ORDER-BY`, `FOREACH`, an aggregation, or `RGX_EXTRACT`) | `property` |
| A context table name and column after `IN`; a `FROM` or statement `AS` name | `type` |
| `@field` in a `FOREACH` sub-query; a column `AS` alias | `variable` |
| A string, a free-text word, and an unquoted string value | `string` |
| A number, and a numeric range bound | `number` |
| `true`, `false` | `boolean` |
| `null`, an IP address, a CIDR block, a datetime, `*` as a range bound | `constant` |
| `( ) [ ] { }` | `punctuation.bracket` |
| `,` and the `.` between a context table and its column | `punctuation.delimiter` |
| `!=`, an unknown function name, an argument that is not a string, a bare `*` | `error` |

Tide YAML injects the language at `configurations.exabeam.sequences[].query` (profile `rule`) and at `response.procedure.searches[].query` when `system` is `exabeam` (profile `search`). Highlight goldens: [fixtures/languages/exabeam/highlight/](../../fixtures/languages/exabeam/highlight/).

### Diagnostics

Codes are stable, and the engine reports each with a range. Every code that needs no catalogue has a conformance query that triggers it, `fixtures/languages/exabeam/invalid/<code>.<profile>.exabeam`.

#### Errors

| Code | Condition |
|------|-----------|
| `exabeam_parse_error` | Syntax error: an unterminated string, an unbalanced bracket, a missing operand, an empty query, a comparison with a non-number |
| `exabeam_implicit_operator` | Two terms with no `AND` or `OR` between them, including `a NOT b` |
| `exabeam_not_equal` | `!=` in a filter |
| `exabeam_single_group` | Parentheses around one expression (`(a) AND b`), which Exabeam refuses |
| `exabeam_bare_wildcard` | `*` alone as a term |
| `exabeam_leading_slash` | A query that starts with `/` |
| `exabeam_free_text_special` | Unquoted free text with a character other than letters, digits, `_`, `-`, `*`, `?` (`10.228.200.3`, `a.b`) |
| `exabeam_unknown_function` | A call that is not `RGX`, `RGXi`, `WLD`, `WLDi` in a filter, or not an aggregation or `RGX_EXTRACT` in `SELECT`. The message gives the Exabeam form for `contains`, `startswith`, `endswith`, `cidr`, `exists` |
| `exabeam_function_arity` | A filter function without exactly one string argument; an aggregation without one field (`*` for `COUNT` only); `RGX_EXTRACT` without `[field,] "pattern"` |
| `exabeam_regex` | A pattern RE2 refuses: a syntax error, a back-reference, look-around, an atomic group, a possessive quantifier |
| `exabeam_range` | A range bound that is not a number, an IPv4 address, a datetime, or `*`; mixed kinds; low > high; both bounds `*`; mismatched brackets; an invalid CIDR block |
| `exabeam_ipv6_range` | An IPv6 range or CIDR block. Exabeam ranges are IPv4 only |
| `exabeam_time_exact` | A time field (`time`, `approxLogTime`, `ingest_time`, `raw_log_time`) with an exact value instead of a range |
| `exabeam_context_table_or` | A context table lookup under `OR` |
| `exabeam_context_table_limit` | More than two context table lookups in one query |
| `exabeam_advanced_in_rule` | The advanced form under the `rule` profile |
| `exabeam_keyword_case` | A clause keyword (or `RGX_EXTRACT`) in mixed case (`Select`) |
| `exabeam_clause_order` | Clauses out of order, or a clause twice in one statement |
| `exabeam_pipe_limit` | More than five pipes |
| `exabeam_rgx_extract_limit` | More than three `RGX_EXTRACT` in one query |
| `exabeam_reserved_alias` | An `AS` name that is a reserved word |
| `exabeam_group_by_select_star` | `GROUP-BY` with `SELECT *` |
| `exabeam_group_by_column` | A selected column that is neither grouped nor aggregated |
| `exabeam_foreach_clause` | `GROUP-BY` or `ORDER-BY` inside a `FOREACH` sub-query |
| `exabeam_foreach_reference` | `@field` outside a `FOREACH` sub-query |

#### Warnings

| Code | Condition |
|------|-----------|
| `exabeam_mixed_boolean` | `AND` and `OR` at one level without parentheses |
| `exabeam_wildcard_in_phrase` | `*` or `?` in a quoted value that holds a space. Exabeam does not expand wildcards in phrases |
| `exabeam_single_value_list` | A list with one value |
| `exabeam_unquoted_value` | A field value that is a bare word but not a number, boolean, `null`, IP address, or `@field`. Exabeam documents string values in double quotes |
| `exabeam_legacy_regex` | A `"/…/"` value, the Data Lake regex form. Write `RGX("…")` |
| `exabeam_unknown_field` | A field the [catalogue](#field-catalogue) does not have, unless it starts `c_` or `m_` |
| `exabeam_string_field_number` | An unquoted number on a field the catalogue types as a string (`event_code:4625`). Exabeam requires `"4625"` |

#### Reserved words

From the Search guide; none may be an `AS` name: `abort all and any array as asc assert_rows_modified at between by case cast collate contains create cross cube current default define desc distinct else end enum escape except exclude exists extract false fetch following for from full group grouping groups hash having if ignore in inner intersect interval into is join lateral left like limit lookup merge natural new no not null nulls of offset on or order outer over partition preceding proto range recursive respect right rollup rows select set some struct tablesample then to treat true unbounded union unnest using when where window with within`.

### Limits

| Limit | Value | Code |
|-------|-------|------|
| Context table lookups per query | 2 | `exabeam_context_table_limit` |
| Pipes | 5 (six statements) | `exabeam_pipe_limit` |
| `RGX_EXTRACT` per query | 3 | `exabeam_rgx_extract_limit` |
| Query length | none documented | — |

Tenant limits are not language checks: a piped query's 7-day range and 1,000-a-month quota, the 100,000-value `FOREACH` limit, the 100,000-row context table, and the licence's search time range.

## Relationships

- [exabeam-1.0 platform](../platforms/exabeam-1.0.md): correlation-rule sequences use the `rule` profile
- [rule-1.0](../objects/rule-1.0.md) and [rule-1.1](../objects/rule-1.1.md): `searches[]` with `system: exabeam` use the `search` profile
- [validation](../validation.md#language-diagnostics): how language errors and warnings are reported
- [elastic-1.0](../platforms/elastic-1.0.md): `eql` there is Elastic EQL, a different language
- [RFC 0017](../../rfcs/0017-exabeam-platform.md): research, sources, and the readings this spec chose

## Defaults & overrides

| Setting | Default | Override |
|---------|---------|----------|
| Profile of a `.exabeam` file | `search` | The host may pass `rule` |
| Profile of a sequence query | `rule` | none |
| Unknown field | warning | none |

## Examples

A correlation-rule sequence (profile `rule`):

```text
activity_type:"process-create"
AND parent_process_name:("winword.exe", "excel.exe", "powerpnt.exe")
AND process_name:("powershell.exe", "pwsh.exe")
AND process_command_line:RGXi("\\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\\s")
```

Context tables, CIDR, and null (profile `rule`):

```text
activity_type:"app-login" AND outcome:"fail"
AND NOT src_ip:[10.0.0.0/8] AND NOT src_ip:[172.16.0.0/12] AND NOT src_ip:[192.168.0.0/16]
AND NOT src_ip:(0.0.0.0, 127.0.0.1, null)
```

A hunt (profile `search`):

```text
activity_type:"app-login" AND outcome:"success" AND user IN "Privileged Accounts"
| FOREACH dest_host [ SELECT src_host WHERE src_host: @dest_host AND activity_type:"network-connection" ]
| SELECT src_host, COUNT(src_host) AS connections GROUP-BY src_host
```

| What | Diagnostic |
|------|------------|
| `user != "SYSTEM"` | `exabeam_not_equal`: write `NOT user:"SYSTEM"` |
| `subject:"app" NOT vendor:"Exabeam"` | `exabeam_implicit_operator`: write `AND NOT` |
| `process_command_line: contains("-enc")` | `exabeam_unknown_function`: write `WLD("*-enc*")` |
| `src_ip:[fd00::/8]` | `exabeam_ipv6_range` |
| `user IN "Executives" OR src_ip IN "Admins"` | `exabeam_context_table_or` (twice) |
| `SELECT user, COUNT(*) AS logins …` in a rule | `exabeam_advanced_in_rule` |

Fixtures: [fixtures/languages/exabeam/valid/](../../fixtures/languages/exabeam/valid/) (each clean under its profile), [invalid/](../../fixtures/languages/exabeam/invalid/) (one per code the reference checker can prove; `exabeam_unknown_field` and `exabeam_string_field_number` need the catalogue), and [highlight/](../../fixtures/languages/exabeam/highlight/) (token goldens). `scripts/exabeam_language.py` is the reference checker the conformance tests run. It is tooling, not opentide's engine.

## History

| Version | Date | Notes |
|---------|------|-------|
| 1.0 | 2026-11-11 | Draft ([RFC 0017](../../rfcs/0017-exabeam-platform.md)): language id `exabeam`, the filter and advanced grammars, `rule` and `search` profiles, CIM field catalogue, highlighting on the existing HighlightSpec, stable `exabeam_*` diagnostics. |
