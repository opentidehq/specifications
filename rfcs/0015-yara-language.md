# RFC 0015: One YARA language across detection platforms

- **RFC:** 0015
- **Title:** One YARA language across detection platforms
- **Author:** opentide maintainers
- **Status:** accepted
- **Created:** 2026-11-09
- **Accepted:** 2026-11-10, with the normative text in [specs/languages/yara-1.0.md](../specs/languages/yara-1.0.md) and [specs/platforms/harfanglab-1.0.md](../specs/platforms/harfanglab-1.0.md) 1.2
- **Issue:** answers the YARA half of [opentidehq/specifications#68](https://github.com/opentidehq/specifications/issues/68). The Sigma half of #68 stays open.
- **Related:** [RFC 0016](0016-bitdefender-gravityzone-platform.md), the Bitdefender GravityZone platform, which carries the second YARA block
- **Implementation:** [opentidehq/language-server#165](https://github.com/opentidehq/language-server/issues/165) (YARA engine), widened to whole YARA signatures; the HarfangLab `signature` form and `harfanglab_rule_kind` in opentidehq/opentide

## Summary

YARA becomes a language spec of its own, `specs/languages/yara-1.0.md`. Every platform that deploys YARA embeds it in the same way, so YARA is written and checked once for all of them. The spec defines:

- **`YaraSignature`**, the one shared object. Its field `signature` is a whole YARA text: imports, then one or more YARA rules. It is written out literally in the platform block and deployed verbatim.
- **The dialect**: YARA as libyara 4.5 compiles it, with YARA-X 1.x as a second opinion that reports warnings.
- **Diagnostics**: stable `yara_*` codes, which the analysis engine reports in `opentide validate` and in editors.
- **Platform profiles**: per-platform limits (characters, size, modules, recommended meta).

HarfangLab's existing `yara` block gains the `signature` form, beside its decomposed `strings` and `condition` fields. A HarfangLab block becomes one kind: a Sigma rule or a YARA file, never both. **HarfangLab's deployer is not reworked**: its identity, payload, and status handling stay as specified in harfanglab-1.0. The new form only changes where `content` comes from.

Bitdefender GravityZone carries the second YARA block ([RFC 0016](0016-bitdefender-gravityzone-platform.md)).

The analysis engine (language-server) gains a YARA language: diagnostics, highlighting, hover, completion, go-to-definition, rename, and formatting, for whole signatures and for HarfangLab's decomposed fragments.

## Motivation

- **Two EDRs run YARA, and opentide has no spec for it.** HarfangLab's block decomposes one rule into `strings` and `condition` fields. It cannot express several rules, private or global helper rules, rule tags, or a condition-only rule (`pe.imphash() == "…"`). Nothing compiles the text before it reaches the tenant ([specifications#68](https://github.com/opentidehq/specifications/issues/68), [language-server#165](https://github.com/opentidehq/language-server/issues/165)). A Bitdefender block with its own YARA field would create a second, different contract.
- **One contract for every EDR.** A detection engineer who writes YARA for a malware family wants it on every EDR that runs YARA. With one shape and one language spec, YARA is written and checked the same way everywhere. Each platform block still carries its own text, so a block never deploys text written somewhere else.
- **Offline checking.** Neither vendor has a YARA dry run. An offline engine is the only check before deploy, as Falco's is for Sysdig ([RFC 0014](0014-sysdig-falco-platform.md)).

## Research

### HarfangLab YARA

HarfangLab publishes no public API reference. These facts come from third-party clients that call the API: OpenCTI's HarfangLab connectors, [demisto/content `HarfangLabEDR`](https://github.com/demisto/content/tree/master/Packs/HarfangLabEDR), and SEKOIA's and Netskope's integrations. They also come from HarfangLab's own published rules, [HarfangLab/iocs](https://github.com/HarfangLab/iocs).

| Finding | Status |
|---------|--------|
| A **YaraFile** is a whole YARA text (`content`) that may hold several rules (`rule_names` is a list; HarfangLab's own `hl_public_reports_master.yar` holds 39). Each file compiles as one YARA namespace. | confirmed |
| No HarfangLab document defines YARA meta. HarfangLab's own rules (HarfangLab/iocs at `3e2b674`) set `context` on every rule, 79 times: `"file"` 67, `"memory"` 6, `"file,memory"` 6. They never set `os`, `arch`, `score`, or `id`. | confirmed (vendor usage, not vendor docs) |
| The existing deployer rewrites `file` to `file.pe`, `file.elf`, or `file.macho` by `os`. These values come from CoreTide commit `e1fae48` (2025-12-18), which cites no source. | confirmed (provenance) |
| The engine and its modules are not published. | — |

The HarfangLab deployer's own behaviour (identity by `metadata.uuid`, `DISABLEMENT` on YARA, reading the YaraFile response) is out of scope. Under this RFC, the existing deployer takes precedence.

### Bitdefender YARA

GravityZone's YARA detection rules take a whole YARA text (`settings.yaraQuery`): one or more rules, ASCII only, at most 30,000 characters, and no `include` ([YARA detection rules](https://www.bitdefender.com/business/support/en/77209-1118491-yara-detection-rules.html)). Its endpoint agent ships **libyara**. The BEST open-source notices for [Windows](https://www.bitdefender.com/business/support/en/77209-521335-open-source-software-used-by-best-for-windows.html) and [Linux](https://www.bitdefender.com/business/support/en/77209-521336-open-source-software-used-by-best-for-linux.html) list YARA (BSD-3-Clause), linked to libyara's documentation, and neither mentions YARA-X. The libyara version is not published, and no page lists or excludes modules.

### YARA engines

- **libyara 4.5** (VirusTotal YARA, C; Python `yara-python`). Every EDR that shipped YARA before 2025 embeds it: HarfangLab (YARA since 2020) and Bitdefender (YARA GA November 2024).
- **YARA-X 1.x** (Rust). It is stricter than libyara in documented places ([*Differences with YARA*](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)): regexp escapes, `@a[-1]`, `base64` lengths, `entrypoint`, and repeated rule modifiers. It also adds syntax libyara refuses (`.len()`, hex and octal jump bounds, booleans in `of` tuples).

The contract is therefore **libyara 4.5**. Bitdefender's agent ships it, and HarfangLab most plausibly runs it. YARA-X is a second opinion whose disagreements are warnings.

## Detailed design

### 1. Spec layout

| Path | Change |
|------|--------|
| `specs/languages/yara-1.0.md` | **New.** `spec: language-yara`, version `1.0`, no `schema_id`. |
| `specs/platforms/harfanglab-1.0.md` | 1.1 → **1.2**. `yara.signature`; one kind per block; constraint codes; offline YARA check. `schema_id` unchanged. |
| `specs/platforms/index.md` | 1.4 → **1.5**. HarfangLab capability row and static-validation bar. |
| `specs/validation.md` | 1.5 → **1.6**. Language diagnostics and advisories; checker codes. |
| `SPECS.md`, `CHANGELOG.md`, `rfcs/README.md`, `llms.txt` | Index rows |

YARA is a language spec, not a section inside one platform spec as Falco is in [sysdig-1.0](../specs/platforms/sysdig-1.0.md#falco-language), because several platforms carry it.

### 2. `YaraSignature`

A platform's `yara` block embeds one field:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature` | string | yes | The YARA signature, as a `.yar` file holds it: `import` statements, then one or more YARA rules. It may include `private` and `global` rules, rule tags, and comments. |

- **Verbatim.** Deploy sends `signature` unchanged, apart from line endings normalised to `\n` and a trailing newline. It adds, removes, and reorders nothing.
- **Literal.** `signature` is written out in the block. A YAML alias (`signature: *name`) fails with `yara_signature_alias`. One opentide rule may carry a `yara` block for several platforms; each writes its own `signature`.
- At least one rule is neither `private` nor `global`. No `include`. Rule names are unique within `signature`.

The key is `signature`. A YARA text is the signature an EDR scans files and memory with, which is the term detection engineers use, and HarfangLab's name for its YARA *signatures engine*. One `signature` may hold several YARA rules, as one `.yar` file does. Rejected names:

- `source`: collides with HarfangLab's *YaraSource* (the tenant's `source_id`) and with Sysdig's `source`.
- `rules`: collides with the opentide rule, and with the planned rename of `configurations` to `rule`.
- `query`: YARA is not a query language.
- `content`: generic, and opentide already says "detection content" for whole rules.

### 3. Dialect and diagnostics

- **Errors** are what libyara 4.5 refuses to compile.
- **Warnings** cover two cases:
  - what only YARA-X refuses (`yara_x_incompatible`);
  - libyara's own compile warnings.
- **YARA-X-only syntax** is an error, because libyara refuses it.
- **A `dialect` per profile** (`libyara4` today) lets a later revision move one platform to YARA-X.

A rule with no `strings:` section is valid YARA. This answers #68 question 3 for the language. HarfangLab's decomposed form still requires `strings`, because its deployer always writes the header. A condition-only rule uses the `signature` form.

The engine knows 13 modules: `pe`, `elf`, `math`, `hash`, `time`, `dotnet`, `macho`, `magic`, `cuckoo`, `console`, `string`, `lnk`, `dex`. Each profile names its confirmed set; importing another known module is a warning. Neither vendor publishes a module list, so by maintainer decision (2026-11-10) both profiles confirm `pe`, `elf`, `math`, `hash`, `time` (answers #68 question 2).

The error and warning codes are the tables of [yara-1.0](../specs/languages/yara-1.0.md#diagnostics).

### 4. Profiles

| | `bitdefender` | `harfanglab` |
|---|---|---|
| Dialect | `libyara4` | `libyara4` |
| Characters | ASCII only | UTF-8 |
| Size | ≤ 30,000 characters | no documented limit |
| Confirmed modules | `pe`, `elf`, `math`, `hash`, `time` | `pe`, `elf`, `math`, `hash`, `time` |
| Recommended meta | none | `context` on every non-private rule |

HarfangLab `context` values: `file`, `memory`, or `file,memory` (HarfangLab's published rules), and `file.pe`, `file.elf`, `file.macho` (what the existing deployer writes). Any other value is the `harfanglab_yara_context` warning.

### 5. HarfangLab (`harfanglab-1.0.md` 1.2)

| Change | Text |
|--------|------|
| `yara.signature` | `HarfangLabYara` takes **either** `signature` or the decomposed `meta`/`strings`/`condition`/`imports`. With `signature`, deploy sends it as the YaraFile `content`, verbatim. Every other part of the deploy is unchanged: the same endpoint, payload fields, name, identity, and status handling. |
| One kind per block | `sigma` and `yara` together fail `harfanglab_rule_kind`. The requirement "when both are present, deploy MUST publish `sigma`" is removed, because both can no longer be present. A block with neither still validates and still fails at deploy. |
| Constraint codes | `harfanglab_rule_kind`; `harfanglab_yara_form` (`signature` with any decomposed key); `harfanglab_yara_section_header` (a `strings:`, `condition:`, or `rule` header inside a fragment); `harfanglab_yara_import` (an `imports` entry that is not a module); `harfanglab_yara_rule_name` (the YARA rule name deploy derives from the rule `name` is a YARA keyword or keeps a non-ASCII letter). |
| Offline check | `opentide validate` and editors check `yara.signature`, and the decomposed fragments assembled the way deploy assembles them, under the HarfangLab profile. `validate query` stays `supported: false`. |

An existing block with both `sigma` and `yara` now fails validation, and its author splits it into two rules. Today only its Sigma half ever deploys, so keeping `sigma` in the original rule leaves every tenant unchanged.

### 6. Analysis engine (language-server)

This widens [language-server#165](https://github.com/opentidehq/language-server/issues/165) from decomposed HarfangLab fragments to whole signatures, and follows the Falco addition (RFC 0014 §6).

**Parsers.**

- **Verdict parser: VirusTotal's `yara-x-parser`** (BSD-3-Clause). It is pure Rust (logos + rowan), keeps a lossless CST with byte spans, and recovers after errors.
- **Tree-sitter grammar** (`grammars/tree-sitter-opentide-yara`), for highlighting and the corpus gate. An agreement test runs it against the verdict parser.
- **The full `yara-x` compiler is an oracle only.** It brings wasmtime, breaks the WASI build, reports one error per compile, and would make YARA-X the contract.

| Work package | Content |
|--------------|---------|
| Toolchain | Rust 1.85 → 1.95 (`yara-x-*` crates); build on native, `wasm32-unknown-unknown`, and `wasm32-wasip1`; cargo-about |
| Plumbing | `LanguageId::Yara` (`yara`, `.yar`, `.yara`), the `yara_*` and `harfanglab_*` codes, the `match` sites, fuzz target |
| Grammar | tree-sitter grammar, corpus, `highlights.scm`, tmLanguage, agreement test |
| Engine | `crates/opentide-yara` (I/O-free): CST → symbol table → a semantic pass for every code, under `Dialect { Libyara4, YaraX }`, with profiles |
| Module catalogue | `catalogs/yara/modules.toml` generated from YARA-X's module reflection, marked per dialect from libyara's module sources; `language.toml`; BSD-3 `NOTICE` |
| Injection | `configurations.<platform>.yara.signature` for `bitdefender` and `harfanglab`; a two-scalar injection for decomposed HarfangLab `strings` + `condition` with `imports` (one synthetic rule, offsets mapped back); the profile chosen by the path |
| Editor features | Hover, completion, signature help, symbols, folding, go-to-definition and references for strings and rules, rename of string ids (also across the two scalars of a decomposed block), formatting of `.yar` files with `yara-x-fmt` |
| Conformance | Vendored YARA-X suites (about 880 cases) and libyara's `test-rules.c`; an external corpus with `.broken.` twins (ReversingLabs and InQuest, MIT; a signature-base subset, DRL-1.1; GPL and ELv2 sets fetched in CI only) |
| Oracle | `scripts/oracles/yara/oracle.py`: `yara-python` 4.5.4 and the `yara-x` wheel, a verdict per dialect, an exact ledger. Neither ships. |
| Docs | `docs/YARA.md`: each code mapped to the libyara source and its test |

opentide then:

- bumps the engine pin (with Rust 1.95);
- sets `OFFLINE_QUERY_LANGUAGES["harfanglab"] = ("yara",)`, and `bitdefender` with RFC 0016;
- adds `.yar` and `.yara` to `QUERY_FILE_SUFFIXES`;
- lets the YARA advisories through `lint` and `explain`;
- implements the `signature` branch of the HarfangLab YARA compiler and `harfanglab_rule_kind`.

### 7. Engineering plan

| # | Work package | Repo | Person-days |
|---|--------------|------|-------------|
| L0 | Toolchain spike | language-server | 2 |
| L1 | Plumbing | language-server | 2 |
| L2 | Tree-sitter grammar | language-server | 5–7 |
| L3 | `opentide-yara` engine | language-server | 15–20 |
| L4 | Module catalogue | language-server | 4–5 |
| L5 | Editor features | language-server | 8–10 |
| L6 | Tide injection and `harfanglab_*` codes | language-server | 5–7 |
| L7 | Conformance and oracle | language-server | 9–12 |
| L9 | Packaging, docs, release | language-server | 4–5 |
| H1 | HarfangLab `signature` branch, `harfanglab_rule_kind`, the other codes in the model; tests | opentide | 2–3 |
| E1 | Engine bump and YARA wiring in `validate`, `lint`, `explain`, MCP | opentide | 1–2 |

The critical path is L0 → L1 → L3 → L7 → L9 → E1, about 7–9 weeks. H1 ships first, independently.

## Drawbacks

- Engine versions and module lists are not public. A rule that uses a feature newer than the agent's libyara, or a module the agent lacks, fails at deploy instead of at validation.
- The engine follows YARA-X's release train. The `yara-x-*` crates need Rust 1.95 today, and the minimum moves about every two months. The two parsers can disagree, so the agreement test has to keep them aligned.
- A rule that targets two YARA platforms writes its signature twice.

## Alternatives

- **YARA at the rule root**, shared by every platform. Rejected: it hides what each platform deploys, and it needs `rule::1.2` while [RFC 0012](0012-rule-document-shape.md) rethinks the rule shape. `YaraSignature` moves there unchanged if that redesign wants it.
- **YAML anchors to share one text between blocks.** Rejected: someone reading the second block would not see the YARA it deploys.
- **Deploy-time meta injection** (`id`, `score`, `context`). Rejected: it needs a YARA rewriter in the deploy path and breaks "what was reviewed is what is deployed".
- **Reworking the HarfangLab YARA deployer** (YaraFile ids in deployment state, `PATCH` updates, `DISABLEMENT`, reading the response status). Out of scope: the existing deployer takes precedence. The findings are recorded in [Research](#harfanglab-yara) for a separate proposal.
- **The full YARA-X compiler in-process.** Rejected, as above. A later opt-in feature for native and Python builds stays possible.
- **The third-party `tree-sitter-yara`.** Rejected: its licence headers disagree, and its hex support is incomplete.

## Unresolved questions

- Whether to version the per-platform module sets in the language spec or in the platform specs.
- When a vendor names its engine, whether the profile's `dialect` moves.

## References

- [opentidehq/specifications#68](https://github.com/opentidehq/specifications/issues/68); [opentidehq/language-server#165](https://github.com/opentidehq/language-server/issues/165); [RFC 0014](0014-sysdig-falco-platform.md); [RFC 0016](0016-bitdefender-gravityzone-platform.md)
- [libyara 4.5](https://github.com/VirusTotal/yara); [YARA-X](https://github.com/VirusTotal/yara-x) and [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)
- [HarfangLab/iocs](https://github.com/HarfangLab/iocs); OpenCTI HarfangLab connectors; [YARA signatures engine](https://harfanglab.io/edr/signatures-engine-yara/)
- Bitdefender: [YARA detection rules](https://www.bitdefender.com/business/support/en/77209-1118491-yara-detection-rules.html); BEST open-source notices ([Windows](https://www.bitdefender.com/business/support/en/77209-521335-open-source-software-used-by-best-for-windows.html), [Linux](https://www.bitdefender.com/business/support/en/77209-521336-open-source-software-used-by-best-for-linux.html))
