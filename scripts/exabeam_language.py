#!/usr/bin/env python3
r"""Reference checker for specs/languages/exabeam-1.0.md (the Exabeam Query Language).

This is conformance tooling, as object_fixtures.py is: it proves that the grammar in the
spec is coherent, that every example in the spec parses, that every diagnostic code has a
fixture that triggers it, and that the highlight table yields the token classes the spec
lists. It is not opentide's engine. The analysis engine (language-server) implements the
spec in Rust with a tree-sitter grammar and the CIM field catalogue; this checker has no
catalogue, so it reports neither `exabeam_unknown_field` nor `exabeam_string_field_number`.

Regular expressions are checked against RE2 the way the spec describes: the pattern is the
string's value (`\\` and `\"` lose a backslash, other escapes stay). `_re2_check` walks it once, refuses
what RE2 refuses and Python accepts (back-references, look-around, atomic groups, possessive
quantifiers, `\Z`, an escaped non-ASCII character, comments, the `x` flag, repeat counts over 1000), rewrites what RE2 accepts
and Python spells differently (`\pL`, `\p{Greek}`, `\z`, `\x{263a}`, `\Q…\E`, `(?<name>…)`,
the `U` flag, a flag group after the start, a repeated assertion such as `$?`), and compiles the result with Python `re`. That
approximates RE2; the engine uses an RE2-syntax parser.

Usage: python scripts/exabeam_language.py [--profile rule|search] [--tokens] FILE
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path

PROFILES = ("rule", "search")

# Highlight captures this language uses. Every one is in the language server's frozen
# HighlightSpec legend (highlights/spec.toml, version 0.3.0); the spec adds none.
CAPTURES = (
    "keyword",
    "operator",
    "operator.pipe",
    "function.builtin",
    "type",
    "variable",
    "property",
    "string",
    "number",
    "boolean",
    "constant",
    "punctuation.bracket",
    "punctuation.delimiter",
    "error",
)

FILTER_FUNCTIONS = {"RGX": "regex", "RGXI": "regex", "WLD": "wildcard", "WLDI": "wildcard"}
AGGREGATES = {"COUNT", "MIN", "MAX", "SUM", "AVG"}
# Names written like a function that Exabeam does not have: Sigma and other SIEM habits.
KNOWN_FOREIGN = {"CONTAINS", "SW", "EW", "STARTSWITH", "ENDSWITH", "WC", "CIDR", "EXISTS", "IN", "LIKE", "MATCH", "REGEX"}
CLAUSE_WORDS = {"SELECT", "WHERE", "FROM", "FOREACH", "GROUP-BY", "ORDER-BY", "LIMIT", "AS", "DISTINCT", "ASC", "DESC"}
TIME_FIELDS = {"approxlogtime", "ingest_time", "time", "raw_log_time"}
# The Search guide's reserved words: none of them may be an `AS` alias.
RESERVED = set(
    """abort all and any array as asc assert_rows_modified at between by case cast collate contains create
    cross cube current default define desc distinct else end enum escape except exclude exists extract false
    fetch following for from full group grouping groups hash having if ignore in inner intersect interval into
    is join lateral left like limit lookup merge natural new no not null nulls of offset on or order outer over
    partition preceding proto range recursive respect right rollup rows select set some struct tablesample then
    to treat true unbounded union unnest using when where window with within""".split()
)
MAX_PIPES = 5
MAX_RGX_EXTRACT = 3
MAX_CONTEXT_TABLES = 2

ERRORS = {
    "exabeam_parse_error",
    "exabeam_implicit_operator",
    "exabeam_not_equal",
    "exabeam_bare_wildcard",
    "exabeam_leading_slash",
    "exabeam_free_text_special",
    "exabeam_unknown_function",
    "exabeam_function_arity",
    "exabeam_regex",
    "exabeam_range",
    "exabeam_ipv6_range",
    "exabeam_time_exact",
    "exabeam_context_table_or",
    "exabeam_context_table_limit",
    "exabeam_advanced_in_rule",
    "exabeam_keyword_case",
    "exabeam_clause_order",
    "exabeam_pipe_limit",
    "exabeam_rgx_extract_limit",
    "exabeam_reserved_alias",
    "exabeam_group_by_select_star",
    "exabeam_group_by_column",
    "exabeam_foreach_clause",
    "exabeam_foreach_reference",
    "exabeam_foreach_position",
}
WARNINGS = {
    "exabeam_mixed_boolean",
    "exabeam_implicit_and",
    "exabeam_pipe_misuse",
    "exabeam_wildcard_in_phrase",
    "exabeam_unquoted_value",
    "exabeam_legacy_regex",
    "exabeam_single_group",
    "exabeam_unknown_field",
    "exabeam_string_field_number",
}


@dataclass
class Diagnostic:
    code: str
    message: str
    start: int
    end: int

    @property
    def severity(self) -> str:
        return "warning" if self.code in WARNINGS else "error"


@dataclass
class Token:
    start: int
    end: int
    capture: str


@dataclass
class Result:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    advanced: bool = False
    #: (start, end) of each context table lookup, in source order.
    context_tables: list[tuple[int, int]] = field(default_factory=list)

    @property
    def codes(self) -> list[str]:
        return [d.code for d in self.diagnostics]

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == "error"]


class ParseError(Exception):
    def __init__(self, message: str, pos: int) -> None:
        super().__init__(message)
        self.pos = pos


IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
# A field name may hold `-` (Exabeam tokenizes `first-name` as one token; its content uses `c-uri`).
FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*")
HYPHEN_WORD = re.compile(r"(?i)(group|order)-by\b")
NUMBER = re.compile(r"[+-]?\d+(?:\.\d+)?\Z")
DATETIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})?\Z")
# A bare value runs to whitespace or a delimiter. `:` is allowed so a datetime range bound lexes whole.
BARE = re.compile(r"[^\s()\[\]{},\"'|=<>!]+")
FREE_TEXT_OK = re.compile(r"[A-Za-z0-9_*?]+\Z")
# Filter operators are never a bare word: a term where one stands is a missing operand.
OPERATOR_WORDS = {"AND", "OR", "NOT", "TO", "IN"}
EPOCH_MS = re.compile(r"\d{10,}\Z")
RE2_MAX_REPEAT = 1000
RE2_MAX_DEPTH = 1000
POSIX_CLASSES = {"alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "word", "xdigit"}
# `AS name` closing a statement: before the end, a pipe, GROUP-BY, ORDER-BY, or LIMIT.
STATEMENT_ALIAS = re.compile(r"(?i)as\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\||\Z|(?:group|order)-by\b|limit\b)")
RE2_FLAGS = set("imsU")


def _re2_check(pattern: str) -> str | None:
    """Why RE2 refuses `pattern` (the string body as written), or None."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    in_class = False
    depth = 0
    names: set[str] = set()
    while i < n:
        ch = pattern[i]
        if ch == "(" and not in_class and not pattern.startswith("(?", i) or (
            ch == "(" and not in_class and re.match(r"\(\?[A-Za-z-]*:", pattern[i:])
        ):
            depth += 1
            if depth > RE2_MAX_DEPTH:
                return f"nesting deeper than {RE2_MAX_DEPTH}"
        elif ch == ")" and not in_class:
            depth = max(depth - 1, 0)
        if ch == "\\":
            if i + 1 >= n:
                return "trailing backslash"
            nx = pattern[i + 1]
            if not nx.isascii():
                return f"\\{nx} is not an RE2 escape: only ASCII punctuation is escaped"
            if nx in "bBAz" and not in_class and pattern[i + 2 : i + 3] in ("*", "+", "?", "{"):
                out.append("(?:" + ("\\Z" if nx == "z" else pattern[i : i + 2]) + ")")  # RE2 repeats an assertion
                i += 2
                continue
            if nx.isdigit():
                # RE2: `\0` and `\1`-`\7` before another octal digit are octal (up to
                # three digits); any other digit escape is a back-reference.
                m = re.compile(r"\\(0[0-7]{0,2}|[1-7][0-7]{1,2})").match(pattern, i)
                if not m:
                    return "back-references are not RE2"
                out.append(f"\\u{int(m.group(1), 8):04x}")
                i = m.end()
                continue
            if nx == "Z":
                return "\\Z is not RE2: write \\z or $"
            if nx == "z" and not in_class:
                out.append("\\Z")
                i += 2
                continue
            if nx in "pP":
                m = re.compile(r"\\[pP](?:\{\^?[A-Za-z_]+\}|[A-Za-z])").match(pattern, i)
                if not m:
                    return "invalid Unicode class escape"
                out.append("a")
                i = m.end()
                continue
            if nx == "x" and pattern[i + 2 : i + 3] == "{":
                m = re.compile(r"\\x\{([0-9A-Fa-f]{1,8})\}").match(pattern, i)
                if not m or int(m.group(1), 16) > 0x10FFFF:
                    return "invalid \\x{…} escape"
                out.append(re.escape(chr(int(m.group(1), 16))))
                i = m.end()
                continue
            if nx == "Q":
                if in_class:
                    return "\\Q is not an escape inside a class"
                end = pattern.find("\\E", i + 2)
                literal = pattern[i + 2 :] if end < 0 else pattern[i + 2 : end]
                out.append(re.escape(literal))
                i = n if end < 0 else end + 2
                continue
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            elif ch == "[" and pattern.startswith("[:", i):
                m = re.compile(r"\[:\^?([a-z]+):\]").match(pattern, i)
                if m:  # an ASCII class such as [:alpha:]; Python reads it as a set
                    if m.group(1) not in POSIX_CLASSES:
                        return f"[:{m.group(1)}:] is not an RE2 character class"
                    out.append("a")
                    i = m.end()
                    continue
            out.append(ch)
            i += 1
            continue
        if ch == "[":
            in_class = True
            out.append(ch)
            i += 1
            if pattern[i : i + 1] == "^":
                out.append("^")
                i += 1
            if pattern[i : i + 1] == "]":  # a `]` right after `[` or `[^` is a literal
                out.append("\\]")
                i += 1
            continue
        if ch == "(" and pattern.startswith("(?", i):
            rest = pattern[i + 2 :]
            if rest[:1] in ("=", "!") or rest[:2] in ("<=", "<!"):
                return "look-around is not RE2"
            if rest[:1] == ">":
                return "atomic groups are not RE2"
            if rest[:2] == "P=" or rest[:2] == "P>":
                return "back-references are not RE2"
            if rest[:1] == "#":
                return "comments are not RE2"
            if rest[:1] == "<" or rest[:2] == "P<":
                start = i + (3 if rest[:1] == "<" else 4)
                close = pattern.find(">", start)
                name = pattern[start:close] if close >= 0 else ""
                if not re.fullmatch(r"[A-Za-z0-9_]+", name):
                    return f"invalid capture group name {name!r}"
                if name in names:
                    return f"duplicate capture group name {name!r}"
                names.add(name)
                out.append(f"(?P<n_{name}>")  # Python names start with a letter or `_`
                depth += 1
                if depth > RE2_MAX_DEPTH:
                    return f"nesting deeper than {RE2_MAX_DEPTH}"
                i = close + 1
                continue
            m = re.compile(r"\(\?([A-Za-z]*)(?:-([A-Za-z]*))?([:)])").match(pattern, i)
            if m:
                letters = set(m.group(1) + (m.group(2) or ""))
                if not letters <= RE2_FLAGS:
                    return f"flags {''.join(sorted(letters - RE2_FLAGS))} are not RE2 (RE2 has i, m, s, U)"
                on = "".join(c for c in m.group(1) if c != "U")
                off = "".join(c for c in (m.group(2) or "") if c != "U")
                if m.group(3) == ")":
                    i = m.end()  # a flag group sets flags from here on; validity is all that matters
                    continue
                out.append("(?" + on + ("-" + off if off else "") + ":" if on or off else "(?:")
                i = m.end()
                continue
        if ch == "{":
            m = re.compile(r"\{(\d+)(?:,(\d*))?\}").match(pattern, i)
            if m:
                counts = [int(g) for g in m.groups() if g]
                if any(c > RE2_MAX_REPEAT for c in counts):
                    return f"repeat counts above {RE2_MAX_REPEAT} are not RE2"
                if pattern[m.end() : m.end() + 1] == "+":
                    return "possessive quantifiers are not RE2"
                out.append(m.group(0))
                i = m.end()
                continue
        if ch in "*+?" and pattern[i + 1 : i + 2] == "+":
            return "possessive quantifiers are not RE2"
        if ch in "^$" and pattern[i + 1 : i + 2] in ("*", "+", "?", "{"):
            out.append(f"(?:{ch})")  # RE2 repeats an assertion; Python calls it nothing to repeat
            i += 1
            continue
        out.append(ch)
        i += 1
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            re.compile("".join(out))
    except re.error as exc:
        return str(exc)
    except RecursionError:
        return None  # deep but within RE2's nesting limit: Python's parser recurses, RE2's does not
    return None


def _unescape(body: str) -> str:
    """A query string's value: `\\"`, `\\'`, `` \\` `` and `\\\\` lose their backslash; other escapes stay."""
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in "\"'`\\":
            out.append(body[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


EPOCH_MS_CAP = 10**38  # the engine compares epoch milliseconds as 128-bit integers


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm)."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _instant(text: str) -> int:
    """A range bound on the time line, in epoch milliseconds; a datetime with no zone is UTC."""
    if EPOCH_MS.match(text):
        return min(int(text), EPOCH_MS_CAP)
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})?", text)
    assert m, text
    y, mo, d, hh, mi, ss = (int(g) for g in m.groups()[:6])
    millis = int((m.group(7) or "0").ljust(3, "0"))
    offset = 0
    if m.group(8) and m.group(8) != "Z":
        sign = -1 if m.group(8)[0] == "-" else 1
        offset = sign * (int(m.group(8)[1:3]) * 60 + int(m.group(8)[4:6]))
    return ((((_days_from_civil(y, mo, d) * 24 + hh) * 60 + mi - offset) * 60) + ss) * 1000 + millis


def _is_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


@dataclass
class Statement:
    """What one advanced statement selects and uses, for the pipe guardrail."""

    foreach: bool = False
    star: bool = False
    select: set[str] = field(default_factory=set)
    fields: set[str] = field(default_factory=set)


@dataclass
class Node:
    kind: str  # or | and | not | group | term | context
    children: list[Node] = field(default_factory=list)
    start: int = 0
    end: int = 0


class Parser:
    def __init__(self, text: str, profile: str) -> None:
        if profile not in PROFILES:
            raise ValueError(f"profile is one of {PROFILES}")
        self.text = text
        self.profile = profile
        self.pos = 0
        self.result = Result()
        self.context_tables: list[tuple[int, int]] = []
        self.rgx_extract = 0
        self.in_foreach = 0

    # -- low level -------------------------------------------------------------------------
    def diag(self, code: str, message: str, start: int, end: int) -> None:
        self.result.diagnostics.append(Diagnostic(code, message, start, max(end, start + 1)))

    def tok(self, start: int, end: int, capture: str) -> None:
        self.result.tokens.append(Token(start, end, capture))

    def ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos].isspace():
            self.pos += 1

    def peek(self, n: int = 1) -> str:
        self.ws()
        return self.text[self.pos : self.pos + n]

    def at_end(self) -> bool:
        self.ws()
        return self.pos >= len(self.text)

    def word_at(self) -> tuple[str, int, int] | None:
        """The identifier-like word at the cursor (GROUP-BY and ORDER-BY are one word)."""
        self.ws()
        m = HYPHEN_WORD.match(self.text, self.pos) or IDENT.match(self.text, self.pos)
        if not m:
            return None
        return m.group(0), m.start(), m.end()

    def column_at(self) -> tuple[str, int, int] | None:
        """A field name at the cursor, `-` included (`c-uri`); GROUP-BY and ORDER-BY stay keywords."""
        self.ws()
        if HYPHEN_WORD.match(self.text, self.pos):
            return None
        m = FIELD.match(self.text, self.pos)
        if not m:
            return None
        return m.group(0), m.start(), m.end()

    def keyword_at(self, *words: str) -> tuple[str, int, int] | None:
        w = self.word_at()
        if w and w[0].upper() in words:
            nxt = self.text[w[2] : w[2] + 1]
            if nxt == "" or not (nxt.isalnum() or nxt in "_."):
                return w
        return None

    def take_keyword(self, *words: str, clause: bool = False) -> tuple[str, int, int] | None:
        w = self.keyword_at(*words)
        if not w:
            return None
        if clause and not (w[0].isupper() or w[0].islower()):
            self.diag("exabeam_keyword_case", f"{w[0]!r}: clause keywords are all upper or all lower case", w[1], w[2])
        self.tok(w[1], w[2], "keyword")
        self.pos = w[2]
        return w

    def expect(self, ch: str, capture: str = "punctuation.bracket") -> int:
        self.ws()
        if not self.text.startswith(ch, self.pos):
            raise ParseError(f"expected {ch!r}", self.pos)
        self.tok(self.pos, self.pos + len(ch), capture)
        self.pos += len(ch)
        return self.pos - len(ch)

    def string(self) -> tuple[str, int, int]:
        """A quoted string at the cursor: its raw body (escapes kept), start, end."""
        self.ws()
        quote = self.text[self.pos]
        start = self.pos
        i = self.pos + 1
        while i < len(self.text):
            if self.text[i] == "\\":
                i += 2
                continue
            if self.text[i] == quote:
                self.pos = i + 1
                self.tok(start, self.pos, "string")
                return self.text[start + 1 : i], start, self.pos
            i += 1
        raise ParseError("unterminated string", start)

    # -- entry -----------------------------------------------------------------------------
    def parse(self) -> Result:
        try:
            if self.at_end():
                if self.profile == "search":
                    return self.result  # an empty search queries every log
                raise ParseError("a sequence query cannot be empty", 0)
            if self.text.lstrip().startswith("/"):
                start = len(self.text) - len(self.text.lstrip())
                self.diag("exabeam_leading_slash", "a query cannot start with `/`", start, start + 1)
                return self.result
            if self.looks_advanced():
                self.result.advanced = True
                if self.profile == "rule":
                    w = self.word_at()
                    s = w[1] if w else self.pos
                    self.diag(
                        "exabeam_advanced_in_rule",
                        "a correlation rule sequence query is a filter: SELECT, WHERE, pipes, and the other advanced operators are Search only",
                        s,
                        len(self.text),
                    )
                    return self.result
                self.advanced()
            else:
                tree = self.filter(stop=())
                self.check_tree(tree, under_or=False)
            if not self.at_end():
                raise ParseError(f"unexpected {self.text[self.pos]!r}", self.pos)
        except ParseError as exc:
            self.diag("exabeam_parse_error", str(exc), exc.pos, exc.pos + 1)
        self.check_context_tables()
        self.result.context_tables = list(self.context_tables)
        self.result.tokens.sort(key=lambda t: (t.start, t.end))
        return self.result

    def looks_advanced(self) -> bool:
        """Advanced form: it opens with SELECT, WHERE, FROM, or FOREACH, or has a pipe, GROUP-BY, ORDER-BY, a statement
        `AS name`, or a trailing `LIMIT n` outside strings and brackets."""
        if self.keyword_at("SELECT", "WHERE", "FROM", "FOREACH"):
            return True
        depth = 0
        i = 0
        text = self.text
        while i < len(text):
            ch = text[i]
            if ch in "\"'":
                j = i + 1
                while j < len(text) and text[j] != ch:
                    j += 2 if text[j] == "\\" else 1
                i = j + 1
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif depth == 0 and ch == "|":
                return True
            elif depth == 0 and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_.-")):
                m = (
                    HYPHEN_WORD.match(text, i)
                    or re.match(r"(?i)limit\s+\d+\s*\Z", text[i:])
                    or (i > 0 and STATEMENT_ALIAS.match(text, i))
                )
                if m:
                    return True
            i += 1
        return False

    # -- filter ----------------------------------------------------------------------------
    def filter(self, stop: tuple[str, ...]) -> Node:
        node = self.or_expr(stop)
        return node

    def at_stop(self, stop: tuple[str, ...]) -> bool:
        if self.at_end():
            return True
        ch = self.peek()
        if ch in (")", "]", "|"):
            return True
        return bool(stop and self.keyword_at(*stop))

    def or_expr(self, stop: tuple[str, ...]) -> Node:
        start = self.pos
        branches = [self.and_expr(stop)]
        while self.take_keyword("OR"):
            branches.append(self.and_expr(stop))
        if len(branches) == 1:
            return branches[0]
        node = Node("or", branches, start, self.pos)
        if any(b.kind == "and" for b in branches):
            self.diag(
                "exabeam_mixed_boolean",
                "AND and OR at one level: AND binds tighter, but Exabeam does not document it; add parentheses",
                start,
                self.pos,
            )
        return node

    def and_expr(self, stop: tuple[str, ...]) -> Node:
        start = self.pos
        items = [self.unary(stop)]
        while True:
            if self.take_keyword("AND"):
                items.append(self.unary(stop))
                continue
            if self.at_stop(stop) or self.keyword_at("OR"):
                break
            here = self.pos
            if self.keyword_at("NOT"):
                self.diag(
                    "exabeam_implicit_operator",
                    "NOT without AND or OR: Exabeam calls it invalid; write AND NOT or OR NOT",
                    here,
                    here + 3,
                )
                items.append(self.unary(stop))
                continue
            nxt = self.unary(stop)
            if not (items[-1].kind == "text" and nxt.kind == "text"):
                self.diag(
                    "exabeam_implicit_and",
                    "two terms with no operator are read as AND: write AND",
                    here,
                    nxt.end,
                )
            items.append(nxt)
        if len(items) == 1:
            return items[0]
        return Node("and", items, start, self.pos)

    def unary(self, stop: tuple[str, ...], negated: bool = False) -> Node:
        start = self.pos
        if self.take_keyword("NOT"):
            return Node("not", [self.unary(stop, negated=True)], start, self.pos)
        return self.primary(stop, negated=negated)

    def primary(self, stop: tuple[str, ...], negated: bool = False) -> Node:
        self.ws()
        start = self.pos
        if self.peek() == "(":
            self.expect("(")
            inner = self.or_expr(())
            self.expect(")")
            node = Node("group", [inner], start, self.pos)
            if inner.kind in ("term", "text", "context", "not", "group") and not negated:
                self.diag(
                    "exabeam_single_group",
                    "parentheses around a single expression: Exabeam's guide calls it an error; drop them",
                    start,
                    self.pos,
                )
            return node
        return self.term()

    def term(self) -> Node:
        self.ws()
        start = self.pos
        if self.at_end():
            raise ParseError("expected a term", self.pos)
        ch = self.text[self.pos]
        if ch in "\"'":
            body, s, e = self.string()
            self.check_phrase(body, s, e, free_text=True)
            return Node("text", [], s, e)
        if ch == "*" and (self.pos + 1 >= len(self.text) or self.text[self.pos + 1].isspace() or self.text[self.pos + 1] == ")"):
            self.diag("exabeam_bare_wildcard", "`*` alone is not a query", self.pos, self.pos + 1)
            self.tok(self.pos, self.pos + 1, "error")
            self.pos += 1
            return Node("term", [], start, self.pos)
        fm = FIELD.match(self.text, self.pos)
        if fm and "-" in fm.group(0):
            after = self.text[fm.end() :].lstrip()
            if after[:2] in ("==", "!=", "<=", ">=") or after[:1] in (":", "=", "<", ">"):
                return self.field_term(fm.group(0), fm.start(), fm.end())
            if re.match(r"(?i)in\s*[\"']", after):
                return self.context_term(fm.group(0), fm.start(), fm.end())
        w = self.word_at()
        if w:
            name, ws_, we = w
            after = self.text[we:]
            stripped = after.lstrip()
            if stripped.startswith("("):
                return self.call(name, ws_, we, filter_position=True)
            if stripped[:2] in ("==", "!=", "<=", ">=") or stripped[:1] in (":", "=", "<", ">"):
                return self.field_term(name, ws_, we)
            if re.match(r"(?i)in\b", stripped):
                return self.context_term(name, ws_, we)
        # free text: a bare word
        m = BARE.match(self.text, self.pos)
        if not m:
            raise ParseError(f"unexpected {ch!r}", self.pos)
        word = m.group(0)
        if word.upper() in OPERATOR_WORDS:
            raise ParseError(f"{word!r} is an operator, not a term: an operand is missing", m.start())
        if not FREE_TEXT_OK.match(word):
            self.diag(
                "exabeam_free_text_special",
                f"free text {word!r} has special characters: put it in double quotes",
                m.start(),
                m.end(),
            )
        self.tok(m.start(), m.end(), "string")
        self.pos = m.end()
        return Node("text", [], start, self.pos)

    def field_term(self, name: str, s: int, e: int) -> Node:
        self.tok(s, e, "property")
        self.pos = e
        self.ws()
        op_start = self.pos
        two = self.text[self.pos : self.pos + 2]
        if two == "!=":
            self.diag("exabeam_not_equal", "there is no `!=` in a filter: write NOT field:value", op_start, op_start + 2)
            self.tok(op_start, op_start + 2, "error")
            self.pos += 2
            self.value(name, exact=False)
            return Node("term", [], s, self.pos)
        if two in ("==", "<=", ">="):
            op = two
        else:
            op = self.text[self.pos]
        self.tok(self.pos, self.pos + len(op), "operator")
        self.pos += len(op)
        if op in (":", "="):
            self.ws()
            two = self.text[self.pos : self.pos + 2]
            if two in ("<=", ">="):
                self.tok(self.pos, self.pos + 2, "operator")
                self.pos += 2
                op = two
            elif self.text[self.pos : self.pos + 1] in ("<", ">"):
                self.tok(self.pos, self.pos + 1, "operator")
                op = self.text[self.pos]
                self.pos += 1
        if op in ("<", ">", "<=", ">="):
            self.scalar(name, comparison=True)
        else:
            self.value(name, exact=op == "==")
        return Node("term", [], s, self.pos)

    def context_term(self, name: str, s: int, e: int) -> Node:
        self.tok(s, e, "property")
        self.pos = e
        self.take_keyword("IN")
        self.ws()
        if self.peek() not in ("\"", "'"):
            raise ParseError("IN takes a context table name in double quotes", self.pos)
        _, ts, te = self.string()
        self.result.tokens[-1].capture = "type"
        end = te
        if self.text[self.pos : self.pos + 1] == ".":
            self.tok(self.pos, self.pos + 1, "punctuation.delimiter")
            self.pos += 1
            if self.text[self.pos : self.pos + 1] not in ("\"", "'"):
                raise ParseError("a context table column is a quoted name", self.pos)
            _, _cs, end = self.string()
            self.result.tokens[-1].capture = "type"
        self.context_tables.append((s, end))
        return Node("context", [], s, end)

    def value(self, field_name: str, exact: bool) -> None:
        self.ws()
        ch = self.text[self.pos : self.pos + 1]
        if ch in ("\"", "'"):
            body, s, e = self.string()
            if field_name.lower() in TIME_FIELDS:
                self.diag("exabeam_time_exact", f"{field_name} takes a range, not an exact value", s, e)
            self.check_phrase(body, s, e, free_text=False)
            return
        if ch == "(":
            self.list_value(field_name)
            return
        if ch in ("[", "{"):
            self.range_value(field_name)
            return
        w = self.word_at()
        if w and self.text[w[2] :].lstrip().startswith("("):
            self.call(w[0], w[1], w[2], filter_position=False)
            return
        if field_name.lower() in TIME_FIELDS:
            m = BARE.match(self.text, self.pos)
            if m and m.group(0).lower() != "null":
                self.diag("exabeam_time_exact", f"{field_name} takes a range, not an exact value", m.start(), m.end())
                self.tok(m.start(), m.end(), "number" if NUMBER.match(m.group(0)) else "constant")
                self.pos = m.end()
                return
        self.scalar(field_name, comparison=False)

    def scalar(self, field_name: str, comparison: bool) -> None:
        self.ws()
        if self.text[self.pos : self.pos + 1] in ("\"", "'"):
            body, s, e = self.string()
            if comparison and not NUMBER.match(_unescape(body)):
                self.diag("exabeam_parse_error", "a comparison takes a number", s, e)
            return
        m = BARE.match(self.text, self.pos)
        if not m:
            raise ParseError("expected a value", self.pos)
        word = m.group(0)
        self.pos = m.end()
        capture = self.bare_capture(word, field_name, m.start(), m.end(), comparison)
        self.tok(m.start(), m.end(), capture)

    def bare_capture(self, word: str, field_name: str, s: int, e: int, comparison: bool) -> str:
        if word.startswith("@"):
            if not self.in_foreach:
                self.diag("exabeam_foreach_reference", f"{word} refers to a FOREACH value outside FOREACH", s, e)
            return "variable"
        if NUMBER.match(word):
            return "number"
        if comparison:
            raise ParseError("a comparison takes a number", s)
        if word.lower() in ("true", "false"):
            return "boolean"
        if word.lower() == "null":
            return "constant"
        if _is_ip(word):
            return "constant"
        self.diag(
            "exabeam_unquoted_value",
            f"{word!r} is not quoted: Exabeam documents string values in double quotes",
            s,
            e,
        )
        return "string"

    def list_value(self, field_name: str) -> None:
        start = self.expect("(")
        count = 0
        while True:
            self.ws()
            if self.text[self.pos : self.pos + 1] in ("\"", "'"):
                body, s, e = self.string()
                self.check_phrase(body, s, e, free_text=False)
            else:
                self.scalar(field_name, comparison=False)
            count += 1
            if self.peek() == ",":
                self.expect(",", "punctuation.delimiter")
                continue
            break
        self.expect(")")

    def range_value(self, field_name: str) -> None:
        self.ws()
        open_ch = self.text[self.pos]
        start = self.pos
        self.expect(open_ch)
        # CIDR: [a.b.c.d/nn]
        m = re.compile(r"\s*([0-9A-Fa-f:.]+)/(\d{1,3})\s*\]").match(self.text, self.pos)
        if open_ch == "[" and m:
            net = m.group(1) + "/" + m.group(2)
            self.tok(m.start(1), m.end(2), "constant")
            try:
                parsed = ipaddress.ip_network(net, strict=False)
            except ValueError:
                self.diag("exabeam_range", f"{net!r} is not a CIDR network", m.start(1), m.end(2))
            else:
                if parsed.version == 6:
                    self.diag("exabeam_ipv6_range", "CIDR is IPv4 only in Exabeam Search", m.start(1), m.end(2))
            self.pos = m.end(2)
            self.expect("]")
            return
        lo, lo_s, lo_e = self.bound()
        if not self.take_keyword("TO"):
            raise ParseError("a range is [low TO high]", self.pos)
        hi, hi_s, hi_e = self.bound()
        self.ws()
        close = self.text[self.pos : self.pos + 1]
        if close not in ("]", "}"):
            raise ParseError("a range closes with ] or }", self.pos)
        self.expect(close)
        if (open_ch == "[") != (close == "]"):
            self.diag("exabeam_range", "a range opens and closes with the same kind of bracket", start, self.pos)
        self.check_range(lo, hi, lo_s, hi_e, field_name)

    def bound(self) -> tuple[str, int, int]:
        self.ws()
        if self.text[self.pos : self.pos + 1] in ("\"", "'"):
            body, s, e = self.string()
            return _unescape(body), s, e
        m = re.compile(r"[^\s\]}]+").match(self.text, self.pos)
        if not m:
            raise ParseError("expected a range bound", self.pos)
        word = m.group(0)
        self.pos = m.end()
        if word == "*":
            capture = "constant"
        elif NUMBER.match(word):
            capture = "number"
        else:
            capture = "constant"
        self.tok(m.start(), m.end(), capture)
        return word, m.start(), m.end()

    def check_range(self, lo: str, hi: str, s: int, e: int, field_name: str) -> None:
        time_field = field_name.lower() in TIME_FIELDS
        kinds: list[tuple[str, object]] = []
        for b in (lo, hi):
            if b == "*":
                kinds.append(("open", None))
            elif time_field and EPOCH_MS.match(b):
                kinds.append(("datetime", _instant(b)))
            elif NUMBER.match(b):
                kinds.append(("number", float(b)))
            elif DATETIME.match(b):
                kinds.append(("datetime", _instant(b)))
            elif _is_ip(b):
                kinds.append(("ip", _is_ip(b)))
            else:
                self.diag("exabeam_range", f"{b!r} is not a number, IPv4 address, datetime, or *", s, e)
                return
        if all(k == "open" for k, _ in kinds):
            self.diag("exabeam_range", "a range needs at least one bound", s, e)
            return
        closed = [k for k in kinds if k[0] != "open"]
        if len({k for k, _ in closed}) > 1:
            self.diag("exabeam_range", "the bounds are of different kinds: both numbers, IPv4 addresses, or datetimes", s, e)
            return
        if closed[0][0] == "ip":
            if any(v.version == 6 for _, v in closed):
                self.diag("exabeam_ipv6_range", "IP ranges are IPv4 only in Exabeam Search", s, e)
                return
        if len(closed) == 2 and closed[0][1] is not None and closed[0][1] > closed[1][1]:  # type: ignore[operator]
            self.diag("exabeam_range", "the low bound is greater than the high bound", s, e)

    def call(self, name: str, s: int, e: int, filter_position: bool) -> Node:
        upper = name.upper()
        self.pos = e
        if upper not in FILTER_FUNCTIONS:
            self.tok(s, e, "error")
            hint = " (Exabeam writes contains as WLD(\"*x*\"), startswith as RGX(\"^x\"))" if upper in KNOWN_FOREIGN else ""
            self.diag("exabeam_unknown_function", f"{name}() is not an Exabeam filter function{hint}", s, e)
        else:
            self.tok(s, e, "function.builtin")
        self.expect("(")
        args: list[tuple[str, int, int]] = []
        while self.peek() != ")":
            if self.at_end():
                raise ParseError("unclosed function call", self.pos)
            if self.peek() in ("\"", "'"):
                args.append(self.string())
            else:
                m = BARE.match(self.text, self.pos)
                if not m:
                    raise ParseError("expected a function argument", self.pos)
                self.tok(m.start(), m.end(), "error")
                self.pos = m.end()
                args.append((m.group(0), m.start(), m.end()))
                if upper in FILTER_FUNCTIONS:
                    self.diag("exabeam_function_arity", f"{name}() takes one double-quoted pattern", m.start(), m.end())
            if self.peek() == ",":
                self.expect(",", "punctuation.delimiter")
        self.expect(")")
        if upper in FILTER_FUNCTIONS and len(args) != 1:
            self.diag("exabeam_function_arity", f"{name}() takes exactly one pattern", s, self.pos)
        if upper in FILTER_FUNCTIONS and len(args) == 1 and FILTER_FUNCTIONS[upper] == "regex":
            body, as_, ae = args[0]
            why = _re2_check(_unescape(body))
            if why:
                self.diag("exabeam_regex", f"invalid RE2 pattern: {why}", as_, ae)
        return Node("term", [], s, self.pos)

    def check_phrase(self, body: str, s: int, e: int, free_text: bool) -> None:
        value = _unescape(body)
        inner = value.strip("`")
        if len(value) > 2 and value.startswith("/") and value.endswith("/"):
            self.diag(
                "exabeam_legacy_regex",
                "a value between slashes may be read as a regular expression: write RGX(\"…\") for a pattern, or drop the slashes for a path",
                s,
                e,
            )
            return
        if re.search(r"(?<!\\)[*?]", inner) and re.search(r"(?<!\\)\s", body.strip()):
            self.diag("exabeam_wildcard_in_phrase", "wildcards do not work inside a quoted phrase", s, e)

    def check_tree(self, node: Node, under_or: bool) -> None:
        if node.kind == "context" and under_or:
            self.diag("exabeam_context_table_or", "a context table lookup is combined with AND or AND NOT only", node.start, node.end)
        for child in node.children:
            self.check_tree(child, under_or or (node.kind == "or" and len(node.children) > 1))

    def check_context_tables(self) -> None:
        if len(self.context_tables) > MAX_CONTEXT_TABLES:
            s, e = self.context_tables[MAX_CONTEXT_TABLES]
            self.diag("exabeam_context_table_limit", f"at most {MAX_CONTEXT_TABLES} context table lookups per query", s, e)

    # -- advanced (Search only) -------------------------------------------------------------
    def advanced(self) -> None:
        pipes = 0
        if (fw := self.keyword_at("FOREACH")) is not None:
            self.diag("exabeam_foreach_position", "FOREACH runs on the result of a preceding query: put a query and | before it", fw[1], fw[2])
        previous = self.statement()
        while self.peek() == "|":
            ps = self.pos
            self.expect("|", "operator.pipe")
            pipes += 1
            if pipes == MAX_PIPES + 1:
                self.diag("exabeam_pipe_limit", f"at most {MAX_PIPES} pipes", ps, ps + 1)
            current = self.statement()
            if not current.foreach:
                if not previous.select:
                    self.diag(
                        "exabeam_pipe_misuse",
                        "the query before a pipe has no SELECT: write one query with AND or WHERE",
                        ps,
                        ps + 1,
                    )
                elif not previous.star and not (current.fields & previous.select):
                    self.diag(
                        "exabeam_pipe_misuse",
                        "the query after a pipe uses no column the query before it selects: write one query with AND or WHERE",
                        ps,
                        ps + 1,
                    )
            previous = current

    def statement(self) -> "Statement":
        fields_before = len(self.result.tokens)
        info = Statement()
        if self.keyword_at("FOREACH"):
            info = self.foreach()
            info.foreach = True
            return info
        order = ["SELECT", "FROM", "WHERE", "AS", "GROUP-BY", "ORDER-BY", "LIMIT"]
        seen: list[str] = []
        select_items: list[tuple[str, bool]] = []
        select_star = False
        group_by: list[str] = []
        stop = ("SELECT", "FROM", "WHERE", "AS", "GROUP-BY", "ORDER-BY", "LIMIT", "FOREACH")
        first = True
        if self.at_end() or self.peek() in ("|", "]"):
            raise ParseError("an empty statement: a pipe joins two statements", self.pos)
        while not self.at_end() and self.peek() not in ("|", "]"):
            kw = self.keyword_at(*order)
            if kw is None:
                if first or seen and seen[-1] in ("FROM",):
                    # a bare filter is an implicit WHERE
                    tree = self.filter(stop=stop)
                    self.check_tree(tree, under_or=False)
                    seen.append("WHERE")
                    first = False
                    continue
                raise ParseError("expected a clause", self.pos)
            word = kw[0].upper()
            if seen and order.index(word) < order.index(seen[-1]):
                self.diag("exabeam_clause_order", f"{word} comes before {seen[-1]}: [SELECT] [WHERE] [GROUP-BY] [ORDER-BY] [LIMIT]", kw[1], kw[2])
            if word in seen:
                self.diag("exabeam_clause_order", f"{word} appears twice", kw[1], kw[2])
            seen.append(word)
            first = False
            self.take_keyword(word, clause=True)
            if word == "SELECT":
                select_star, select_items = self.select_list()
            elif word == "FROM":
                self.alias(capture="type")
            elif word == "WHERE":
                tree = self.filter(stop=stop)
                self.check_tree(tree, under_or=False)
            elif word == "AS":
                self.alias(capture="type")
            elif word == "GROUP-BY":
                group_by = self.name_list(order_by=False)
            elif word == "ORDER-BY":
                self.name_list(order_by=True)
            elif word == "LIMIT":
                self.ws()
                m = re.compile(r"\d+").match(self.text, self.pos)
                if not m or int(m.group(0)) < 1:
                    raise ParseError("LIMIT takes a positive integer", self.pos)
                self.tok(m.start(), m.end(), "number")
                self.pos = m.end()
        if self.in_foreach and ({"GROUP-BY", "ORDER-BY"} & set(seen)):
            self.diag("exabeam_foreach_clause", "a FOREACH sub-query has no GROUP-BY or ORDER-BY", self.pos - 1, self.pos)
        if group_by:
            if select_star:
                self.diag("exabeam_group_by_select_star", "GROUP-BY does not combine with SELECT *", 0, self.pos)
            grouped = {g.lower() for g in group_by}
            for col, aggregated in select_items:
                if not aggregated and col.lower() not in grouped:
                    self.diag("exabeam_group_by_column", f"{col} is selected but neither grouped nor aggregated", 0, self.pos)
        new = self.result.tokens[fields_before:]
        info.fields = {self.text[t.start : t.end].lower() for t in new if t.capture in ("property", "type")}
        info.star = select_star
        if "SELECT" in seen:
            info.select = {c.lower() for c, _ in select_items} | {
                self.text[t.start : t.end].lower() for t in new if t.capture == "variable"
            }
            info.select.add("*") if select_star else None
        return info

    def foreach(self) -> "Statement":
        self.take_keyword("FOREACH", clause=True)
        w = self.column_at()
        if not w:
            raise ParseError("FOREACH names a field", self.pos)
        self.tok(w[1], w[2], "property")
        self.pos = w[2]
        self.expect("[")
        self.in_foreach += 1
        inner = self.statement()
        self.in_foreach -= 1
        self.expect("]")
        if self.take_keyword("LIMIT", clause=True):
            self.ws()
            m = re.compile(r"\d+").match(self.text, self.pos)
            if not m or int(m.group(0)) < 1:
                raise ParseError("LIMIT takes a positive integer", self.pos)
            self.tok(m.start(), m.end(), "number")
            self.pos = m.end()
        return inner

    def select_list(self) -> tuple[bool, list[tuple[str, bool]]]:
        star = False
        items: list[tuple[str, bool]] = []
        self.take_keyword("DISTINCT", clause=True)
        while True:
            self.ws()
            if self.text[self.pos : self.pos + 1] == "*":
                self.tok(self.pos, self.pos + 1, "operator")
                self.pos += 1
                star = True
            else:
                w = self.column_at()
                if not w:
                    raise ParseError("expected a column", self.pos)
                name, s, e = w
                if self.text[e:].lstrip().startswith("("):
                    self.select_call(name, s, e)
                    items.append((name, True))
                else:
                    self.tok(s, e, "property")
                    self.pos = e
                    items.append((name, False))
            if self.take_keyword("AS", clause=True):
                self.alias(capture="variable")
            if self.peek() == ",":
                self.expect(",", "punctuation.delimiter")
                continue
            return star, items

    def select_call(self, name: str, s: int, e: int) -> None:
        upper = name.upper()
        self.pos = e
        if upper == "RGX_EXTRACT":
            self.rgx_extract += 1
            if self.rgx_extract == MAX_RGX_EXTRACT + 1:
                self.diag("exabeam_rgx_extract_limit", f"at most {MAX_RGX_EXTRACT} RGX_EXTRACT per query", s, e)
            if not (name.isupper() or name.islower()):
                self.diag("exabeam_keyword_case", f"{name!r}: write RGX_EXTRACT or rgx_extract", s, e)
            self.tok(s, e, "function.builtin")
            self.expect("(")
            args = 0
            pattern: tuple[str, int, int] | None = None
            while self.peek() != ")":
                if self.peek() in ("\"", "'"):
                    pattern = self.string()
                else:
                    w = self.column_at()
                    if not w:
                        raise ParseError("expected a field or a pattern", self.pos)
                    self.tok(w[1], w[2], "property")
                    self.pos = w[2]
                args += 1
                if self.peek() == ",":
                    self.expect(",", "punctuation.delimiter")
            self.expect(")")
            if args not in (1, 2) or pattern is None:
                self.diag("exabeam_function_arity", "RGX_EXTRACT([field,] \"pattern\")", s, self.pos)
            elif (why := _re2_check(_unescape(pattern[0]))) is not None:
                self.diag("exabeam_regex", f"invalid RE2 pattern: {why}", pattern[1], pattern[2])
            return
        if upper in AGGREGATES and not (name.isupper() or name.islower()):
            self.diag("exabeam_keyword_case", f"{name!r}: write {upper} or {upper.lower()}", s, e)
        if upper not in AGGREGATES:
            self.tok(s, e, "error")
            self.diag("exabeam_unknown_function", f"{name}() is not an Exabeam aggregation (COUNT, MIN, MAX, SUM, AVG, RGX_EXTRACT)", s, e)
        else:
            self.tok(s, e, "function.builtin")
        self.expect("(")
        self.ws()
        if self.text[self.pos : self.pos + 1] == "*":
            if upper != "COUNT":
                self.diag("exabeam_function_arity", f"{name}(*) : only COUNT takes *", self.pos, self.pos + 1)
            self.tok(self.pos, self.pos + 1, "operator")
            self.pos += 1
        else:
            w = self.column_at()
            if not w:
                raise ParseError("an aggregation takes one field", self.pos)
            self.tok(w[1], w[2], "property")
            self.pos = w[2]
        if self.peek() == ",":
            self.diag("exabeam_function_arity", f"{name}() takes one field", self.pos, self.pos + 1)
            while self.peek() != ")" and not self.at_end():
                self.pos += 1
        self.expect(")")

    def alias(self, capture: str) -> None:
        w = self.word_at()
        if not w:
            raise ParseError("expected a name", self.pos)
        name, s, e = w
        if name.lower() in RESERVED:
            self.diag("exabeam_reserved_alias", f"{name!r} is a reserved word", s, e)
        self.tok(s, e, capture)
        self.pos = e

    def name_list(self, order_by: bool) -> list[str]:
        names: list[str] = []
        while True:
            w = self.column_at()
            if not w:
                raise ParseError("expected a column", self.pos)
            self.tok(w[1], w[2], "property")
            self.pos = w[2]
            names.append(w[0])
            if order_by:
                self.take_keyword("ASC", "DESC", clause=True)
            if self.peek() == ",":
                self.expect(",", "punctuation.delimiter")
                continue
            return names


def analyze(text: str, profile: str = "rule") -> Result:
    """Diagnostics and highlight tokens for one query under `profile` (`rule` or `search`)."""
    return Parser(text, profile).parse()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", choices=PROFILES, default="rule")
    ap.add_argument("--tokens", action="store_true", help="print highlight tokens")
    ap.add_argument("file", type=Path)
    args = ap.parse_args(argv)
    text = args.file.read_text(encoding="utf-8")
    result = analyze(text, args.profile)
    out: dict[str, object] = {
        "diagnostics": [
            {"code": d.code, "severity": d.severity, "message": d.message, "range": [d.start, d.end]} for d in result.diagnostics
        ]
    }
    if args.tokens:
        out["tokens"] = [[t.start, t.end, t.capture, text[t.start : t.end]] for t in result.tokens]
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
