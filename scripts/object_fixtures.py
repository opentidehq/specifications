"""Conformance checks for Tide object YAML fixtures.

This is a specifications-repo checker, not the opentide validation engine.
It enforces the object-spec field types and vocabulary pins that CI can
prove without a Pydantic runtime.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised via validate.py error path
    yaml = None  # type: ignore[assignment]
    _YAML_IMPORT_ERROR = exc
else:
    _YAML_IMPORT_ERROR = None

UUID_V4 = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
REGISTERED_SCHEMAS = frozenset(
    {"threat::1.0", "objective::1.0", "objective::1.1", "rule::1.0", "rule::1.1"}
)
RULE_SCHEMAS = frozenset({"rule::1.0", "rule::1.1"})
OBJECTIVE_SCHEMAS = frozenset({"objective::1.0", "objective::1.1"})
SIGNAL_DEFINITION_FIELDS = (
    "name",
    "uuid",
    "description",
    "severity",
    "methodology",
    "entities",
    "data",
    "effort",
    "detectors",
    "examples",
    "parent",
)
THREAT_REQUIRED_BODY = (
    "description",
    "severity",
    "impact",
    "leverage",
    "viability",
    "terrain",
    "surface",
    "mitre_attack",
)
PACKED_SEPARATOR = ";"


@dataclass(frozen=True)
class VocabKey:
    identity: str
    stages: frozenset[str]


@dataclass
class Vocab:
    field: str
    key_mode: str
    keys: list[VocabKey] = field(default_factory=list)

    def identities(self) -> set[str]:
        return {item.identity for item in self.keys}

    def scoped_identities(self) -> set[str]:
        scoped: set[str] = set()
        for item in self.keys:
            if not item.stages:
                continue
            for stage in item.stages:
                scoped.add(f"{stage}::{item.identity}")
        return scoped

    def has_unscoped(self, token: str) -> bool:
        return token in self.identities()

    def has_scoped(self, token: str) -> bool:
        return token in self.scoped_identities()


@dataclass(frozen=True)
class CheckError:
    code: str
    message: str
    path: str = ""

    def format(self, source: str = "") -> str:
        prefix = f"{source}: " if source else ""
        where = f" ({self.path})" if self.path else ""
        return f"{prefix}{self.code}{where}: {self.message}"


def _stages_of(entry: dict[str, Any]) -> frozenset[str]:
    raw = entry.get("tide.vocab.stages")
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        return frozenset({raw})
    if isinstance(raw, list):
        return frozenset(str(item) for item in raw)
    return frozenset()


def load_vocabularies(vocab_dir: Path) -> dict[str, Vocab]:
    index: dict[str, Vocab] = {}
    for path in sorted(vocab_dir.glob("*.vocab.toml")):
        import tomllib

        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        field_name = str(doc.get("field") or "")
        key_mode = str(doc.get("key") or "name")
        vocab = Vocab(field=field_name, key_mode=key_mode)
        for entry in doc.get("keys") or []:
            identity = entry.get("id") if key_mode == "id" else entry.get("name")
            if identity is None:
                continue
            vocab.keys.append(VocabKey(identity=str(identity), stages=_stages_of(entry)))
        index[field_name] = vocab
    return index


def _is_packed_token(value: Any) -> bool:
    return isinstance(value, str) and PACKED_SEPARATOR in value


def _require_non_empty_string(value: Any, *, code: str, path: str, errors: list[CheckError]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(CheckError(code, "must be a non-empty string", path))


def _require_uuid_v4(value: Any, *, path: str, errors: list[CheckError]) -> None:
    if not isinstance(value, str) or not UUID_V4.match(value):
        errors.append(CheckError("invalid_uuid", "must be a UUIDv4 string", path))
        return
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        errors.append(CheckError("invalid_uuid", "must be a UUIDv4 string", path))
        return
    if parsed.version != 4:
        errors.append(CheckError("invalid_uuid", "must be UUID version 4", path))


def _require_vocab_name(
    value: Any,
    vocab: Vocab | None,
    *,
    path: str,
    errors: list[CheckError],
    code: str = "unknown_vocab_value",
) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(CheckError("invalid_vocab_token", "must be a non-empty vocabulary string", path))
        return
    if _is_packed_token(value):
        errors.append(
            CheckError(
                "packed_vocab_string",
                "semicolon-packed strings are not a valid encoding of list[string]",
                path,
            )
        )
        return
    if vocab is None:
        return
    if not vocab.has_unscoped(value):
        errors.append(CheckError(code, f"{value!r} is not in {vocab.field}::{vocab.key_mode}", path))


def _require_vocab_id(
    value: Any,
    vocab: Vocab | None,
    *,
    path: str,
    errors: list[CheckError],
) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(CheckError("invalid_vocab_token", "must be a non-empty vocabulary string", path))
        return
    if _is_packed_token(value):
        errors.append(
            CheckError(
                "packed_vocab_string",
                "semicolon-packed strings are not a valid encoding of list[string]",
                path,
            )
        )
        return
    if vocab is None:
        return
    if not vocab.has_unscoped(value):
        errors.append(
            CheckError("unknown_vocab_value", f"{value!r} is not a {vocab.field} id", path)
        )


def _require_scoped_token_list(
    value: Any,
    vocab: Vocab | None,
    *,
    path: str,
    errors: list[CheckError],
) -> None:
    """Validate a list whose vocabulary groups its keys under stages.

    A stage-scoped vocabulary carries the same key name under more than one
    stage (``VPN``, ``Wireless`` and ``Industrial`` are each defined under both
    ``Infrastructure`` and ``Protocol`` in ``surface``), so a bare key name is
    ambiguous and MUST NOT be accepted: the authored value is
    ``<stage>::<key>``. This mirrors ``ThreatActor.name``, which has required
    ``att&ck::``/``misp::`` scoping since actors::1.0.
    """
    if isinstance(value, str):
        code = "packed_vocab_string" if _is_packed_token(value) else "field_not_list"
        errors.append(
            CheckError(code, "must be a list of stage-scoped vocabulary strings", path)
        )
        return
    if not isinstance(value, list) or not value:
        errors.append(CheckError("empty_vocab_list", "MUST be a non-empty list", path))
        return
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, str) or not item.strip():
            errors.append(
                CheckError("invalid_vocab_token", "must be a non-empty vocabulary string", item_path)
            )
            continue
        if _is_packed_token(item):
            errors.append(
                CheckError(
                    "packed_vocab_string",
                    "semicolon-packed strings are not a valid encoding of list[string]",
                    item_path,
                )
            )
            continue
        if vocab is None:
            continue
        if not vocab.has_scoped(item):
            # A value that resolves unscoped is a missing stage prefix, which is
            # a different authoring mistake from naming a key that does not exist.
            if vocab.has_unscoped(item):
                errors.append(
                    CheckError(
                        "surface_unscoped",
                        f"{item!r} MUST be stage-scoped (for example OS::{item})",
                        item_path,
                    )
                )
            else:
                errors.append(
                    CheckError(
                        "unknown_vocab_value",
                        f"{item!r} is not a scoped {vocab.field} value",
                        item_path,
                    )
                )


def _require_token_list(
    value: Any,
    vocab: Vocab | None,
    *,
    path: str,
    errors: list[CheckError],
    id_mode: bool = False,
    allow_empty: bool = False,
) -> None:
    if isinstance(value, str):
        code = "packed_vocab_string" if _is_packed_token(value) else "field_not_list"
        errors.append(
            CheckError(
                code,
                "must be a YAML list of vocabulary tokens, not a scalar string",
                path,
            )
        )
        return
    if not isinstance(value, list):
        errors.append(CheckError("field_not_list", "must be a YAML list of vocabulary tokens", path))
        return
    if not value and not allow_empty:
        errors.append(CheckError("empty_vocab_list", "list must contain at least one token", path))
        return
    checker = _require_vocab_id if id_mode else _require_vocab_name
    for index, item in enumerate(value):
        checker(item, vocab, path=f"{path}[{index}]", errors=errors)


def _is_iso_timestamp(value: Any) -> bool:
    """ISO 8601 date or datetime, the same forms as metadata.created and metadata.modified."""
    if isinstance(value, date):
        return True
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_reviewed(metadata: Any, *, allowed: bool, errors: list[CheckError]) -> None:
    if not isinstance(metadata, dict) or "reviewed" not in metadata:
        return
    if not allowed:
        errors.append(
            CheckError(
                "reviewed_not_in_schema",
                "metadata.reviewed is defined only on rule::1.1",
                "metadata.reviewed",
            )
        )
        return
    if not _is_iso_timestamp(metadata.get("reviewed")):
        errors.append(
            CheckError(
                "invalid_reviewed",
                "metadata.reviewed must be an ISO 8601 date or datetime",
                "metadata.reviewed",
            )
        )


def _validate_metadata(metadata: Any, errors: list[CheckError]) -> str | None:
    if not isinstance(metadata, dict):
        errors.append(CheckError("missing_metadata", "metadata block is required", "metadata"))
        return None
    schema = metadata.get("schema")
    if not isinstance(schema, str) or schema not in REGISTERED_SCHEMAS:
        errors.append(
            CheckError(
                "unknown_schema",
                f"unregistered metadata.schema {schema!r}",
                "metadata.schema",
            )
        )
    _require_uuid_v4(metadata.get("uuid"), path="metadata.uuid", errors=errors)
    if "version" not in metadata:
        errors.append(CheckError("missing_field", "metadata.version is required", "metadata.version"))
    for key in ("created", "modified"):
        if key not in metadata:
            errors.append(CheckError("missing_field", f"metadata.{key} is required", f"metadata.{key}"))
    return schema if isinstance(schema, str) else None


def _validate_threat_actor(
    actor: Any,
    actors_vocab: Vocab | None,
    *,
    path: str,
    errors: list[CheckError],
) -> None:
    if isinstance(actor, str):
        errors.append(
            CheckError(
                "actors_not_objects",
                "actors entries MUST be ThreatActor objects, not bare strings",
                path,
            )
        )
        return
    if not isinstance(actor, dict):
        errors.append(CheckError("actors_not_objects", "actors entries MUST be mappings", path))
        return
    name = actor.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append(CheckError("actor_missing_name", "ThreatActor.name is required", f"{path}.name"))
        return
    if "::" not in name:
        errors.append(
            CheckError(
                "actor_unscoped",
                "ThreatActor.name MUST be stage-scoped (att&ck::<id> or misp::<id>)",
                f"{path}.name",
            )
        )
        return
    if actors_vocab is not None and not actors_vocab.has_scoped(name):
        errors.append(
            CheckError(
                "actor_unknown",
                f"{name!r} is not a scoped actors::1.0 value",
                f"{path}.name",
            )
        )
    references = actor.get("references")
    if references is not None:
        if not isinstance(references, list) or any(not isinstance(item, str) for item in references):
            errors.append(
                CheckError(
                    "invalid_actor_references",
                    "ThreatActor.references MUST be a list of strings when present",
                    f"{path}.references",
                )
            )
    sighting = actor.get("sighting")
    if sighting is not None and not isinstance(sighting, str):
        errors.append(
            CheckError(
                "invalid_actor_sighting",
                "ThreatActor.sighting MUST be a string when present",
                f"{path}.sighting",
            )
        )


def validate_threat(doc: dict[str, Any], vocabs: dict[str, Vocab]) -> list[CheckError]:
    errors: list[CheckError] = []
    _require_non_empty_string(doc.get("name"), code="missing_field", path="name", errors=errors)
    _require_vocab_name(doc.get("criticality"), vocabs.get("criticality"), path="criticality", errors=errors)
    schema = _validate_metadata(doc.get("metadata"), errors)
    if schema and schema != "threat::1.0":
        errors.append(CheckError("unknown_schema", f"threat fixture has schema {schema!r}", "metadata.schema"))
    tlp = (doc.get("metadata") or {}).get("tlp") if isinstance(doc.get("metadata"), dict) else None
    _require_vocab_name(tlp, vocabs.get("tlp"), path="metadata.tlp", errors=errors)
    _validate_reviewed(doc.get("metadata"), allowed=False, errors=errors)

    body = doc.get("threat")
    if not isinstance(body, dict):
        errors.append(CheckError("missing_threat_body", "threat body is required", "threat"))
        return errors

    for key in THREAT_REQUIRED_BODY:
        if key not in body:
            errors.append(CheckError("missing_field", f"threat.{key} is required", f"threat.{key}"))

    _require_non_empty_string(
        body.get("description"), code="missing_field", path="threat.description", errors=errors
    )
    _require_vocab_name(body.get("severity"), vocabs.get("severity"), path="threat.severity", errors=errors)
    _require_token_list(body.get("impact"), vocabs.get("impact"), path="threat.impact", errors=errors)
    _require_token_list(body.get("leverage"), vocabs.get("leverage"), path="threat.leverage", errors=errors)
    _require_vocab_name(body.get("viability"), vocabs.get("viability"), path="threat.viability", errors=errors)
    _require_non_empty_string(
        body.get("terrain"), code="missing_field", path="threat.terrain", errors=errors
    )
    _require_scoped_token_list(
        body.get("surface"), vocabs.get("surface"), path="threat.surface", errors=errors
    )
    _require_token_list(
        body.get("mitre_attack"),
        vocabs.get("att&ck"),
        path="threat.mitre_attack",
        errors=errors,
        id_mode=True,
    )

    actors = body.get("actors", None)
    if actors is not None:
        if not isinstance(actors, list):
            errors.append(CheckError("actors_not_objects", "threat.actors MUST be a list", "threat.actors"))
        else:
            for index, actor in enumerate(actors):
                _validate_threat_actor(
                    actor, vocabs.get("actors"), path=f"threat.actors[{index}]", errors=errors
                )
    return errors


def validate_objective(doc: dict[str, Any], vocabs: dict[str, Vocab]) -> list[CheckError]:
    errors: list[CheckError] = []
    _require_non_empty_string(doc.get("name"), code="missing_field", path="name", errors=errors)
    schema = _validate_metadata(doc.get("metadata"), errors)
    if schema and schema not in OBJECTIVE_SCHEMAS:
        errors.append(
            CheckError("unknown_schema", f"objective fixture has schema {schema!r}", "metadata.schema")
        )
    tlp = (doc.get("metadata") or {}).get("tlp") if isinstance(doc.get("metadata"), dict) else None
    _require_vocab_name(tlp, vocabs.get("tlp"), path="metadata.tlp", errors=errors)
    _validate_reviewed(doc.get("metadata"), allowed=False, errors=errors)

    composition = doc.get("composition")
    if not isinstance(composition, dict):
        errors.append(CheckError("missing_field", "top-level composition is required", "composition"))

    body = doc.get("objective")
    if not isinstance(body, dict):
        errors.append(CheckError("missing_field", "objective body is required", "objective"))
        return errors
    signals = body.get("signals")
    if not isinstance(signals, list) or len(signals) < 1:
        errors.append(
            CheckError("empty_signals", "objective.signals MUST contain at least one signal", "objective.signals")
        )
        return errors
    for index, signal in enumerate(signals):
        if not isinstance(signal, dict):
            errors.append(
                CheckError("invalid_signal", "each signal MUST be a mapping", f"objective.signals[{index}]")
            )
            continue
        has_reuse = "reuse" in signal
        definition_fields = [key for key in SIGNAL_DEFINITION_FIELDS if key in signal]
        if has_reuse and definition_fields:
            errors.append(
                CheckError(
                    "signal_entry_mixed",
                    "reuse cannot be combined with definition fields",
                    f"objective.signals[{index}]",
                )
            )
        if has_reuse and schema == "objective::1.0":
            errors.append(
                CheckError(
                    "binding_requires_1_1",
                    "reuse is valid only on objective::1.1",
                    f"objective.signals[{index}].reuse",
                )
            )
        if has_reuse:
            _require_uuid_v4(signal.get("reuse"), path=f"objective.signals[{index}].reuse", errors=errors)
            continue
        for required in ("name", "uuid", "description", "severity", "methodology", "entities", "data"):
            if required not in signal:
                errors.append(
                    CheckError(
                        "missing_field",
                        f"signal.{required} is required",
                        f"objective.signals[{index}].{required}",
                    )
                )
        _require_uuid_v4(signal.get("uuid"), path=f"objective.signals[{index}].uuid", errors=errors)
        effort = signal.get("effort")
        if effort is not None and (isinstance(effort, bool) or not isinstance(effort, int)):
            errors.append(
                CheckError(
                    "invalid_effort",
                    "signal.effort MUST be an integer score, not a string or a vocabulary term",
                    f"objective.signals[{index}].effort",
                )
            )
    return errors


_ELASTIC_NO_LANGUAGE = frozenset({"eql", "esql", "machine_learning"})
_ELASTIC_NO_SOURCE = frozenset({"esql", "machine_learning"})


def validate_elastic_block(block: dict[str, Any]) -> list[CheckError]:
    """The three platform::elastic::1.0 constraint codes the invalid fixture exercises.

    `language`, `esql_source`, and `suppression_shape` (specs/platforms/elastic-1.0.md).
    The checker reports the platform's own code names, so a fixture fails with the
    code opentide reports. The other Elastic codes are left to opentide.
    """
    errors: list[CheckError] = []
    base = "configurations.elastic"
    rule_type = block.get("type")
    if rule_type in _ELASTIC_NO_LANGUAGE and block.get("language"):
        errors.append(
            CheckError("language", f"language MUST NOT be set for type {rule_type}", f"{base}.language")
        )
    if rule_type in _ELASTIC_NO_SOURCE and (
        block.get("index") or block.get("data_view_id") or block.get("filters")
    ):
        errors.append(
            CheckError(
                "esql_source",
                f"type {rule_type} MUST NOT set index, data_view_id, or filters",
                base,
            )
        )
    suppression = block.get("suppression")
    if suppression is not None:
        group_by = suppression.get("group_by") if isinstance(suppression, dict) else None
        if not isinstance(suppression, dict):
            valid = False
        elif rule_type == "threshold":
            valid = bool(suppression.get("duration")) and not group_by
        else:
            valid = (
                isinstance(group_by, list)
                and 1 <= len(group_by) <= 3
                and len(set(map(str, group_by))) == len(group_by)
                and all(isinstance(item, str) and item for item in group_by)
            )
        if not valid:
            errors.append(
                CheckError(
                    "suppression_shape",
                    "threshold needs duration and no group_by; other types need 1-3 distinct group_by fields",
                    f"{base}.suppression",
                )
            )
    return errors


_SYSDIG_PRIORITIES = frozenset(
    {"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "INFO", "DEBUG"}
)
_SYSDIG_TUNING_FORBIDDEN = ("output", "priority", "policies", "source", "name")
_SYSDIG_STR_OPS = (
    "=", "==", "!=", "contains", "icontains", "bcontains", "startswith", "bstartswith",
    "endswith", "glob", "iglob", "regex",
)
_SYSDIG_LIST_COMPS = frozenset({"in", "intersects", "pmatch"})
# Falco's operators (libsinsp parser.cpp) and the modified string operators
# (falco rule_loader_cmpop.h): "startswith oneof", "= anyof", ...
_SYSDIG_COMPS = frozenset({"exists", "<", "<=", ">", ">="} | set(_SYSDIG_STR_OPS) | _SYSDIG_LIST_COMPS)
_SYSDIG_MODIFIERS = ("oneof", "anyof", "allof")
_SYSDIG_RESERVED = frozenset({"and", "or", "not", "in", "exists", "val"}) | _SYSDIG_COMPS
_SYSDIG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SYSDIG_SOURCE = re.compile(r"^[a-z][a-z0-9_]*$")


def _blank(value: Any) -> bool:
    return not isinstance(value, str) or not value.strip()


def _modified(comp: str) -> bool:
    parts = comp.split()
    return len(parts) == 2 and parts[0] in _SYSDIG_STR_OPS and parts[1] in _SYSDIG_MODIFIERS


def _comp(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) else None


def _sysdig_exception_ok(exc: Any) -> bool:
    """Falco's validate_exception_info and build_rule_exception_infos shape checks."""
    if not isinstance(exc, dict) or _blank(exc.get("name")):
        return False
    fields, comps, values = exc.get("fields"), exc.get("comps"), exc.get("values", [])
    if values is None:
        values = []
    if not isinstance(values, list):
        return False
    if isinstance(fields, str):
        if _blank(fields):
            return False
        if comps is not None:
            comp = _comp(comps)
            if comp is None or not (comp in _SYSDIG_LIST_COMPS or _modified(comp)):
                return False
        return all(not isinstance(value, (list, dict)) for value in values)
    if not isinstance(fields, list) or not fields or not all(isinstance(f, str) and f for f in fields):
        return False
    if comps is None:
        comps = ["="] * len(fields)
    if not isinstance(comps, list) or len(comps) != len(fields):
        return False
    for raw in comps:
        comp = _comp(raw)
        if comp is None or not (comp in _SYSDIG_COMPS or _modified(comp)):
            return False
    return all(isinstance(row, list) and len(row) == len(fields) for row in values)


def validate_sysdig_block(block: dict[str, Any]) -> list[CheckError]:
    """The platform::sysdig::1.0 constraint codes that need no Falco parser.

    specs/platforms/sysdig-1.0.md#constraints. `sysdig_definition_order` and
    `sysdig_list_in_value` need the Falco tokenizer and are left to opentide.
    """
    errors: list[CheckError] = []
    base = "configurations.sysdig"
    tuning = block.get("append_to_rule")
    if tuning is None:
        if _blank(block.get("condition")):
            errors.append(CheckError("sysdig_rule_shape", "a new rule needs a non-blank condition", f"{base}.condition"))
    else:
        has_condition = not _blank(block.get("condition"))
        has_exceptions = isinstance(block.get("exceptions"), list) and bool(block["exceptions"])
        if _blank(tuning) or not (has_condition or has_exceptions):
            errors.append(
                CheckError(
                    "sysdig_rule_shape",
                    "a tuning names a rule and appends a condition or exceptions",
                    f"{base}.append_to_rule",
                )
            )
        set_keys = [key for key in _SYSDIG_TUNING_FORBIDDEN if block.get(key) not in (None, "", [])]
        if set_keys:
            errors.append(
                CheckError(
                    "sysdig_tuning_keys",
                    f"a tuning MUST NOT set {', '.join(set_keys)}",
                    base,
                )
            )
    priority = block.get("priority")
    if priority is not None and (not isinstance(priority, str) or priority.upper() not in _SYSDIG_PRIORITIES):
        errors.append(CheckError("sysdig_priority", f"{priority!r} is not a Falco priority", f"{base}.priority"))
    source = block.get("source")
    if source is not None and (not isinstance(source, str) or not _SYSDIG_SOURCE.match(source)):
        errors.append(CheckError("sysdig_source", f"{source!r} is not a Falco source name", f"{base}.source"))
    exceptions = block.get("exceptions") or []
    for index, exc in enumerate(exceptions if isinstance(exceptions, list) else [exceptions]):
        if not _sysdig_exception_ok(exc):
            errors.append(
                CheckError(
                    "sysdig_exception_shape",
                    "exception fields, comps, and values do not align",
                    f"{base}.exceptions[{index}]",
                )
            )
    defined: set[str] = set()
    for kind in ("macros", "lists"):
        entries = block.get(kind) or []
        for index, entry in enumerate(entries if isinstance(entries, list) else []):
            name = entry.get("name") if isinstance(entry, dict) else None
            path = f"{base}.{kind}[{index}].name"
            if not isinstance(name, str) or not _SYSDIG_NAME.match(name) or name in _SYSDIG_RESERVED:
                errors.append(CheckError("sysdig_definition_name", f"{name!r} is not a macro or list name", path))
                continue
            if name in defined:
                errors.append(CheckError("sysdig_definition_duplicate", f"{name!r} is defined twice", path))
            defined.add(name)
    return errors


# response.procedure.searches[].language: the query languages a system with more
# than one language takes (specs/objects/rule-1.1.md, specifications#58).
SEARCH_LANGUAGES: dict[str, frozenset[str]] = {
    "elastic": frozenset({"kuery", "lucene", "eql", "esql"}),
}


_YARA_INCLUDE = re.compile(r"^\s*include\s+\"", re.MULTILINE)
_YARA_RULE = re.compile(r"^\s*((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_YARA_SECTION_HEADER = re.compile(r"^\s*(?:strings\s*:|condition\s*:|(?:(?:private|global)\s+)*rule\s+[A-Za-z_])", re.MULTILINE)


def validate_yara_signature(signature: Any, path: str) -> list[CheckError]:
    """The YARA codes of specs/languages/yara-1.0.md that need no YARA parser."""
    errors: list[CheckError] = []
    if not isinstance(signature, str) or not signature.strip():
        return [CheckError("yara_empty_signature", "signature MUST be a non-blank YARA text", path)]
    if _YARA_INCLUDE.search(signature):
        errors.append(CheckError("yara_include", "include is not allowed in a signature", path))
    rules = _YARA_RULE.findall(signature)
    if not any(not modifiers.strip() for modifiers, _ in rules):
        errors.append(CheckError("yara_empty_signature", "no rule that is neither private nor global", path))
    seen: set[str] = set()
    for _, name in rules:
        if name in seen:
            errors.append(CheckError("yara_duplicate_rule", f"rule {name!r} is defined twice", path))
        seen.add(name)
    return errors


def validate_harfanglab_block(block: dict[str, Any]) -> list[CheckError]:
    """The platform::harfanglab::1.0 constraint codes that need no YARA parser.

    specs/platforms/harfanglab-1.0.md#constraints. `harfanglab_yara_import` and
    `harfanglab_yara_rule_name` need the module catalogue and are left to opentide.
    """
    base = "configurations.harfanglab"
    errors: list[CheckError] = []
    sigma, yara_block = block.get("sigma"), block.get("yara")
    if sigma is not None and yara_block is not None:
        errors.append(CheckError("harfanglab_rule_kind", "a block carries sigma or yara, not both", base))
    if not isinstance(yara_block, dict):
        return errors
    decomposed = [key for key in ("meta", "strings", "condition", "imports") if key in yara_block]
    if "signature" in yara_block:
        if decomposed:
            errors.append(
                CheckError(
                    "harfanglab_yara_form",
                    f"signature is set with decomposed keys {', '.join(decomposed)}",
                    f"{base}.yara",
                )
            )
        errors.extend(validate_yara_signature(yara_block["signature"], f"{base}.yara.signature"))
    for key in ("strings", "condition"):
        body = yara_block.get(key)
        if isinstance(body, str) and _YARA_SECTION_HEADER.search(body):
            errors.append(
                CheckError("harfanglab_yara_section_header", f"{key} holds a section or rule header", f"{base}.yara.{key}")
            )
    return errors


BITDEFENDER_TARGETS = frozenset(
    {
        "process", "file", "connection", "registry", "user connection", "email", "application", "key vault",
        "role", "policy", "sharing link", "url", "ssh key", "launch template", "service principal", "user group",
        "automation account", "automation account hook", "certificate authority", "api", "bucket",
        "jira project", "confluence page",
    }
)
_BD_CREATED_BY = ("Name", "Path", "FullPathName", "CommandLine", "User")
BITDEFENDER_FIELDS: dict[str, frozenset[str]] = {
    "process": frozenset(
        f"Process.{name}"
        for name in (
            "Name", "Path", "FullPathName", "CommandLine", "Parent.Name", "Parent.Path", "Parent.FullPathName",
            "Parent.CommandLine", "User", "MD5", "SHA2",
        )
    ),
    "file": frozenset(
        [f"File.{name}" for name in ("Name", "Path", "FullPathName", "Operation", "CertificateSigner",
                                     "CertificateIssuer", "CertificateSignedStatus", "MD5", "SHA2", "Url",
                                     "SourceIP", "DestinationIP")]
        + [f"File.CreatedBy.{name}" for name in _BD_CREATED_BY]
    ),
    "connection": frozenset(
        [f"Connection.{name}" for name in ("SourceIP", "DestinationIP", "SourcePort", "DestinationPort", "URL",
                                           "Domain", "Protocol", "HTTPUser", "HTTPDownloadedFile",
                                           "HTTPUploadedFile", "FTPUser", "SSHUser", "TelnetUser", "SMBDomain",
                                           "SMBSharePath", "SMBUser", "WMIExecQuery", "FileRemotePath",
                                           "FileRemoteOperation")]
        + [f"Connection.Process.{name}" for name in _BD_CREATED_BY]
    ),
    "registry": frozenset(
        [f"Registry.{name}" for name in ("Key", "Value", "Data", "DataType", "Operation")]
        + [f"Registry.CreatedBy.{name}" for name in _BD_CREATED_BY[:4]]
    ),
}
BITDEFENDER_ENUMS: dict[str, frozenset[str]] = {
    "File.Operation": frozenset({"rename", "copy", "create", "shared", "downloaded", "uploaded", "read", "write", "move"}),
    "File.CertificateSignedStatus": frozenset({"is_signed", "is_unsigned"}),
    "Connection.Protocol": frozenset({"http/https", "smb"}),
    "Connection.FileRemoteOperation": frozenset({"create", "rem_delete", "read", "write", "move"}),
    "Registry.Operation": frozenset(
        {"key_created", "key_deleted", "key_renamed", "value_created", "value_deleted", "value_written"}
    ),
    "Registry.DataType": frozenset(
        {"string", "expandablestring", "dword", "qword", "binary", "none", "link", "resource_list",
         "full_resource_descriptor", "resource_requirements_list"}
    ),
}
BITDEFENDER_ACTIONS = ("isolate", "collect_investigation_package", "sandbox", "kill_process", "antimalware_scan",
                       "quarantine", "risk_scan")
_BD_RELATIONS = ("is", "contains", "any")


def _bd_criterion_errors(criterion: Any, target: str, path: str) -> list[CheckError]:
    if not isinstance(criterion, dict) or not isinstance(criterion.get("field"), str):
        return [CheckError("bitdefender_criterion_shape", "a criterion needs a field", path)]
    relations = [key for key in _BD_RELATIONS if key in criterion]
    unknown = set(criterion) - {"field", *_BD_RELATIONS}
    if len(relations) != 1 or unknown:
        return [CheckError("bitdefender_criterion_shape", "a criterion has exactly one of is, contains, any", path)]
    relation, value = relations[0], criterion[relations[0]]
    if relation == "any" and (not isinstance(value, list) or not value):
        return [CheckError("bitdefender_criterion_shape", "any takes a non-empty list", path)]
    if relation != "any" and (isinstance(value, (list, dict)) or value is None):
        return [CheckError("bitdefender_criterion_shape", f"{relation} takes one value", path)]
    errors: list[CheckError] = []
    field_name = criterion["field"]
    known = BITDEFENDER_FIELDS.get(target)
    if known is not None and field_name not in known:
        errors.append(CheckError("bitdefender_criterion_field", f"{field_name!r} is not a {target} field", path))
    if field_name in BITDEFENDER_ENUMS:
        if relation == "contains":
            errors.append(CheckError("bitdefender_criterion_relation", f"{field_name} takes is or any", path))
        values = value if isinstance(value, list) else [value]
        bad = [item for item in values if item not in BITDEFENDER_ENUMS[field_name]]
        if bad:
            errors.append(CheckError("bitdefender_criterion_value", f"{bad!r} not in {field_name}", path))
    if relation == "contains" and field_name.endswith((".MD5", ".SHA2")):
        errors.append(CheckError("bitdefender_criterion_relation", f"contains is not allowed on {field_name}", path))
    if field_name.endswith("Port"):
        values = value if isinstance(value, list) else [value]
        if any(not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 65535 for item in values):
            errors.append(CheckError("bitdefender_criterion_value", "a port is an integer 0-65535", path))
    return errors


def validate_bitdefender_block(block: dict[str, Any]) -> list[CheckError]:
    """The platform::bitdefender::1.0 constraint codes that need no catalogue beyond the spec's EDR table.

    specs/platforms/bitdefender-1.0.md#constraints. `bitdefender_criteria_combination` and the workspace check
    `bitdefender_name_duplicate` are left to opentide.
    """
    base = "configurations.bitdefender"
    errors: list[CheckError] = []
    kinds = [key for key in ("detection", "yara") if key in block]
    if len(kinds) != 1:
        errors.append(CheckError("bitdefender_rule_kind", "exactly one of detection and yara", base))
    severity = block.get("severity")
    if severity is not None and severity not in ("Low", "Medium", "High"):
        errors.append(CheckError("bitdefender_severity", f"{severity!r} is not Low, Medium, or High", f"{base}.severity"))
    targets = block.get("targets")
    if targets is not None:
        keys = [key for key in ("endpoint_tags", "companies") if key in (targets if isinstance(targets, dict) else {})]
        if (
            not isinstance(targets, dict)
            or len(keys) != 1
            or set(targets) - {"endpoint_tags", "companies"}
            or not isinstance(targets[keys[0]], list)
            or not targets[keys[0]]
        ):
            errors.append(CheckError("bitdefender_targets_shape", "one non-empty list: endpoint_tags or companies", f"{base}.targets"))
    detection = block.get("detection")
    target = ""
    created_by = False
    if isinstance(detection, dict):
        target = detection.get("target") if isinstance(detection.get("target"), str) else ""
        if target not in BITDEFENDER_TARGETS:
            errors.append(CheckError("bitdefender_target", f"{target!r} is not a detection target", f"{base}.detection.target"))
        criteria = detection.get("criteria")
        if not isinstance(criteria, list) or not criteria:
            errors.append(CheckError("bitdefender_criterion_shape", "criteria is a non-empty list", f"{base}.detection.criteria"))
            criteria = []
        for index, criterion in enumerate(criteria):
            errors.extend(_bd_criterion_errors(criterion, target, f"{base}.detection.criteria.{index}"))
            if isinstance(criterion, dict) and ".CreatedBy." in str(criterion.get("field", "")):
                created_by = True
    actions = block.get("actions")
    if isinstance(actions, dict):
        for key in actions:
            if key not in BITDEFENDER_ACTIONS:
                errors.append(CheckError("bitdefender_action_scope", f"{key!r} is not an action", f"{base}.actions"))
        process_like = target in ("process", "file") or created_by
        for key in ("sandbox", "quarantine"):
            if key in actions and "detection" in kinds and not process_like:
                errors.append(CheckError("bitdefender_action_scope", f"{key} needs a process or file target", f"{base}.actions.{key}"))
        if "kill_process" in actions and ("yara" in kinds or not process_like):
            errors.append(CheckError("bitdefender_action_scope", "kill_process is a Basic process/file action", f"{base}.actions.kill_process"))
        scan = actions.get("antimalware_scan")
        if scan is not None and scan not in ("quick", "full"):
            errors.append(CheckError("bitdefender_action_scope", "antimalware_scan is quick or full", f"{base}.actions.antimalware_scan"))
    yara_block = block.get("yara")
    if isinstance(yara_block, dict):
        signature = yara_block.get("signature")
        path = f"{base}.yara.signature"
        errors.extend(validate_yara_signature(signature, path))
        if isinstance(signature, str):
            if not signature.isascii():
                errors.append(CheckError("bitdefender_yara_ascii", "the signature holds non-ASCII characters", path))
            if len(signature) > 30000:
                errors.append(CheckError("bitdefender_yara_size", "the signature exceeds 30,000 characters", path))
    return errors


def aliased_paths(text: str) -> list[str]:
    """Dotted paths whose value is a YAML alias of a node defined earlier in the file."""
    if yaml is None:
        return []
    try:
        root = yaml.compose(text)
    except Exception:  # noqa: BLE001 - parse errors are reported by load_yaml
        return []
    seen: set[int] = set()
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if id(node) in seen and isinstance(node, yaml.ScalarNode):
            found.append(path)
            return
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                walk(value, f"{path}.{key.value}" if path else str(key.value))
        elif isinstance(node, yaml.SequenceNode):
            for index, value in enumerate(node.value):
                walk(value, f"{path}.{index}")

    if root is not None:
        walk(root, "")
    return found


def validate_searches(doc: dict[str, Any]) -> list[CheckError]:
    """`language` on a hunt search is set only for a system that lists it, with a listed value."""
    response = doc.get("response")
    procedure = response.get("procedure") if isinstance(response, dict) else None
    searches = procedure.get("searches") if isinstance(procedure, dict) else None
    if not isinstance(searches, list):
        return []
    errors: list[CheckError] = []
    for index, search in enumerate(searches):
        # An empty `language:` key (YAML null) is the same as omitting it.
        if not isinstance(search, dict) or search.get("language") is None:
            continue
        path = f"response.procedure.searches[{index}].language"
        system = search.get("system")
        allowed = SEARCH_LANGUAGES.get(system) if isinstance(system, str) else None
        if allowed is None:
            errors.append(
                CheckError("search_language", f"language MUST NOT be set for system {system!r}", path)
            )
        elif not isinstance(search["language"], str) or search["language"] not in allowed:
            errors.append(
                CheckError(
                    "search_language",
                    f"{search['language']!r} is not one of {', '.join(sorted(allowed))} for system {system!r}",
                    path,
                )
            )
    return errors


def validate_rule(doc: dict[str, Any], vocabs: dict[str, Vocab]) -> list[CheckError]:
    errors: list[CheckError] = []
    _require_non_empty_string(doc.get("name"), code="missing_field", path="name", errors=errors)
    if "metadata" not in doc:
        errors.append(CheckError("missing_metadata", "metadata block is required", "metadata"))
        return errors
    schema = _validate_metadata(doc.get("metadata"), errors)
    if schema and schema not in RULE_SCHEMAS:
        errors.append(CheckError("unknown_schema", f"rule fixture has schema {schema!r}", "metadata.schema"))
    tlp = (doc.get("metadata") or {}).get("tlp") if isinstance(doc.get("metadata"), dict) else None
    _require_vocab_name(tlp, vocabs.get("tlp"), path="metadata.tlp", errors=errors)
    _validate_reviewed(doc.get("metadata"), allowed=schema == "rule::1.1", errors=errors)
    _require_non_empty_string(
        doc.get("description"), code="missing_field", path="description", errors=errors
    )
    configurations = doc.get("configurations")
    if isinstance(configurations, dict) and isinstance(configurations.get("elastic"), dict):
        errors.extend(validate_elastic_block(configurations["elastic"]))
    if isinstance(configurations, dict) and isinstance(configurations.get("sysdig"), dict):
        errors.extend(validate_sysdig_block(configurations["sysdig"]))
    if isinstance(configurations, dict) and isinstance(configurations.get("harfanglab"), dict):
        errors.extend(validate_harfanglab_block(configurations["harfanglab"]))
    if isinstance(configurations, dict) and isinstance(configurations.get("bitdefender"), dict):
        errors.extend(validate_bitdefender_block(configurations["bitdefender"]))
    errors.extend(validate_searches(doc))
    return errors


def validate_document(doc: Any, vocabs: dict[str, Vocab]) -> list[CheckError]:
    if not isinstance(doc, dict):
        return [CheckError("invalid_yaml", "fixture MUST parse to a mapping")]
    metadata = doc.get("metadata")
    schema = metadata.get("schema") if isinstance(metadata, dict) else None
    if schema == "threat::1.0" or "threat" in doc:
        return validate_threat(doc, vocabs)
    if schema in OBJECTIVE_SCHEMAS or "objective" in doc:
        return validate_objective(doc, vocabs)
    return validate_rule(doc, vocabs)


def load_yaml(path: Path) -> Any:
    if yaml is None:
        raise RuntimeError("PyYAML is required: pip install pyyaml") from _YAML_IMPORT_ERROR
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_fixture_file(path: Path, vocabs: dict[str, Vocab]) -> list[CheckError]:
    try:
        doc = load_yaml(path)
    except Exception as exc:  # noqa: BLE001 — surface parse errors as fixture failures
        return [CheckError("yaml_parse_error", str(exc))]
    errors = validate_document(doc, vocabs)
    for dotted in aliased_paths(path.read_text(encoding="utf-8")):
        parts = dotted.split(".")
        if len(parts) == 4 and parts[0] == "configurations" and parts[2:] == ["yara", "signature"]:
            errors.append(CheckError("yara_signature_alias", "signature MUST be written in the block, not aliased", dotted))
    return errors


EXPECTED_INVALID_CODES: dict[str, str] = {
    "threat-missing-body.yaml": "missing_threat_body",
    "threat-impact-as-string.yaml": "field_not_list",
    "threat-leverage-semicolon.yaml": "packed_vocab_string",
    "threat-leverage-semicolon-list-item.yaml": "packed_vocab_string",
    "threat-impact-semicolon.yaml": "packed_vocab_string",
    "threat-impact-empty.yaml": "empty_vocab_list",
    "threat-leverage-empty.yaml": "empty_vocab_list",
    "threat-leverage-high.yaml": "unknown_vocab_value",
    "threat-actors-string-list.yaml": "actors_not_objects",
    "threat-actors-not-list.yaml": "actors_not_objects",
    "threat-actor-missing-name.yaml": "actor_missing_name",
    "threat-actor-unscoped.yaml": "actor_unscoped",
    "threat-actor-wrong-stage.yaml": "actor_unknown",
    "threat-surface-unscoped.yaml": "surface_unscoped",
    "rule-bad-uuid.yaml": "invalid_uuid",
    "rule-unknown-schema.yaml": "unknown_schema",
    "rule-missing-metadata.yaml": "missing_metadata",
    "rule-reviewed-bad-date.yaml": "invalid_reviewed",
    "rule-1.0-reviewed.yaml": "reviewed_not_in_schema",
    "objective-no-signals.yaml": "empty_signals",
    "objective-signal-entry-mixed.yaml": "signal_entry_mixed",
    "objective-signal-bad-uuid.yaml": "invalid_uuid",
    "objective-1.0-signal-binding.yaml": "binding_requires_1_1",
    "objective-effort-string.yaml": "invalid_effort",
    "rule-elastic-esql-index.yaml": "esql_source",
    "rule-search-language.yaml": "search_language",
    "rule-sysdig-tuning-output.yaml": "sysdig_tuning_keys",
    "rule-harfanglab-sigma-and-yara.yaml": "harfanglab_rule_kind",
    "rule-harfanglab-yara-both-forms.yaml": "harfanglab_yara_form",
    "rule-harfanglab-yara-include.yaml": "yara_include",
    "rule-yara-signature-alias.yaml": "yara_signature_alias",
    "rule-bitdefender-two-kinds.yaml": "bitdefender_rule_kind",
    "rule-bitdefender-criterion-field.yaml": "bitdefender_criterion_field",
    "rule-bitdefender-exclusion.yaml": "bitdefender_rule_kind",
    "rule-bitdefender-kill-on-yara.yaml": "bitdefender_action_scope",
}
