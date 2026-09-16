"""Conformance checks for Tide object YAML fixtures.

This is a specifications-repo checker, not the opentide validation engine.
It enforces the object-spec field types and vocabulary pins that CI can
prove without a Pydantic runtime.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
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
REGISTERED_SCHEMAS = frozenset({"threat::1.0", "objective::1.0", "rule::1.0"})
THREAT_REQUIRED_BODY = (
    "description",
    "severity",
    "impact",
    "leverage",
    "viability",
    "terrain",
    "surface",
    "att&ck",
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
    _require_token_list(body.get("surface"), vocabs.get("surface"), path="threat.surface", errors=errors)
    _require_token_list(
        body.get("att&ck"), vocabs.get("att&ck"), path="threat.att&ck", errors=errors, id_mode=True
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
    if schema and schema != "objective::1.0":
        errors.append(
            CheckError("unknown_schema", f"objective fixture has schema {schema!r}", "metadata.schema")
        )
    tlp = (doc.get("metadata") or {}).get("tlp") if isinstance(doc.get("metadata"), dict) else None
    _require_vocab_name(tlp, vocabs.get("tlp"), path="metadata.tlp", errors=errors)

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
    return errors


def validate_rule(doc: dict[str, Any], vocabs: dict[str, Vocab]) -> list[CheckError]:
    errors: list[CheckError] = []
    _require_non_empty_string(doc.get("name"), code="missing_field", path="name", errors=errors)
    if "metadata" not in doc:
        errors.append(CheckError("missing_metadata", "metadata block is required", "metadata"))
        return errors
    schema = _validate_metadata(doc.get("metadata"), errors)
    if schema and schema != "rule::1.0":
        errors.append(CheckError("unknown_schema", f"rule fixture has schema {schema!r}", "metadata.schema"))
    tlp = (doc.get("metadata") or {}).get("tlp") if isinstance(doc.get("metadata"), dict) else None
    _require_vocab_name(tlp, vocabs.get("tlp"), path="metadata.tlp", errors=errors)
    _require_non_empty_string(
        doc.get("description"), code="missing_field", path="description", errors=errors
    )
    return errors


def validate_document(doc: Any, vocabs: dict[str, Vocab]) -> list[CheckError]:
    if not isinstance(doc, dict):
        return [CheckError("invalid_yaml", "fixture MUST parse to a mapping")]
    metadata = doc.get("metadata")
    schema = metadata.get("schema") if isinstance(metadata, dict) else None
    if schema == "threat::1.0" or "threat" in doc:
        return validate_threat(doc, vocabs)
    if schema == "objective::1.0" or "objective" in doc:
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
    return validate_document(doc, vocabs)


EXPECTED_INVALID_CODES: dict[str, str] = {
    "threat-missing-body.yaml": "missing_threat_body",
    "threat-impact-as-string.yaml": "field_not_list",
    "threat-leverage-semicolon.yaml": "packed_vocab_string",
    "threat-leverage-semicolon-list-item.yaml": "packed_vocab_string",
    "threat-impact-empty.yaml": "empty_vocab_list",
    "threat-actors-string-list.yaml": "actors_not_objects",
    "threat-actor-missing-name.yaml": "actor_missing_name",
    "threat-actor-unscoped.yaml": "actor_unscoped",
    "rule-bad-uuid.yaml": "invalid_uuid",
    "rule-unknown-schema.yaml": "unknown_schema",
    "rule-missing-metadata.yaml": "missing_metadata",
    "objective-no-signals.yaml": "empty_signals",
}
