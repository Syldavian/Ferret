#!/usr/bin/env python3
"""Helpers for Ferret RFC 2136 dynamic update scenarios."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.tsigkeyring
import dns.update


RR_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?P<ttl>\d+)\s+(?P<rdclass>\S+)\s+(?P<rdtype>\S+)\s+(?P<rdata>.+?)\s*$"
)


@dataclass(frozen=True)
class UpdatePrerequisite:
    kind: str
    name: str
    type: Optional[str] = None
    rrs: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class UpdateOperation:
    kind: str
    rr: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None


@dataclass(frozen=True)
class QueryStep:
    id: str
    name: str
    type: str
    transport: str = "udp"
    normalize: str = "message"
    ignore_ttl: bool = True
    description: str = ""


@dataclass(frozen=True)
class UpdateStep:
    id: str
    transport: str
    prerequisites: List[UpdatePrerequisite]
    operations: List[UpdateOperation]
    description: str = ""


Step = Union[QueryStep, UpdateStep]


@dataclass(frozen=True)
class DynamicUpdateScenario:
    origin: str
    auth: Dict[str, Any]
    steps: List[Step]
    category: str = "legacy_query"
    notes: str = ""
    source_format: str = "canonical"

    @property
    def has_updates(self) -> bool:
        return any(isinstance(step, UpdateStep) for step in self.steps)


def _canonicalize_origin(origin: str) -> str:
    return dns.name.from_text(origin).to_text()


def _canonicalize_name(name: str) -> str:
    return dns.name.from_text(name).to_text()


def _normalize_auth(auth: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = dict(auth or {})
    mode = str(raw.get("Mode", "none")).lower()
    if mode == "none":
        return {"Mode": "none"}
    if mode != "tsig":
        raise ValueError(f"Unsupported auth mode: {raw.get('Mode')}")
    if "KeyName" not in raw or "Secret" not in raw:
        raise ValueError("TSIG auth requires KeyName and Secret")
    normalized = {
        "Mode": "tsig",
        "KeyName": _canonicalize_name(raw["KeyName"]),
        "Secret": str(raw["Secret"]),
        "Algorithm": str(raw.get("Algorithm", "hmac-sha256")).rstrip(".").lower(),
        "Fudge": int(raw.get("Fudge", 300)),
    }
    if normalized["Fudge"] <= 0:
        raise ValueError("TSIG fudge must be positive")
    # Validate the secret early so scenarios fail before container startup.
    base64.b64decode(normalized["Secret"], validate=True)
    return normalized


def _parse_rr_text(rr_text: str) -> Dict[str, Any]:
    match = RR_RE.match(rr_text)
    if not match:
        raise ValueError(f"Could not parse RR text: {rr_text}")
    return {
        "name": _canonicalize_name(match.group("name")),
        "ttl": int(match.group("ttl")),
        "class": match.group("rdclass").upper(),
        "type": match.group("rdtype").upper(),
        "rdata": match.group("rdata"),
    }


def _make_query_step(step_id: str, payload: Dict[str, Any]) -> QueryStep:
    return QueryStep(
        id=step_id,
        name=_canonicalize_name(payload["Name"]),
        type=payload["Type"].upper(),
        transport=payload.get("Transport", "udp").lower(),
        normalize=payload.get("Normalize", "message"),
        ignore_ttl=payload.get("IgnoreTTL", True),
        description=payload.get("Description", ""),
    )


def _legacy_prerequisite_to_struct(prereq: Dict[str, Any]) -> UpdatePrerequisite:
    rdclass = prereq.get("Class", "").upper()
    rdtype = prereq.get("Type", "").upper()
    name = _canonicalize_name(prereq["Name"])
    rdata = prereq.get("Rdata")
    if rdclass == "ANY" and rdtype == "ANY":
        return UpdatePrerequisite(kind="name_in_use", name=name)
    if rdclass == "NONE" and rdtype == "ANY":
        return UpdatePrerequisite(kind="name_absent", name=name)
    if rdclass == "ANY":
        return UpdatePrerequisite(kind="rrset_exists", name=name, type=rdtype)
    if rdclass == "NONE":
        return UpdatePrerequisite(kind="rrset_absent", name=name, type=rdtype)
    if rdata is None:
        raise ValueError(f"Legacy prerequisite missing Rdata: {prereq}")
    ttl = prereq.get("TTL", 0)
    rr_text = f"{name} {ttl} {rdclass} {rdtype} {rdata}"
    return UpdatePrerequisite(kind="rrset_equals", name=name, type=rdtype, rrs=[rr_text])


def _legacy_update_to_operations(update_payload: Dict[str, Any]) -> List[UpdateOperation]:
    operations: List[UpdateOperation] = []
    for rr_text in update_payload.get("Add", []):
        operations.append(UpdateOperation(kind="add_rr", rr=rr_text))
    for rr_text in update_payload.get("Delete", []):
        operations.append(UpdateOperation(kind="delete_rr", rr=rr_text))
    for rr_meta in update_payload.get("DeleteRRset", []):
        operations.append(
            UpdateOperation(kind="delete_rrset", name=_canonicalize_name(rr_meta["Name"]), type=rr_meta["Type"].upper())
        )
    for name in update_payload.get("DeleteName", []):
        operations.append(UpdateOperation(kind="delete_name", name=_canonicalize_name(name)))
    return operations


def _legacy_update_step(step_id: str, payload: Dict[str, Any]) -> UpdateStep:
    prereqs: List[UpdatePrerequisite] = []
    if "Prerequisite" in payload:
        legacy_prereq = payload["Prerequisite"]
        if isinstance(legacy_prereq, list):
            prereqs.extend(_legacy_prerequisite_to_struct(item) for item in legacy_prereq)
        else:
            prereqs.append(_legacy_prerequisite_to_struct(legacy_prereq))
    return UpdateStep(
        id=step_id,
        transport=payload.get("Transport", "udp").lower(),
        prerequisites=prereqs,
        operations=_legacy_update_to_operations(payload.get("Update", {})),
        description=payload.get("Description", ""),
    )


def _parse_canonical_prerequisite(item: Dict[str, Any]) -> UpdatePrerequisite:
    rr_texts = [_canonicalize_rr_text(rr) for rr in item.get("Rrs", [])]
    return UpdatePrerequisite(
        kind=item["Kind"],
        name=_canonicalize_name(item["Name"]),
        type=item.get("Type", "").upper() or None,
        rrs=rr_texts,
    )


def _canonicalize_rr_text(rr_text: str) -> str:
    parsed = _parse_rr_text(rr_text)
    return f'{parsed["name"]} {parsed["ttl"]} {parsed["class"]} {parsed["type"]} {parsed["rdata"]}'


def _parse_canonical_operation(item: Dict[str, Any]) -> UpdateOperation:
    rr_text = item.get("Rr")
    if rr_text is not None:
        rr_text = _canonicalize_rr_text(rr_text)
    name = item.get("Name")
    if name is not None:
        name = _canonicalize_name(name)
    rr_type = item.get("Type")
    if rr_type is not None:
        rr_type = rr_type.upper()
    return UpdateOperation(kind=item["Kind"], rr=rr_text, name=name, type=rr_type)


def _parse_canonical_step(item: Dict[str, Any], index: int) -> Step:
    step_kind = item["Kind"].upper()
    step_id = item.get("Id", f"{step_kind.lower()}{index}")
    if step_kind == "QUERY":
        payload = {
            "Name": item["Name"],
            "Type": item["Type"],
            "Transport": item.get("Transport", "udp"),
            "Normalize": item.get("Normalize", "message"),
            "IgnoreTTL": item.get("IgnoreTTL", True),
            "Description": item.get("Description", ""),
        }
        return _make_query_step(step_id, payload)
    if step_kind != "UPDATE":
        raise ValueError(f"Unsupported step kind: {item['Kind']}")
    return UpdateStep(
        id=step_id,
        transport=item.get("Transport", "udp").lower(),
        prerequisites=[_parse_canonical_prerequisite(pr) for pr in item.get("Prerequisites", [])],
        operations=[_parse_canonical_operation(op) for op in item.get("Operations", [])],
        description=item.get("Description", ""),
    )


def load_scenario(raw: Any, origin: str) -> DynamicUpdateScenario:
    """Normalize legacy or canonical query JSON into a scenario."""
    origin = _canonicalize_origin(origin)
    if isinstance(raw, list):
        steps: List[Step] = []
        update_count = 0
        query_count = 0
        for item in raw:
            query_payload = item.get("Query", {})
            qtype = query_payload.get("Type", "").upper()
            if qtype == "UPDATE":
                update_count += 1
                steps.append(_legacy_update_step(f"u{update_count}", query_payload))
            else:
                query_count += 1
                steps.append(_make_query_step(f"q{query_count}", query_payload))
        return DynamicUpdateScenario(
            origin=origin,
            auth=_normalize_auth({"Mode": "none"}),
            steps=steps,
            category="legacy_query" if update_count == 0 else "legacy_update",
            notes="",
            source_format="legacy_list",
        )
    if not isinstance(raw, dict):
        raise ValueError("Scenario JSON must be either a list or an object")
    steps = [_parse_canonical_step(step, idx + 1) for idx, step in enumerate(raw.get("Steps", []))]
    return DynamicUpdateScenario(
        origin=_canonicalize_origin(raw.get("Origin", origin)),
        auth=_normalize_auth(raw.get("Auth", {"Mode": "none"})),
        steps=steps,
        category=raw.get("Category", raw.get("Mode", "dynamic_update")).lower(),
        notes=raw.get("Notes", ""),
        source_format="canonical",
    )


def rr_text_to_components(rr_text: str) -> Tuple[str, int, str, str, str]:
    parsed = _parse_rr_text(rr_text)
    return (
        parsed["name"],
        parsed["ttl"],
        parsed["class"],
        parsed["type"],
        parsed["rdata"],
    )


def build_update_message(origin: str, step: UpdateStep, auth: Optional[Dict[str, Any]] = None) -> dns.update.Update:
    """Create a dnspython RFC 2136 UPDATE message."""
    auth = _normalize_auth(auth)
    update = dns.update.Update(origin)
    if auth["Mode"] == "tsig":
        keyring = dns.tsigkeyring.from_text({auth["KeyName"]: auth["Secret"]})
        update.use_tsig(
            keyring,
            keyname=auth["KeyName"],
            algorithm=auth["Algorithm"],
            fudge=auth["Fudge"],
        )
    for prereq in step.prerequisites:
        if prereq.kind == "name_in_use":
            update.present(prereq.name)
        elif prereq.kind == "name_absent":
            update.absent(prereq.name)
        elif prereq.kind == "rrset_exists":
            if not prereq.type:
                raise ValueError("rrset_exists prerequisite requires a type")
            update.present(prereq.name, prereq.type)
        elif prereq.kind == "rrset_absent":
            if not prereq.type:
                raise ValueError("rrset_absent prerequisite requires a type")
            update.absent(prereq.name, prereq.type)
        elif prereq.kind == "rrset_equals":
            if not prereq.rrs:
                raise ValueError("rrset_equals prerequisite requires RRs")
            for rr_text in prereq.rrs:
                name, _ttl, _rdclass, rr_type, rdata = rr_text_to_components(rr_text)
                update.present(name, rr_type, rdata)
        else:
            raise ValueError(f"Unsupported prerequisite kind: {prereq.kind}")
    for operation in step.operations:
        if operation.kind == "add_rr":
            if not operation.rr:
                raise ValueError("add_rr operation requires rr")
            name, ttl, _rdclass, rr_type, rdata = rr_text_to_components(operation.rr)
            update.add(name, ttl, rr_type, rdata)
        elif operation.kind == "delete_rr":
            if not operation.rr:
                raise ValueError("delete_rr operation requires rr")
            name, _ttl, _rdclass, rr_type, rdata = rr_text_to_components(operation.rr)
            update.delete(name, rr_type, rdata)
        elif operation.kind == "delete_rrset":
            if not operation.name or not operation.type:
                raise ValueError("delete_rrset operation requires name and type")
            update.delete(operation.name, operation.type)
        elif operation.kind == "delete_name":
            if not operation.name:
                raise ValueError("delete_name operation requires name")
            update.delete(operation.name)
        else:
            raise ValueError(f"Unsupported operation kind: {operation.kind}")
    return update


def send_update(update: dns.update.Update, port: int, transport: str = "udp") -> Union[str, dns.message.Message]:
    """Send an UPDATE request and return either a response or an error marker."""
    addr = "127.0.0.1"
    try:
        if transport.lower() == "tcp":
            return dns.query.tcp(update, addr, 3, port=port, ignore_trailing=True)
        return dns.query.udp(update, addr, 3, port=port, ignore_trailing=True)
    except dns.exception.Timeout:
        return "No response"
    except Exception as exc:  # pylint: disable=broad-except
        return f"Unexpected error {exc}"


def message_to_jsonable(result: Union[str, dns.message.Message]) -> Union[str, List[str]]:
    if isinstance(result, str):
        return result
    return result.to_text().split("\n")


def _normalize_question(message: dns.message.Message) -> List[str]:
    return sorted(str(question) for question in message.question)


def _normalize_section(section: Sequence[Any], ignore_ttl: bool) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for rrset in section:
        for rdata in rrset:
            row = {
                "name": rrset.name.to_text(),
                "class": dns.rdataclass.to_text(rrset.rdclass),
                "type": dns.rdatatype.to_text(rrset.rdtype),
                "rdata": rdata.to_text(),
            }
            if not ignore_ttl:
                row["ttl"] = rrset.ttl
            rows.append(row)
    rows.sort(key=lambda row: json.dumps(row, sort_keys=True))
    return rows


def normalize_query_result(
    result: Union[str, dns.message.Message], mode: str = "message", ignore_ttl: bool = True
) -> Dict[str, Any]:
    if isinstance(result, str):
        return {"outcome": result}
    flags = sorted(flag for flag in dns.flags.to_text(result.flags).split() if flag != "RA")
    normalized = {
        "outcome": "response",
        "opcode": dns.opcode.to_text(result.opcode()),
        "rcode": dns.rcode.to_text(result.rcode()),
        "flags": flags,
        "question": _normalize_question(result),
    }
    if mode == "rrset":
        normalized["answer"] = _normalize_section(result.answer, ignore_ttl)
        return normalized
    normalized["answer"] = _normalize_section(result.answer, ignore_ttl)
    normalized["authority"] = _normalize_section(result.authority, ignore_ttl)
    normalized["additional"] = _normalize_section(result.additional, ignore_ttl)
    return normalized


def normalize_update_reply(result: Union[str, dns.message.Message]) -> Dict[str, Any]:
    if isinstance(result, str):
        return {"outcome": result}
    flags = sorted(flag for flag in dns.flags.to_text(result.flags).split() if flag not in {"AA", "RA"})
    return {
        "outcome": "response",
        "opcode": dns.opcode.to_text(result.opcode()),
        "rcode": dns.rcode.to_text(result.rcode()),
        "flags": flags,
    }


def json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def scenario_to_jsonable(scenario: DynamicUpdateScenario) -> Dict[str, Any]:
    auth_payload = dict(scenario.auth)
    if auth_payload.get("Mode") == "tsig" and "Secret" in auth_payload:
        auth_payload["Secret"] = "<redacted>"
    steps: List[Dict[str, Any]] = []
    for step in scenario.steps:
        if isinstance(step, QueryStep):
            steps.append(
                {
                    "Id": step.id,
                    "Kind": "QUERY",
                    "Name": step.name,
                    "Type": step.type,
                    "Transport": step.transport,
                    "Normalize": step.normalize,
                    "IgnoreTTL": step.ignore_ttl,
                    "Description": step.description,
                }
            )
        else:
            steps.append(
                {
                    "Id": step.id,
                    "Kind": "UPDATE",
                    "Transport": step.transport,
                    "Description": step.description,
                    "Prerequisites": [
                        {
                            "Kind": prereq.kind,
                            "Name": prereq.name,
                            "Type": prereq.type,
                            "Rrs": prereq.rrs,
                        }
                        for prereq in step.prerequisites
                    ],
                    "Operations": [
                        {
                            "Kind": operation.kind,
                            "Rr": operation.rr,
                            "Name": operation.name,
                            "Type": operation.type,
                        }
                        for operation in step.operations
                    ],
                }
            )
    return {
        "Mode": "DynamicUpdate" if scenario.has_updates else "QueryOnly",
        "Origin": scenario.origin,
        "Auth": auth_payload,
        "Category": scenario.category,
        "Notes": scenario.notes,
        "SourceFormat": scenario.source_format,
        "Steps": steps,
    }


def prerequisite_shape(step: UpdateStep) -> str:
    if not step.prerequisites:
        return "none"
    parts = []
    for prereq in step.prerequisites:
        suffix = prereq.type or "ANY"
        if prereq.kind == "rrset_equals" and prereq.rrs:
            rr_type = rr_text_to_components(prereq.rrs[0])[3]
            suffix = rr_type
        parts.append(f"{prereq.kind}:{suffix}")
    return "|".join(sorted(parts))


def operation_shape(step: UpdateStep) -> str:
    parts = []
    for operation in step.operations:
        suffix = operation.type or ""
        if operation.rr:
            suffix = rr_text_to_components(operation.rr)[3]
        if suffix:
            parts.append(f"{operation.kind}:{suffix}")
        else:
            parts.append(operation.kind)
    return "|".join(sorted(parts))
