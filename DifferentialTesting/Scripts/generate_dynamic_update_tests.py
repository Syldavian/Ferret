#!/usr/bin/env python3
"""Generate handcrafted RFC 2136 dynamic update tests for Ferret."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1] / "ferret_tests"
ZONEFILES_DIR = ROOT / "ZoneFiles"
QUERIES_DIR = ROOT / "Queries"
TSIG_KEY_NAME = "ferret-update.campus.edu."
TSIG_SECRET = "ZmVycmV0LWR5bmFtaWMtdXBkYXRlLXNlY3JldA=="


BASE_ZONE = """campus.edu.                  500 IN SOA ns1.campus.edu. root.campus.edu. 3 500 86400 2419200 500
campus.edu.                  500 IN NS  ns1.campus.edu.
ns1.campus.edu.              500 IN A   172.20.0.2
"""


def write_case(test_id: str, zone_text: str, scenario: Dict[str, Any]) -> None:
    (ZONEFILES_DIR / f"{test_id}.txt").write_text(zone_text.rstrip() + "\n", encoding="utf-8")
    (QUERIES_DIR / f"{test_id}.json").write_text(json.dumps(scenario, indent=2) + "\n", encoding="utf-8")


def scenario(category: str,
             steps: List[Dict[str, Any]],
             notes: str = "",
             auth: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "Mode": "DynamicUpdate",
        "Origin": "campus.edu.",
        "Auth": auth or {"Mode": "none"},
        "Category": category,
        "Notes": notes,
        "Steps": steps,
    }


def query(step_id: str, name: str, rr_type: str, description: str = "") -> Dict[str, Any]:
    return {
        "Id": step_id,
        "Kind": "QUERY",
        "Name": name,
        "Type": rr_type,
        "Transport": "udp",
        "Normalize": "rrset",
        "IgnoreTTL": True,
        "Description": description,
    }


def update(step_id: str,
           operations: List[Dict[str, Any]],
           prerequisites: List[Dict[str, Any]] | None = None,
           description: str = "") -> Dict[str, Any]:
    return {
        "Id": step_id,
        "Kind": "UPDATE",
        "Transport": "udp",
        "Description": description,
        "Prerequisites": prerequisites or [],
        "Operations": operations,
    }


def add_rr(rr: str) -> Dict[str, Any]:
    return {"Kind": "add_rr", "Rr": rr}


def delete_rr(rr: str) -> Dict[str, Any]:
    return {"Kind": "delete_rr", "Rr": rr}


def delete_rrset(name: str, rr_type: str) -> Dict[str, Any]:
    return {"Kind": "delete_rrset", "Name": name, "Type": rr_type}


def delete_name(name: str) -> Dict[str, Any]:
    return {"Kind": "delete_name", "Name": name}


def prereq(kind: str, name: str, rr_type: str | None = None, rrs: List[str] | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"Kind": kind, "Name": name}
    if rr_type is not None:
        payload["Type"] = rr_type
    if rrs is not None:
        payload["Rrs"] = rrs
    return payload


def main() -> None:
    write_case(
        "test_100_dynamic_update_add_rr_absent",
        BASE_ZONE,
        scenario(
            "add_rr_absent",
            [
                update(
                    "u1",
                    [add_rr("added.campus.edu. 500 IN A 198.51.100.7")],
                    description="Add a new A RR at an owner name that is initially absent.",
                ),
                query("q1", "added.campus.edu.", "A", "Observe the new RR after the update."),
            ],
        ),
    )

    write_case(
        "test_101_dynamic_update_delete_existing_rr",
        BASE_ZONE + "deleteme.campus.edu.            500 IN A   198.51.100.10\n",
        scenario(
            "delete_existing_rr",
            [
                update(
                    "u1",
                    [delete_rr("deleteme.campus.edu. 0 IN A 198.51.100.10")],
                    description="Delete an RR that exists exactly once in the initial zone.",
                ),
                query("q1", "deleteme.campus.edu.", "A", "The owner should disappear after deletion."),
            ],
        ),
    )

    write_case(
        "test_102_dynamic_update_delete_missing_rr",
        BASE_ZONE,
        scenario(
            "delete_missing_rr",
            [
                update(
                    "u1",
                    [delete_rr("missing.campus.edu. 0 IN A 198.51.100.11")],
                    description="Delete an RR that does not exist. RFC 2136 says this should be silently ignored.",
                ),
                query("q1", "missing.campus.edu.", "A", "The owner should still be absent."),
            ],
        ),
    )

    write_case(
        "test_103_dynamic_update_delete_rrset",
        BASE_ZONE +
        "rrset.campus.edu.               500 IN A   198.51.100.1\n"
        "rrset.campus.edu.               500 IN A   198.51.100.2\n",
        scenario(
            "delete_rrset",
            [
                update(
                    "u1",
                    [delete_rrset("rrset.campus.edu.", "A")],
                    description="Delete a whole A RRset with two members.",
                ),
                query("q1", "rrset.campus.edu.", "A", "The A RRset should no longer exist."),
            ],
        ),
    )

    write_case(
        "test_104_dynamic_update_prereq_name_in_use_add",
        BASE_ZONE + 'occupied.campus.edu.            500 IN TXT "present"\n',
        scenario(
            "prereq_name_in_use",
            [
                update(
                    "u1",
                    [add_rr("gated.campus.edu. 500 IN A 198.51.100.30")],
                    prerequisites=[prereq("name_in_use", "occupied.campus.edu.")],
                    description="Add an RR only when a different owner name already exists.",
                ),
                query("q1", "gated.campus.edu.", "A", "The gated RR should appear when the prerequisite is satisfied."),
            ],
        ),
    )

    write_case(
        "test_105_dynamic_update_prereq_name_absent_rejects",
        BASE_ZONE + 'occupied.campus.edu.            500 IN TXT "present"\n',
        scenario(
            "prereq_name_absent",
            [
                update(
                    "u1",
                    [add_rr("blocked.campus.edu. 500 IN A 198.51.100.31")],
                    prerequisites=[prereq("name_absent", "occupied.campus.edu.")],
                    description="Attempt an add guarded by a name_absent prerequisite that should fail.",
                ),
                query("q1", "blocked.campus.edu.", "A", "The blocked RR should remain absent if the prerequisite fails."),
            ],
        ),
    )

    write_case(
        "test_106_dynamic_update_duplicate_add_retry",
        BASE_ZONE,
        scenario(
            "duplicate_add_retry",
            [
                update(
                    "u1",
                    [add_rr("retry.campus.edu. 500 IN A 198.51.100.40")],
                    description="First add of a new RR.",
                ),
                query("q1", "retry.campus.edu.", "A", "Observe state after the first add."),
                update(
                    "u2",
                    [add_rr("retry.campus.edu. 500 IN A 198.51.100.40")],
                    description="Repeat the identical update to test retry/idempotence handling.",
                ),
                query("q2", "retry.campus.edu.", "A", "Observe state after replaying the same add."),
            ],
        ),
    )

    write_case(
        "test_107_dynamic_update_delete_name",
        BASE_ZONE +
        "wipe.campus.edu.                500 IN A   198.51.100.50\n"
        'wipe.campus.edu.                500 IN TXT "bye"\n',
        scenario(
            "delete_name",
            [
                update(
                    "u1",
                    [delete_name("wipe.campus.edu.")],
                    description="Delete every RRset at an owner name.",
                ),
                query("q1", "wipe.campus.edu.", "A", "The owner should be gone after delete_name."),
                query("q2", "wipe.campus.edu.", "TXT", "No RRset at the owner name should remain."),
            ],
        ),
    )

    write_case(
        "test_108_dynamic_update_tsig_add_rr_absent",
        BASE_ZONE,
        scenario(
            "tsig_add_rr_absent",
            [
                update(
                    "u1",
                    [add_rr("signed-added.campus.edu. 500 IN A 198.51.100.60")],
                    description="Add a new A RR using a TSIG-signed UPDATE request.",
                ),
                query("q1", "signed-added.campus.edu.", "A", "Observe the new RR after the signed update."),
            ],
            notes="This scenario exercises TSIG-authenticated dynamic update support for servers that require signed UPDATEs.",
            auth={
                "Mode": "tsig",
                "KeyName": TSIG_KEY_NAME,
                "Secret": TSIG_SECRET,
                "Algorithm": "hmac-sha256",
                "Fudge": 300,
            },
        ),
    )

    write_case(
        "test_002_prerequisite_matching_rdata_canonicalization_and_c",
        BASE_ZONE +
        "mxtarget.campus.edu.         500 IN A   192.0.2.45\n"
        "; The MX and TXT RDATA use mixed case to create ambiguity for UPDATE prerequisite matching\n"
        "test.campus.edu.             500 IN MX  10 MxTarget.Campus.EDU.\n"
        'test.campus.edu.             500 IN TXT "MiXeD-Text"\n',
        scenario(
            "prereq_rdata_canonicalization",
            [
                update(
                    "u1",
                    [add_rr("added-if-mx-match.campus.edu. 500 IN A 198.51.100.7")],
                    prerequisites=[
                        prereq(
                            "rrset_equals",
                            "test.campus.edu.",
                            "MX",
                            ["test.campus.edu. 0 IN MX 10 mxtarget.campus.edu."],
                        )
                    ],
                    description="Add an A record only if the MX RRset matches a lower-case presentation of the stored MX.",
                ),
                query("q1", "added-if-mx-match.campus.edu.", "A",
                      "Observe whether the MX prerequisite was considered satisfied."),
                update(
                    "u2",
                    [add_rr("added-if-txt-match.campus.edu. 500 IN A 198.51.100.8")],
                    prerequisites=[
                        prereq(
                            "rrset_equals",
                            "test.campus.edu.",
                            "TXT",
                            ['test.campus.edu. 0 IN TXT "mixed-text"'],
                        )
                    ],
                    description="Add an A record only if the TXT RRset matches a lower-case presentation of the stored TXT.",
                ),
                query("q2", "added-if-txt-match.campus.edu.", "A",
                      "Observe whether the TXT prerequisite was considered satisfied."),
            ],
            notes="This canonical scenario replaces the earlier ad hoc UPDATE list with explicit follow-up observations.",
        ),
    )


if __name__ == "__main__":
    main()
