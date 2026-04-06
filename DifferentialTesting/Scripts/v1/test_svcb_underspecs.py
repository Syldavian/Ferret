#!/usr/bin/env python3
"""
Run SVCB/HTTPS underspec tests with preprocessor gating.

Workflow:
1) Run preprocessor checks (bind/nsd/knot/powerdns) on each zone file.
2) For implementations that accept the zone, load the zone and issue queries.
3) Record per-implementation responses including raw HTTPS/SVCB RDATA bytes.

Usage:
  python3 Scripts/test_svcb_underspecs.py -path CustomTests/SVCBUnderspecs
"""

from __future__ import annotations

import json
import socket
import struct
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from multiprocessing import Process
from pathlib import Path
from typing import Any, Dict, List, Tuple

import dns.message
import dns.rdatatype
import dns.rcode

from Scripts import preprocessor_checks
from Implementations.Bind.prepare import run as bind
from Implementations.Nsd.prepare import run as nsd
from Implementations.Knot.prepare import run as knot
from Implementations.Powerdns.prepare import run as powerdns

ZONE_FILES = "ZoneFiles"
QUERIES = "Queries"
RESULTS = "Results"

IMPLS = ("bind", "nsd", "knot", "powerdns")
PREPROCESSOR_KEY = {
    "bind": "Bind",
    "nsd": "Nsd",
    "knot": "Knot",
    "powerdns": "Powerdns",
}
SVCB_TYPES = {
    getattr(dns.rdatatype, "SVCB", 64),
    getattr(dns.rdatatype, "HTTPS", 65),
}
SVCB_KEY_NAMES = {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "ech",
    6: "ipv6hint",
}


def get_ports(input_args: Namespace) -> Dict[str, Tuple[bool, int]]:
    implementations: Dict[str, Tuple[bool, int]] = {}
    implementations["bind"] = (not input_args.b, 8000)
    implementations["nsd"] = (not input_args.n, 8100)
    implementations["knot"] = (not input_args.k, 8200)
    implementations["powerdns"] = (not input_args.p, 8300)
    return implementations


def read_zone_origin(zone_path: Path) -> str:
    origin = ""
    with zone_path.open("r", encoding="utf-8") as zone_fp:
        for line in zone_fp:
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            if "SOA" not in stripped:
                continue
            if stripped[:1].isspace():
                continue
            tokens = stripped.split()
            if tokens:
                origin = tokens[0]
                break
    return origin


def prepare_containers(zone_file: Path,
                       zone_domain: str,
                       cid: int,
                       restart: bool,
                       implementations: Dict[str, Tuple[bool, int]],
                       tag: str) -> None:
    runners = {
        "bind": bind,
        "nsd": nsd,
        "knot": knot,
        "powerdns": powerdns,
    }
    procs: List[Process] = []
    for impl, (check, port) in implementations.items():
        if not check:
            continue
        runner = runners[impl]
        procs.append(
            Process(
                target=runner,
                args=(zone_file, zone_domain, f"{cid}_{impl}_server", port * cid, restart, tag),
            )
        )
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()


def read_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original_offset = offset
    seen = 0
    while True:
        if offset >= len(data):
            return ("<name-out-of-bounds>", offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return ("<name-pointer-oob>", offset + 1)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            seen += 1
            if seen > 20:
                return ("<name-pointer-loop>", original_offset)
            continue
        offset += 1
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length
    name = ".".join(labels) + "."
    return (name, original_offset if jumped else offset)


def read_name_no_compression(data: bytes, offset: int) -> Tuple[str, int, str]:
    labels: List[str] = []
    while True:
        if offset >= len(data):
            return ("<name-out-of-bounds>", offset, "out-of-bounds")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            return ("<compressed-name>", offset, "compression-not-supported")
        if offset + length > len(data):
            return ("<label-out-of-bounds>", offset, "label-out-of-bounds")
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length
    return (".".join(labels) + ".", offset, "")


def read_rr(data: bytes, offset: int) -> Tuple[Dict[str, Any], int, str]:
    name, offset = read_name(data, offset)
    if offset + 10 > len(data):
        return ({"name": name}, offset, "rr-header-out-of-bounds")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    if offset + rdlen > len(data):
        return ({"name": name, "type": rtype, "class": rclass, "ttl": ttl}, offset,
                "rdata-out-of-bounds")
    rdata = data[offset:offset + rdlen]
    offset += rdlen
    rr = {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdata_hex": rdata.hex(),
    }
    return (rr, offset, "")


def parse_svcb_rdata(rdata: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if len(rdata) < 3:
        result["error"] = "rdata-too-short"
        return result
    priority = struct.unpack("!H", rdata[:2])[0]
    target, offset, name_err = read_name_no_compression(rdata, 2)
    result["priority"] = priority
    result["target"] = target
    if name_err:
        result["target_error"] = name_err
        result["params"] = []
        return result
    params = []
    while offset < len(rdata):
        if offset + 4 > len(rdata):
            result["params_error"] = "param-header-out-of-bounds"
            break
        key = struct.unpack("!H", rdata[offset:offset + 2])[0]
        length = struct.unpack("!H", rdata[offset + 2:offset + 4])[0]
        offset += 4
        if offset + length > len(rdata):
            result["params_error"] = "param-value-out-of-bounds"
            break
        value = rdata[offset:offset + length]
        offset += length
        params.append({
            "key": key,
            "key_name": SVCB_KEY_NAMES.get(key, "unknown"),
            "length": length,
            "value_hex": value.hex(),
        })
    result["params"] = params
    result["param_keys"] = [p["key"] for p in params]
    return result


def parse_dns_message(data: bytes) -> Dict[str, Any]:
    if len(data) < 12:
        return {"error": "message-too-short"}
    (msg_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    aa = bool(flags & 0x0400)
    tc = bool(flags & 0x0200)
    offset = 12
    for _ in range(qdcount):
        _, offset = read_name(data, offset)
        if offset + 4 > len(data):
            return {
                "id": msg_id,
                "rcode": rcode,
                "rcode_text": dns.rcode.to_text(rcode),
                "aa": aa,
                "tc": tc,
                "error": "question-out-of-bounds",
            }
        offset += 4
    answers: List[Dict[str, Any]] = []
    authority: List[Dict[str, Any]] = []
    additional: List[Dict[str, Any]] = []
    for _ in range(ancount):
        rr, offset, err = read_rr(data, offset)
        if err:
            return {
                "id": msg_id,
                "rcode": rcode,
                "rcode_text": dns.rcode.to_text(rcode),
                "aa": aa,
                "tc": tc,
                "error": err,
            }
        answers.append(rr)
    for _ in range(nscount):
        rr, offset, err = read_rr(data, offset)
        if err:
            return {
                "id": msg_id,
                "rcode": rcode,
                "rcode_text": dns.rcode.to_text(rcode),
                "aa": aa,
                "tc": tc,
                "error": err,
            }
        authority.append(rr)
    for _ in range(arcount):
        rr, offset, err = read_rr(data, offset)
        if err:
            return {
                "id": msg_id,
                "rcode": rcode,
                "rcode_text": dns.rcode.to_text(rcode),
                "aa": aa,
                "tc": tc,
                "error": err,
            }
        additional.append(rr)

    svcb_rrs = []
    for rr in answers:
        if rr.get("type") in SVCB_TYPES:
            rdata = bytes.fromhex(rr.get("rdata_hex", ""))
            rr["svcb"] = parse_svcb_rdata(rdata)
            svcb_rrs.append(rr)

    return {
        "id": msg_id,
        "rcode": rcode,
        "rcode_text": dns.rcode.to_text(rcode),
        "aa": aa,
        "tc": tc,
        "answer_count": ancount,
        "answer_rrs": answers,
        "svcb_rrs": svcb_rrs,
        "additional_rrs": additional,
    }


def send_query(name: str,
               qtype: str,
               port: int,
               timeout: float,
               bufsize: int,
               dnssec: bool) -> Dict[str, Any]:
    try:
        rdtype = dns.rdatatype.from_text(qtype)
    except Exception:
        if qtype.upper() == "HTTPS":
            rdtype = 65
        elif qtype.upper() == "SVCB":
            rdtype = 64
        else:
            return {"error": f"unsupported qtype: {qtype}"}
    query = dns.message.make_query(name, rdtype)
    query.flags = 0
    ednsflags = dns.flags.DO if dnssec else 0
    query.use_edns(edns=0, payload=bufsize, ednsflags=ednsflags)
    wire = query.to_wire()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(wire, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
        parsed = parse_dns_message(data)
        parsed["raw_message_hex"] = data.hex()
        return parsed
    except socket.timeout:
        return {"error": "timeout"}
    except OSError as exc:
        return {"error": f"socket-error: {exc}"}
    finally:
        sock.close()


def load_queries(queries_path: Path) -> List[Dict[str, Any]]:
    with queries_path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def run_tests(input_args: Namespace) -> None:
    root = Path(input_args.path).resolve()
    zone_dir = root / ZONE_FILES
    query_dir = root / QUERIES
    results_dir = root / RESULTS
    results_dir.mkdir(exist_ok=True)

    if not zone_dir.exists() or not query_dir.exists():
        raise SystemExit(f"Expected {ZONE_FILES}/ and {QUERIES}/ under {root}")

    # Step 1: Preprocessor checks (creates PreprocessorOutputs)
    preprocessor_checks.preprocessor_check_helper(input_args, root)

    tag = ":latest" if input_args.latest else ":oct"
    port_map = get_ports(input_args)

    for zone_path in sorted(zone_dir.iterdir()):
        if not zone_path.is_file():
            continue
        zoneid = zone_path.stem
        preproc_path = root / preprocessor_checks.PREPROCESSOR_DIRECTORY / (zoneid + ".json")
        if not preproc_path.exists():
            print(f"Skipping {zoneid}: no preprocessor output at {preproc_path}")
            continue
        with preproc_path.open("r", encoding="utf-8") as fp:
            preproc = json.load(fp)

        accepted: Dict[str, Tuple[bool, int]] = {}
        for impl, (enabled, port) in port_map.items():
            if not enabled:
                continue
            key = PREPROCESSOR_KEY[impl]
            code = preproc.get(key, {}).get("Code", 1)
            if code == 0:
                accepted[impl] = (True, port)

        result: Dict[str, Any] = {
            "zone_file": zone_path.name,
            "origin": read_zone_origin(zone_path),
            "preprocessor": preproc,
            "accepted": list(accepted.keys()),
            "queries": [],
        }

        if not accepted:
            print(f"{zoneid}: no implementations accepted the zone; skipping queries")
            (results_dir / (zoneid + ".json")).write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
            continue

        if not result["origin"]:
            result["error"] = "SOA not found"
            (results_dir / (zoneid + ".json")).write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
            continue

        prepare_containers(zone_path, result["origin"], input_args.id, False, accepted, tag)
        time.sleep(1)

        queries_path = query_dir / (zoneid + ".json")
        if not queries_path.exists():
            result["error"] = f"Queries file not found: {queries_path}"
            (results_dir / (zoneid + ".json")).write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
            continue
        queries = load_queries(queries_path)

        for q in queries:
            qname = q["Query"]["Name"]
            qtype = q["Query"]["Type"]
            bufsize = int(q["Query"].get("Bufsize", 1232))
            dnssec = bool(q["Query"].get("Dnssec", False))
            query_result: Dict[str, Any] = {
                "query": {
                    "Name": qname,
                    "Type": qtype,
                    "Bufsize": bufsize,
                    "Dnssec": dnssec,
                },
                "responses": {},
            }
            for impl, (check, port) in accepted.items():
                if not check:
                    continue
                resp = send_query(qname, qtype, port * input_args.id, input_args.timeout,
                                  bufsize, dnssec)
                query_result["responses"][impl] = resp
            result["queries"].append(query_result)

        (results_dir / (zoneid + ".json")).write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )

    # Cleanup containers used by preprocessors/servers
    for impl in IMPLS:
        preprocessor_checks.delete_container(f"{input_args.id}_{impl}_server")


def main() -> None:
    default_path = str((Path(__file__).resolve().parents[1] / "CustomTests" / "SVCBUnderspecs").resolve())
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="Run SVCB/HTTPS underspec tests with preprocessor gating.",
    )
    parser.add_argument("-path", default=default_path, help="Path to test directory.")
    parser.add_argument("-id", type=int, default=1, choices=range(1, 6),
                        help="Unique id for all the containers")
    parser.add_argument("-b", action="store_true", help="Disable Bind.")
    parser.add_argument("-n", action="store_true", help="Disable Nsd.")
    parser.add_argument("-k", action="store_true", help="Disable Knot.")
    parser.add_argument("-p", action="store_true", help="Disable PowerDns.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--latest", action="store_true",
                       help="Use latest image tags (default).")
    group.add_argument("--oct", action="store_true",
                       help="Use oct image tags instead of latest.")
    parser.add_argument("--timeout", type=float, default=3.0, help="Query timeout in seconds")
    args = parser.parse_args()
    if args.oct:
        args.latest = False
    elif not args.latest:
        # Default to latest unless --oct is requested.
        args.latest = True
    run_tests(args)


if __name__ == "__main__":
    main()
