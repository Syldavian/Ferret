"""
Runs tests with valid zone files on different implementations.
Either compares responses from multiple implementations with each other or uses an
expected response to flag differences (only when one implementation is passed for testing).
"""
#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import time
from argparse import (SUPPRESS, ArgumentDefaultsHelpFormatter, ArgumentParser,
                      ArgumentTypeError, Namespace)
from datetime import datetime
from multiprocessing import Process
from typing import Any, Dict, List, Optional, TextIO, Tuple, Union

import dns.exception
import dns.flags
import dns.message
import dns.query
from Implementations.Bind.prepare import run as bind
from Implementations.Coredns.prepare import run as coredns
from Implementations.Knot.prepare import run as knot
from Implementations.Maradns.prepare import run as maradns
from Implementations.Nsd.prepare import run as nsd
from Implementations.Powerdns.prepare import run as powerdns
from Implementations.Technitium.prepare import run as technitium
from Implementations.Trustdns.prepare import run as trustdns
from Implementations.Yadifa.prepare import run as yadifa
from Scripts.dynamic_update import (
    DynamicUpdateScenario,
    QueryStep,
    UpdateStep,
    build_update_message,
    json_key,
    load_scenario,
    message_to_jsonable,
    normalize_query_result,
    normalize_update_reply,
    operation_shape,
    prerequisite_shape,
    scenario_to_jsonable,
    send_update,
)

ZONE_FILES = "ZoneFiles/"
QUERIES = "Queries/"
QUERY_RESPONSES = "ExpectedResponses/"
DIFFERENCES = "Differences/"
LOAD_FAILURES = "LoadFailures/"
TRANSCRIPTS = "Transcripts/"
UNSIGNED_DYNAMIC_UPDATE_IMPLEMENTATIONS = {"bind", "knot", "yadifa", "technitium"}
TSIG_DYNAMIC_UPDATE_IMPLEMENTATIONS = {"bind", "knot", "trustdns"}
POST_UPDATE_SETTLE_SECONDS = {"technitium": 1.0}

ResponseType = Tuple[str, Union[str, dns.message.Message]]


def get_ports(input_args: Namespace) -> Dict[str, Tuple[bool, int]]:
    implementations = {}
    implementations["bind"] = (not input_args.b, 8000)
    implementations["nsd"] = (not input_args.n, 8100)
    implementations["knot"] = (not input_args.k, 8200)
    implementations["powerdns"] = (not input_args.p, 8300)
    implementations["yadifa"] = (not input_args.y, 8400)
    implementations["coredns"] = (not input_args.c, 8500)
    implementations["maradns"] = (not input_args.m, 8600)
    implementations["trustdns"] = (not input_args.t, 8700)
    implementations["technitium"] = (not input_args.e, 8800)
    return implementations


def remove_container(cid: int) -> None:
    cmd_status = subprocess.run(
        ["docker", "ps", "-a", "--format", '"{{.Names}}"'], stdout=subprocess.PIPE, check=False)
    output = cmd_status.stdout.decode("utf-8")
    if cmd_status.returncode != 0:
        sys.exit(f"Error in executing Docker ps command: {output}")
    all_container_names = [name[1:-1] for name in output.strip().split("\n") if name]
    servers = [
        "_bind_server",
        "_nsd_server",
        "_knot_server",
        "_powerdns_server",
        "_maradns_server",
        "_yadifa_server",
        "_trustdns_server",
        "_coredns_server",
        "_technitium_server",
    ]
    for server in servers:
        if str(cid) + server in all_container_names:
            subprocess.run(["docker", "container", "rm", str(cid) + server, "-f"],
                           stdout=subprocess.PIPE, check=False)


def start_containers(cid: int, implementations: Dict[str, Tuple[bool, int]], tag: str) -> None:
    remove_container(cid)
    for impl, (check, port) in implementations.items():
        if not check:
            continue
        if impl == "technitium":
            subprocess.run(
                ["docker", "run", "-dp", str(port * cid) + ":53/udp", "-p", f"{str(port * cid + 1)}:5380/tcp",
                 "--name=" + str(cid) + "_" + impl + "_server", impl + tag],
                check=True,
            )
        else:
            subprocess.run(
                ["docker", "run", "-dp", str(port * cid) + ":53/udp",
                 "--name=" + str(cid) + "_" + impl + "_server", impl + tag],
                check=True,
            )


def querier(query_name: str, query_type: str, port: int,
            transport: str = "udp") -> Union[str, dns.message.Message]:
    domain = dns.name.from_text(query_name)
    addr = "127.0.0.1"
    try:
        query = dns.message.make_query(domain, query_type)
        query.flags = 0
        if transport.lower() == "tcp":
            return dns.query.tcp(query, addr, 3, port=port, ignore_trailing=True)
        return dns.query.udp(query, addr, 3, port=port, ignore_trailing=True)
    except dns.exception.Timeout:
        return "No response"
    except Exception as exc:  # pylint: disable=broad-except
        return f"Unexpected error {exc}"


def container_debug(cname: str) -> Dict[str, str]:
    debug: Dict[str, str] = {}
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", cname],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True,
    )
    if inspect.returncode == 0:
        debug["container_state"] = inspect.stdout.strip()
    else:
        debug["container_state"] = inspect.stderr.strip() or "inspect failed"

    log_paths = []
    if "_bind_" in cname:
        log_paths.extend(["/var/log/named.log", "/usr/local/var/log/named.log"])
    if "_knot_" in cname:
        log_paths.append("/var/log/knot.log")
    if "_yadifa_" in cname:
        log_paths.extend([
            "/usr/local/var/log/yadifa/system.log",
            "/usr/local/var/log/yadifa/server.log",
            "/usr/local/var/log/yadifa/all.log",
        ])
    if "_trustdns_" in cname:
        log_paths.append("/var/log/hickory-dns.log")
    if "_powerdns_" in cname:
        log_paths.append("/usr/local/var/log/pdns_server.log")
    if "_coredns_" in cname:
        log_paths.append("/go/coredns/coredns.log")
    for path in log_paths:
        tail = subprocess.run(
            ["docker", "exec", cname, "sh", "-lc", f"tail -n 100 {path}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True,
        )
        key = f"log_tail:{path}"
        if tail.returncode == 0:
            debug[key] = tail.stdout.strip()
        else:
            debug[key] = tail.stderr.strip() or f"tail failed for {path}"
    return debug


def response_equality_check(response_a: Union[str, dns.message.Message],
                            response_b: Union[str, dns.message.Message]) -> bool:
    if type(response_a) != type(response_b):
        return False
    if isinstance(response_a, str):
        return response_a == response_b
    if response_a.rcode() != response_b.rcode():
        return False
    a_flags = dns.flags.to_text(response_a.flags).split()
    if "RA" in a_flags:
        a_flags.remove("RA")
    b_flags = dns.flags.to_text(response_b.flags).split()
    if "RA" in b_flags:
        b_flags.remove("RA")
    if a_flags != b_flags:
        return False

    def check_section(section_a, section_b):
        for record in section_a:
            if record not in section_b:
                return False
        for record in section_b:
            if record not in section_a:
                return False
        return True

    if not check_section(response_a.question, response_b.question):
        return False
    if not check_section(response_a.answer, response_b.answer):
        return False
    if not check_section(response_a.additional, response_b.additional):
        return False
    if not (len(response_a.answer) and len(response_b.answer)):
        return check_section(response_a.authority, response_b.authority)
    return True


def group_responses(responses: List[ResponseType]) -> List[List[ResponseType]]:
    groups: List[List[ResponseType]] = []
    for response in responses:
        found = False
        for group in groups:
            if response_equality_check(group[0][1], response[1]):
                group.append(response)
                found = True
                break
        if not found:
            groups.append([response])
    return groups


def groups_to_json(groups: List[List[ResponseType]]) -> List[Dict[str, Any]]:
    tmp = []
    for same_response_group in groups:
        servers = ""
        for server in same_response_group:
            servers += server[0] + " "
        group = {}
        group["Server/s"] = servers
        group["Response"] = (
            same_response_group[0][1]
            if isinstance(same_response_group[0][1], str)
            else same_response_group[0][1].to_text().split("\n")
        )
        tmp.append(group)
    return tmp


def group_normalized(items: List[Tuple[str, Any, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    for implementation, normalized, sample in items:
        key = json_key(normalized)
        if key not in groups:
            groups[key] = {
                "servers": [],
                "normalized": normalized,
                "sample": sample,
            }
        groups[key]["servers"].append(implementation)
    ordered_groups = list(groups.values())
    ordered_groups.sort(key=lambda group: (-len(group["servers"]), " ".join(group["servers"])))
    return ordered_groups


def normalized_groups_to_json(groups: List[Dict[str, Any]],
                              value_key: str,
                              sample_key: str) -> List[Dict[str, Any]]:
    payload = []
    for group in groups:
        payload.append(
            {
                "Server/s": " ".join(group["servers"]) + " ",
                value_key: group["normalized"],
                sample_key: group["sample"],
            }
        )
    return payload


def prepare_containers(zone_file: pathlib.Path,
                       zone_domain: str,
                       cid: int,
                       restart: bool,
                       implementations: Dict[str, Tuple[bool, int]],
                       tag: str,
                       auth: Optional[Dict[str, Any]] = None) -> None:
    process_pool = []
    for impl, (check, port) in implementations.items():
        if check:
            if auth is not None and impl in {"bind", "knot", "trustdns"}:
                args = (zone_file, zone_domain, str(cid) + "_" + impl + "_server", port * cid, restart, tag, auth)
            else:
                args = (zone_file, zone_domain, str(cid) + "_" + impl + "_server", port * cid, restart, tag)
            process_pool.append(
                Process(
                    target=globals()[impl],
                    args=args,
                )
            )
    for process in process_pool:
        process.start()
    for process in process_pool:
        process.join()


def get_queries(zoneid: str,
                num_implementations: int,
                directory_path: pathlib.Path,
                log_fp: TextIO,
                errors: Dict[str, str]) -> List[Dict[str, Any]]:
    if num_implementations == 1:
        if not (directory_path / QUERY_RESPONSES).exists():
            log_fp.write(
                f"{datetime.now()}\tNo {QUERY_RESPONSES} directory with expected responses exists\n")
            errors[zoneid] = f"No {QUERY_RESPONSES} directory with expected responses exists"
            return []
        if not (directory_path / QUERY_RESPONSES / (zoneid + ".json")).exists():
            log_fp.write(
                f"{datetime.now()}\tThere is no {zoneid}.json expected responses file in {QUERY_RESPONSES}\n")
            errors[zoneid] = (
                f"There is no {zoneid}.json expected responses file in {QUERY_RESPONSES} directory\n"
            )
            return []
        with open(directory_path / QUERY_RESPONSES / (zoneid + ".json"), "r") as query_resp_fp:
            return json.load(query_resp_fp)
    if not (directory_path / QUERIES).exists():
        log_fp.write(f"{datetime.now()}\tThere is no {QUERIES} directory\n")
        errors[zoneid] = f"There is no {QUERIES} directory\n"
        return []
    if not (directory_path / QUERIES / (zoneid + ".json")).exists():
        log_fp.write(f"{datetime.now()}\tThere is no {zoneid}.json queries file in {QUERIES}\n")
        errors[zoneid] = f"There is no {zoneid}.json queries file in {QUERIES} directory\n"
        return []
    with open(directory_path / QUERIES / (zoneid + ".json"), "r") as query_fp:
        return json.load(query_fp)


def get_zone_metadata(zone_path: pathlib.Path) -> Tuple[bool, str]:
    has_dname = False
    zone_domain = ""
    with open(zone_path, "r") as zone_fp:
        for line in zone_fp:
            stripped = line.strip()
            if not stripped or stripped.startswith(";") or stripped.startswith("#"):
                continue
            if "DNAME" in stripped:
                has_dname = True
            if zone_domain or "SOA" not in stripped:
                continue
            if line[:1].isspace():
                continue
            tokens = stripped.split()
            if tokens:
                zone_domain = tokens[0]
    return has_dname, zone_domain


def wait_for_implementations(zoneid: str,
                             zone_domain: str,
                             cid: int,
                             implementations: Dict[str, Tuple[bool, int]],
                             log_fp: TextIO) -> Dict[str, Dict[str, str]]:
    load_failures: Dict[str, Dict[str, str]] = {}
    for impl, (check, port) in implementations.items():
        if not check:
            continue
        deadline = time.time() + 5
        ready = False
        last_resp: Optional[Union[str, dns.message.Message]] = None
        while time.time() < deadline:
            ready_resp = querier(zone_domain, "SOA", port * int(cid))
            if isinstance(ready_resp, dns.message.Message) and ready_resp.rcode() == 0:
                ready = True
                break
            last_resp = ready_resp
            time.sleep(0.5)
        if not ready:
            log_fp.write(
                f"{datetime.now()}\t{impl} not ready for zone {zoneid}, last response: {last_resp}\n")
            implementations[impl] = (False, port)
            cname = f"{cid}_{impl}_server"
            debug = container_debug(cname)
            load_failures[impl] = {
                "last_response": "No response" if last_resp is None else str(last_resp),
                "container": cname,
                **debug,
            }
    return load_failures


def filter_implementations_for_scenario(
    implementations: Dict[str, Tuple[bool, int]],
    has_dname: bool,
    scenario: Optional[DynamicUpdateScenario],
    log_fp: TextIO,
) -> Dict[str, Tuple[bool, int]]:
    filtered = copy.deepcopy(implementations)
    if has_dname:
        for unsupported_dname_impl in ("yadifa", "trustdns", "maradns"):
            filtered[unsupported_dname_impl] = (False, filtered[unsupported_dname_impl][1])
    if scenario and scenario.has_updates:
        auth_mode = scenario.auth.get("Mode", "none")
        supported_implementations = (
            TSIG_DYNAMIC_UPDATE_IMPLEMENTATIONS if auth_mode == "tsig"
            else UNSIGNED_DYNAMIC_UPDATE_IMPLEMENTATIONS
        )
        for impl, (check, port) in list(filtered.items()):
            if check and impl not in supported_implementations:
                log_fp.write(
                    f"{datetime.now()}\tSkipping {impl} for dynamic update scenario "
                    f"(auth mode {auth_mode} supports {', '.join(sorted(supported_implementations))})\n")
                filtered[impl] = (False, port)
    return filtered


def maybe_restart_container(zone_path: pathlib.Path,
                            zone_domain: str,
                            cid: int,
                            tag: str,
                            implementations: Dict[str, Tuple[bool, int]],
                            impl: str,
                            log_fp: TextIO,
                            zoneid: str,
                            auth: Optional[Dict[str, Any]] = None) -> None:
    single_impl = {impl: implementations[impl]}
    prepare_containers(zone_path, zone_domain, cid, True, single_impl, tag, auth=auth)
    log_fp.write(f"{datetime.now()}\tRestarted {impl}'s container while testing zone {zoneid}\n")
    time.sleep(1)


def run_stateless_queries(zoneid: str,
                          parent_directory_path: pathlib.Path,
                          errors: Dict[str, str],
                          cid: int,
                          implementations: Dict[str, Tuple[bool, int]],
                          log_fp: TextIO,
                          tag: str,
                          queries: List[Dict[str, Any]],
                          zone_domain: str) -> List[Dict[str, Any]]:
    differences = []
    zone_path = parent_directory_path / ZONE_FILES / (zoneid + ".txt")
    for query in queries:
        qtype = query.get("Query", {}).get("Type")
        if qtype == "UPDATE" or "Name" not in query.get("Query", {}):
            log_fp.write(f"{datetime.now()}\tSkipping UPDATE query for zone {zoneid} (unsupported)\n")
            continue
        qname = query["Query"]["Name"]
        responses = []
        for impl, (check, port) in implementations.items():
            if not check:
                continue
            respo = querier(qname, qtype, port * int(cid))
            if not isinstance(respo, dns.message.Message):
                maybe_restart_container(zone_path, zone_domain, cid, tag, implementations, impl, log_fp, zoneid)
                respo = querier(qname, qtype, port * int(cid))
            responses.append((impl, respo))
        if len(responses) == 1:
            exp_resps = query["Expected Response"]
            for exp_res in exp_resps:
                responses.append((exp_res["Server/s"], dns.message.from_text("\n".join(exp_res["Response"]))))
        groups = group_responses(responses)
        if len(groups) > 1:
            differences.append(
                {
                    "Query Name": qname,
                    "Query Type": qtype,
                    "Groups": groups_to_json(groups),
                }
            )
    return differences


def build_dynamic_differences(scenario: DynamicUpdateScenario,
                              active_implementations: List[str],
                              results_by_impl: Dict[str, Dict[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    differences: List[Dict[str, Any]] = []
    update_indexes = [idx for idx, step in enumerate(scenario.steps) if isinstance(step, UpdateStep)]
    for pos, update_index in enumerate(update_indexes):
        update_step = scenario.steps[update_index]
        assert isinstance(update_step, UpdateStep)
        next_update_index = update_indexes[pos + 1] if pos + 1 < len(update_indexes) else len(scenario.steps)
        query_steps = [
            step for step in scenario.steps[update_index + 1:next_update_index]
            if isinstance(step, QueryStep)
        ]
        reply_items: List[Tuple[str, Any, Any]] = []
        post_state_items: List[Tuple[str, Any, Any]] = []
        for impl in active_implementations:
            update_result = results_by_impl[impl].get(update_step.id, {})
            reply_items.append((
                impl,
                update_result.get("NormalizedReply", {"outcome": "missing"}),
                update_result.get("RawReply", "missing"),
            ))
            observation_vector = []
            for query_step in query_steps:
                query_result = results_by_impl[impl].get(query_step.id, {})
                observation_vector.append(
                    {
                        "StepId": query_step.id,
                        "Name": query_step.name,
                        "Type": query_step.type,
                        "Result": query_result.get("Normalized", {"outcome": "missing"}),
                    }
                )
            post_state_items.append((impl, observation_vector, observation_vector))
        reply_groups = group_normalized(reply_items)
        post_state_groups = group_normalized(post_state_items)
        reply_diverges = len(reply_groups) > 1
        post_state_diverges = len(post_state_groups) > 1
        if not reply_diverges and not post_state_diverges:
            continue
        if reply_diverges and post_state_diverges:
            divergence_kind = "reply_and_post_state"
        elif reply_diverges:
            divergence_kind = "reply_only"
        else:
            divergence_kind = "post_state_only"
        fingerprint_seed = {
            "scenario_category": scenario.category,
            "auth_mode": scenario.auth.get("Mode", "none"),
            "prerequisite_shape": prerequisite_shape(update_step),
            "operation_shape": operation_shape(update_step),
            "divergence_kind": divergence_kind,
        }
        differences.append(
            {
                "Type": "DynamicUpdate",
                "Update Step": update_step.id,
                "Description": update_step.description,
                "Scenario Category": scenario.category,
                "Auth Mode": scenario.auth.get("Mode", "none"),
                "Prerequisite Shape": prerequisite_shape(update_step),
                "Operation Shape": operation_shape(update_step),
                "Observation Steps": [query_step.id for query_step in query_steps],
                "Reply Groups": normalized_groups_to_json(reply_groups, "Reply", "Sample Reply"),
                "Post-State Groups": normalized_groups_to_json(post_state_groups, "Post State", "Sample Post State"),
                "Divergence Kind": divergence_kind,
                "Fingerprint Seed": fingerprint_seed,
            }
        )
    return differences


def execute_scenario(zoneid: str,
                     scenario: DynamicUpdateScenario,
                     zone_path: pathlib.Path,
                     zone_domain: str,
                     cid: int,
                     implementations: Dict[str, Tuple[bool, int]],
                     log_fp: TextIO,
                     tag: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    transcript: Dict[str, Any] = {
        "ZoneId": zoneid,
        "Origin": zone_domain,
        "Scenario": scenario_to_jsonable(scenario),
        "Implementations": {},
    }
    active_implementations = [impl for impl, (check, _) in implementations.items() if check]
    results_by_impl: Dict[str, Dict[str, Dict[str, Any]]] = {
        impl: {} for impl in active_implementations
    }
    update_executed = {impl: False for impl in active_implementations}
    aborted = {impl: False for impl in active_implementations}
    legacy_differences: List[Dict[str, Any]] = []

    for impl in active_implementations:
        transcript["Implementations"][impl] = {
            "steps": [],
            "errors": [],
        }

    for step in scenario.steps:
        if isinstance(step, QueryStep):
            raw_responses: List[ResponseType] = []
            for impl in active_implementations:
                restarted = False
                if aborted[impl]:
                    response: Union[str, dns.message.Message] = "Skipped after prior stateful failure"
                else:
                    port = implementations[impl][1] * int(cid)
                    response = querier(step.name, step.type, port, transport=step.transport)
                    if not isinstance(response, dns.message.Message) and not update_executed[impl]:
                        maybe_restart_container(
                            zone_path, zone_domain, cid, tag, implementations, impl, log_fp, zoneid, auth=scenario.auth
                        )
                        response = querier(step.name, step.type, port, transport=step.transport)
                        restarted = True
                    elif not isinstance(response, dns.message.Message):
                        aborted[impl] = True
                        transcript["Implementations"][impl]["errors"].append(
                            f"Stateful scenario aborted after query failure on step {step.id}: {response}"
                        )
                normalized = normalize_query_result(response, mode=step.normalize, ignore_ttl=step.ignore_ttl)
                result_entry = {
                    "StepId": step.id,
                    "Kind": "QUERY",
                    "Name": step.name,
                    "Type": step.type,
                    "Transport": step.transport,
                    "Restarted": restarted,
                    "Raw": message_to_jsonable(response),
                    "Normalized": normalized,
                }
                transcript["Implementations"][impl]["steps"].append(result_entry)
                results_by_impl[impl][step.id] = result_entry
                if not aborted[impl] or isinstance(response, dns.message.Message):
                    raw_responses.append((impl, response))
            if not scenario.has_updates:
                groups = group_responses(raw_responses)
                if len(groups) > 1:
                    legacy_differences.append(
                        {
                            "Query Name": step.name,
                            "Query Type": step.type,
                            "Groups": groups_to_json(groups),
                        }
                    )
            continue

        assert isinstance(step, UpdateStep)
        for impl in active_implementations:
            if aborted[impl]:
                result_entry = {
                    "StepId": step.id,
                    "Kind": "UPDATE",
                    "Transport": step.transport,
                    "Request": "Skipped after prior stateful failure",
                    "RawReply": "Skipped after prior stateful failure",
                    "NormalizedReply": {"outcome": "Skipped after prior stateful failure"},
                }
                transcript["Implementations"][impl]["steps"].append(result_entry)
                results_by_impl[impl][step.id] = result_entry
                continue
            port = implementations[impl][1] * int(cid)
            try:
                update_request = build_update_message(scenario.origin, step, scenario.auth)
                reply = send_update(update_request, port, transport=step.transport)
            except Exception as exc:  # pylint: disable=broad-except
                update_request = None
                reply = f"Update construction error {exc}"
            update_executed[impl] = True
            if not isinstance(reply, dns.message.Message):
                aborted[impl] = True
                transcript["Implementations"][impl]["errors"].append(
                    f"Stateful scenario aborted after update failure on step {step.id}: {reply}"
                )
            result_entry = {
                "StepId": step.id,
                "Kind": "UPDATE",
                "Transport": step.transport,
                "Description": step.description,
                "Request": message_to_jsonable(update_request) if isinstance(update_request, dns.message.Message) else str(update_request),
                "RawReply": message_to_jsonable(reply),
                "NormalizedReply": normalize_update_reply(reply),
            }
            transcript["Implementations"][impl]["steps"].append(result_entry)
            results_by_impl[impl][step.id] = result_entry
            if isinstance(reply, dns.message.Message):
                settle_seconds = POST_UPDATE_SETTLE_SECONDS.get(impl, 0)
                if settle_seconds > 0:
                    time.sleep(settle_seconds)

    if scenario.has_updates:
        return build_dynamic_differences(scenario, active_implementations, results_by_impl), transcript
    return legacy_differences, transcript


def run_test(zoneid: str,
             parent_directory_path: pathlib.Path,
             errors: Dict[str, str],
             cid: int,
             port_mappings: Dict[str, Tuple[bool, int]],
             log_fp: TextIO,
             tag: str) -> None:
    zone_path = parent_directory_path / ZONE_FILES / (zoneid + ".txt")
    has_dname, zone_domain = get_zone_metadata(zone_path)
    if not zone_domain:
        log_fp.write(f"{datetime.now()}\tSOA not found in {zoneid}\n")
        errors[zoneid] = "SOA not found"
        return

    base_implementations = copy.deepcopy(port_mappings)
    requested_count = sum(check for check, _port in base_implementations.values())
    if requested_count > 1:
        raw_queries = get_queries(zoneid, requested_count, parent_directory_path, log_fp, errors)
        if not raw_queries:
            return
        scenario = load_scenario(raw_queries, zone_domain)
        implementations = filter_implementations_for_scenario(base_implementations, has_dname, scenario, log_fp)
    else:
        scenario = None
        implementations = filter_implementations_for_scenario(base_implementations, has_dname, None, log_fp)

    prepare_containers(zone_path, zone_domain, cid, False, implementations, tag, auth=scenario.auth if scenario else None)
    load_failures = wait_for_implementations(zoneid, zone_domain, cid, implementations, log_fp)
    load_failure_path = parent_directory_path / LOAD_FAILURES / (zoneid + ".json")
    if load_failures:
        with open(load_failure_path, "w") as lf_fp:
            json.dump(load_failures, lf_fp, indent=2)
    elif load_failure_path.exists():
        load_failure_path.unlink()

    total_impl_tested = sum(check for check, _port in implementations.values())
    if total_impl_tested == 0:
        log_fp.write(f"{datetime.now()}\tNo implementations available for zone {zoneid}\n")
        errors[zoneid] = "No implementations available after capability filtering"
        return

    if total_impl_tested == 1 and scenario is None:
        queries = get_queries(zoneid, total_impl_tested, parent_directory_path, log_fp, errors)
        if not queries:
            return
        difference_path = parent_directory_path / DIFFERENCES / (zoneid + ".json")
        differences = run_stateless_queries(
            zoneid,
            parent_directory_path,
            errors,
            cid,
            implementations,
            log_fp,
            tag,
            queries,
            zone_domain,
        )
        if differences:
            with open(difference_path, "w") as difference_fp:
                json.dump(differences, difference_fp, indent=2)
        elif difference_path.exists():
            difference_path.unlink()
        return

    if scenario is None:
        log_fp.write(f"{datetime.now()}\tNo scenario loaded for zone {zoneid}\n")
        errors[zoneid] = "No scenario loaded"
        return
    differences, transcript = execute_scenario(
        zoneid,
        scenario,
        zone_path,
        zone_domain,
        cid,
        implementations,
        log_fp,
        tag,
    )
    if scenario.has_updates:
        with open(parent_directory_path / TRANSCRIPTS / (zoneid + ".json"), "w") as transcript_fp:
            json.dump(transcript, transcript_fp, indent=2)
    difference_path = parent_directory_path / DIFFERENCES / (zoneid + ".json")
    if differences:
        with open(difference_path, "w") as difference_fp:
            json.dump(differences, difference_fp, indent=2)
    elif difference_path.exists():
        difference_path.unlink()


def run_tests(parent_directory_path: pathlib.Path,
              start: int,
              end: Optional[int],
              input_args: Namespace) -> None:
    errors: Dict[str, str] = {}
    i = 0
    timer = time.time()
    sub_timer = time.time()
    implementations = get_ports(input_args)
    tag = ":latest" if input_args.latest else ":oct"
    start_containers(input_args.id, implementations, tag)
    (parent_directory_path / LOAD_FAILURES).mkdir(exist_ok=True)
    (parent_directory_path / TRANSCRIPTS).mkdir(exist_ok=True)
    with open(parent_directory_path / (str(input_args.id) + "_log.txt"), "w", 1) as log_fp:
        def _zone_sort_key(path: pathlib.Path):
            stem = path.stem
            try:
                return (0, int(stem))
            except ValueError:
                return (1, stem)

        for zone in sorted((parent_directory_path / ZONE_FILES).iterdir(), key=_zone_sort_key)[start:end]:
            log_fp.write(f"{datetime.now()}\tChecking zone: {zone.stem}\n")
            run_test(zone.stem, parent_directory_path, errors, input_args.id, implementations, log_fp, tag)
            i += 1
            if i % 25 == 0:
                log_fp.write(
                    f"{datetime.now()}\tTime taken for {start + i - 25} - {start + i}: "
                    f"{time.time() - sub_timer}s\n")
                sub_timer = time.time()
        log_fp.write(
            f"{datetime.now()}\tTotal time for checking from {start}-{end if end else i}: "
            f"{time.time() - timer}s\n")
        log_fp.write("Errors:\n")
        log_fp.write(str(errors))
        remove_container(input_args.id)


def check_non_negative(value: str) -> int:
    ivalue = int(value)
    if ivalue < 0:
        raise ArgumentTypeError(f"{value} is an invalid range value")
    return ivalue


if __name__ == "__main__":
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="Runs tests with valid zone files on different implementations. "
        "Either compares responses from multiple implementations with each other or uses "
        "an expected response to flag differences (only when one implementation is passed for testing)",
    )
    parser.add_argument("-path", metavar="DIRECTORY_PATH", default=SUPPRESS,
                        help="The path to the directory containing ZoneFiles and either Queries or "
                        "ExpectedResponses directories. (default: Results/ValidZoneFileTests/)")
    parser.add_argument("-id", type=int, default=1, choices=range(1, 6),
                        help="Unique id for all the containers (useful when running comparison in parallel).")
    parser.add_argument("-r", nargs=2, type=check_non_negative, metavar=("START", "END"),
                        default=SUPPRESS, help="The range of tests to compare. (default: All tests)")
    parser.add_argument("-b", help="Disable Bind.", action="store_true")
    parser.add_argument("-n", help="Disable Nsd.", action="store_true")
    parser.add_argument("-k", help="Disable Knot.", action="store_true")
    parser.add_argument("-p", help="Disable PowerDns.", action="store_true")
    parser.add_argument("-c", help="Disable CoreDns.", action="store_true")
    parser.add_argument("-y", help="Disable Yadifa.", action="store_true")
    parser.add_argument("-m", help="Disable MaraDns.", action="store_true")
    parser.add_argument("-t", help="Disable TrustDns.", action="store_true")
    parser.add_argument("-e", help="Disable Technitium.", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--latest", help="Test using latest image tag (default).", action="store_true")
    group.add_argument("--oct", help="Test using oct image tag instead of latest.", action="store_true")

    args = parser.parse_args()
    if args.oct:
        args.latest = False
    elif not args.latest:
        args.latest = True

    dir_path = pathlib.Path(args.path) if "path" in args else pathlib.Path("Results/ValidZoneFileTests")
    if not (dir_path / ZONE_FILES).exists():
        sys.exit(f"The directory {dir_path} does not have ZoneFiles directory")
    checked_implementations = (not args.b) + (not args.n) + (not args.k) + \
        (not args.p) + (not args.c) + (not args.y) + (not args.m) + (not args.t) + (not args.e)
    if checked_implementations == 0:
        sys.exit("Enable at least one implementation")
    if checked_implementations < 2 and not (dir_path / QUERY_RESPONSES).exists():
        sys.exit("Either choose at least two implementations to perform differential testing or "
                 f'the directory "{dir_path}" should have ExpectedResponses directory')
    if not (dir_path / QUERIES).exists() and not (dir_path / QUERY_RESPONSES).exists():
        sys.exit(f'There is no Queries or ExpectedResponses directory in "{dir_path}".')
    if "r" in args:
        START = args.r[0]
        END = args.r[1]
    else:
        START = 0
        END = None
    (dir_path / DIFFERENCES).mkdir(parents=True, exist_ok=True)
    run_tests(dir_path, START, END, args)
