"""
Fingerprint and group tests that resulted in differences.

Legacy query-only differences are grouped by model case plus implementation grouping.
Dynamic update differences are grouped both exactly (including scenario category)
and coarsely (by auth/op/prereq shape plus reply/post-state grouping).
"""

from __future__ import annotations

import json
import pathlib
import sys
from argparse import SUPPRESS, ArgumentDefaultsHelpFormatter, ArgumentParser
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from Scripts.test_with_valid_zone_files import DIFFERENCES, QUERIES, QUERY_RESPONSES


def _servers_signature(groups: Iterable[Dict[str, Any]]) -> Tuple[frozenset[str], ...]:
    signature = []
    for group in groups:
        servers = frozenset(group.get("Server/s", "").strip().split())
        if servers:
            signature.append(servers)
    signature.sort(key=lambda item: (len(item), sorted(item)))
    return tuple(signature)


def _load_json(path: pathlib.Path) -> Any:
    with open(path, "r") as fp:
        return json.load(fp)


def get_model_cases(dir_path: pathlib.Path) -> Dict[str, Dict[str, str]]:
    model_cases = defaultdict(dict)  # type: Dict[str, Dict[str, str]]
    queries_dir = dir_path / QUERIES
    expected_res_dir = dir_path / QUERY_RESPONSES
    tag_dir = None
    if queries_dir.exists() and queries_dir.is_dir():
        tag_dir = queries_dir
    elif expected_res_dir.exists() and expected_res_dir.is_dir():
        tag_dir = expected_res_dir
    if isinstance(tag_dir, pathlib.Path):
        for queries_file in tag_dir.iterdir():
            queries_info = _load_json(queries_file)
            if not isinstance(queries_info, list):
                continue
            for qinfo in queries_info:
                if "ZenResponseTag" in qinfo:
                    query_str = qinfo["Query"]["Name"] + ":" + qinfo["Query"]["Type"]
                    model_cases[queries_file.stem][query_str] = qinfo["ZenResponseTag"]
    return model_cases


def _group_sig_to_text(signature: Tuple[frozenset[str], ...]) -> str:
    return " ".join("{" + ",".join(sorted(group)) + "}" for group in signature) or "{all}"


def _summarize_dynamic_exact(vectors: Dict[Any, set]) -> Dict[str, Any]:
    summary: List[str] = []
    output: List[Dict[str, Any]] = []
    for key in sorted(vectors.keys(), key=lambda item: str(item)):
        category, auth_mode, prereq_shape, op_shape, divergence_kind, reply_sig, post_sig = key
        tests = sorted(vectors[key])
        reply_summary = _group_sig_to_text(reply_sig)
        post_summary = _group_sig_to_text(post_sig)
        summary.append(
            f"{category} {auth_mode} {prereq_shape} {op_shape} {divergence_kind} "
            f"reply={reply_summary} post={post_summary} count={len(tests)}"
        )
        output.append(
            {
                "Scenario Category": category,
                "Auth Mode": auth_mode,
                "Prerequisite Shape": prereq_shape,
                "Operation Shape": op_shape,
                "Divergence Kind": divergence_kind,
                "Reply Groups": [sorted(group) for group in reply_sig],
                "Post-State Groups": [sorted(group) for group in post_sig],
                "Count": len(tests),
                "Tests": tests,
            }
        )
    return {"Summary": summary, "Details": output}


def _summarize_dynamic_coarse(vectors: Dict[Any, set]) -> Dict[str, Any]:
    summary: List[str] = []
    output: List[Dict[str, Any]] = []
    for key in sorted(vectors.keys(), key=lambda item: str(item)):
        auth_mode, prereq_shape, op_shape, divergence_kind, reply_sig, post_sig = key
        items = sorted(vectors[key])
        tests = sorted((zoneid, stepid) for zoneid, stepid, _category in items)
        categories = sorted({category for _zoneid, _stepid, category in items})
        reply_summary = _group_sig_to_text(reply_sig)
        post_summary = _group_sig_to_text(post_sig)
        summary.append(
            f"{auth_mode} {prereq_shape} {op_shape} {divergence_kind} "
            f"reply={reply_summary} post={post_summary} count={len(tests)} categories={len(categories)}"
        )
        output.append(
            {
                "Auth Mode": auth_mode,
                "Prerequisite Shape": prereq_shape,
                "Operation Shape": op_shape,
                "Divergence Kind": divergence_kind,
                "Reply Groups": [sorted(group) for group in reply_sig],
                "Post-State Groups": [sorted(group) for group in post_sig],
                "Count": len(tests),
                "Scenario Categories": categories,
                "Tests": tests,
            }
        )
    return {"Summary": summary, "Details": output}


def _summarize_legacy(vectors: Dict[Any, set]) -> Dict[str, Any]:
    summary = []
    output_json = defaultdict(list)
    keys = sorted(vectors.keys(), key=lambda item: str(item))
    model_cases_present = set(key[0] for key in keys)
    for model_case in model_cases_present:
        for key in keys:
            if key[0] != model_case:
                continue
            groups = key[1]
            sorted_groups = sorted(groups, key=len, reverse=True)
            groups_summary = ""
            json_groups = []
            for group in sorted_groups:
                groups_summary += f' {{{",".join(group)}}} '
                json_groups.append(list(group))
            tests = sorted(vectors[key])
            if model_case != "-":
                summary.append(f"{model_case} {len(tests)} {groups_summary}")
                output_json[model_case].append({
                    "Groups": json_groups,
                    "Count": len(tests),
                    "Tests": tests,
                })
            else:
                summary.append(f"{len(tests)} {groups_summary}")
                output_json["Fingerprints"].append({
                    "Groups": json_groups,
                    "Count": len(tests),
                    "Tests": tests,
                })
    return {"Summary": summary, "Details": output_json}


def fingerprint_group_tests(dir_path: pathlib.Path,
                            model_cases: Dict[str, Dict[str, str]]) -> None:
    difference_dir = dir_path / DIFFERENCES
    difference_zones = [path for path in difference_dir.iterdir() if path.is_file() and path.suffix == '.json']
    has_model_cases = [zone.stem in model_cases for zone in difference_zones]
    if difference_zones and not all(has_model_cases) and any(has_model_cases):
        sys.exit(f"Some of the tests have model cases and others do not in {dir_path}")

    legacy_vectors = defaultdict(set)
    dynamic_exact_vectors = defaultdict(set)
    dynamic_coarse_vectors = defaultdict(set)

    for diff in difference_zones:
        diff_json = _load_json(diff)
        zoneid = diff.stem
        for difference in diff_json:
            if difference.get("Type") == "DynamicUpdate":
                seed = difference.get("Fingerprint Seed", {})
                category = seed.get("scenario_category", difference.get("Scenario Category", "-"))
                auth_mode = seed.get("auth_mode", difference.get("Auth Mode", "none"))
                prereq_shape = seed.get("prerequisite_shape", difference.get("Prerequisite Shape", "-"))
                op_shape = seed.get("operation_shape", difference.get("Operation Shape", "-"))
                divergence_kind = seed.get("divergence_kind", difference.get("Divergence Kind", "-"))
                reply_sig = _servers_signature(difference.get("Reply Groups", []))
                post_sig = _servers_signature(difference.get("Post-State Groups", []))
                exact_key = (
                    category,
                    auth_mode,
                    prereq_shape,
                    op_shape,
                    divergence_kind,
                    reply_sig,
                    post_sig,
                )
                coarse_key = (
                    auth_mode,
                    prereq_shape,
                    op_shape,
                    divergence_kind,
                    reply_sig,
                    post_sig,
                )
                update_step = difference.get("Update Step", "-")
                dynamic_exact_vectors[exact_key].add((zoneid, update_step))
                dynamic_coarse_vectors[coarse_key].add((zoneid, update_step, category))
                continue

            query_str = difference["Query Name"] + ":" + difference["Query Type"]
            frozen_groups = []
            for group in difference["Groups"]:
                servers = set(group["Server/s"].strip().split())
                if servers:
                    frozen_groups.append(frozenset(servers))
            if len(frozen_groups) <= 1:
                continue
            if zoneid in model_cases:
                test_model_case = model_cases[zoneid][query_str]
                legacy_vectors[(test_model_case, frozenset(frozen_groups))].add((zoneid, query_str))
            else:
                legacy_vectors[("-", frozenset(frozen_groups))].add((zoneid, query_str))

    output = {}
    if legacy_vectors:
        output["Legacy"] = _summarize_legacy(legacy_vectors)
    if dynamic_exact_vectors:
        output["DynamicUpdateExact"] = _summarize_dynamic_exact(dynamic_exact_vectors)
    if dynamic_coarse_vectors:
        output["DynamicUpdateCoarse"] = _summarize_dynamic_coarse(dynamic_coarse_vectors)
    with open(dir_path / "Fingerprints.json", "w") as fp:
        json.dump(output, fp, indent=2)


def fingerprint_group_tests_helper(input_dir: pathlib.Path) -> None:
    if not (input_dir.exists() and input_dir.is_dir()):
        return
    differences_dir = input_dir / DIFFERENCES
    if differences_dir.exists() and differences_dir.is_dir():
        model_cases = get_model_cases(input_dir)
        fingerprint_group_tests(input_dir, model_cases)
        return
    for subdir in input_dir.iterdir():
        fingerprint_group_tests_helper(subdir)


if __name__ == "__main__":
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="Fingerprint and group tests that resulted in differences.",
    )
    parser.add_argument("-path", metavar="DIRECTORY_PATH", default=SUPPRESS,
                        help="The path to the directory containing Differences directory. Searches recursively "
                        "(default: Results/)")
    args = parser.parse_args()
    directory_path = pathlib.Path(args.path) if "path" in args else pathlib.Path("Results/")
    fingerprint_group_tests_helper(directory_path)
