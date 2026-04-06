#!/usr/bin/env python3
import json
import pathlib
from typing import Dict, List, Any

BASE = pathlib.Path(__file__).resolve().parents[1] / "ferret_tests"
UNDERSPECS_DIR = BASE / "Underspecs"
EXPECTED_DIR = BASE / "ExpectedDivergence"
QUERIES_DIR = BASE / "Queries"
ZONEFILES_DIR = BASE / "ZoneFiles"
DIFF_DIR = BASE / "Differences"
OUT_DIR = BASE / "UnderspecsLinked"


def load_json(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def build_expected_title_map() -> Dict[str, str]:
    """Map scenario_title -> test_id (filename stem)."""
    mapping: Dict[str, str] = {}
    for path in EXPECTED_DIR.glob("*.json"):
        try:
            data = load_json(path)
        except Exception:
            continue
        title = data.get("scenario_title")
        if isinstance(title, str):
            mapping[title] = path.stem
    return mapping


def collect_testcase(test_id: str) -> Dict[str, Any]:
    """Collect zone file + query file if present."""
    testcase: Dict[str, Any] = {"test_id": test_id}
    zpath = ZONEFILES_DIR / f"{test_id}.txt"
    if zpath.exists():
        testcase["zone_file"] = {
            "path": str(zpath),
            "content": zpath.read_text(encoding="utf-8", errors="replace")
        }
    qpath = QUERIES_DIR / f"{test_id}.json"
    if qpath.exists():
        testcase["queries"] = {
            "path": str(qpath),
            "content": load_json(qpath)
        }
    return testcase


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    title_map = build_expected_title_map()

    for underspec_file in UNDERSPECS_DIR.glob("*.json"):
        data = load_json(underspec_file)
        if not isinstance(data, list):
            continue
        for idx, obj in enumerate(data):
            title = obj.get("title")
            if not isinstance(title, str):
                continue
            test_id = title_map.get(title)
            if not test_id:
                continue
            diff_path = DIFF_DIR / f"{test_id}.json"
            if not diff_path.exists():
                # skip if no results
                continue
            out = {
                "underspec": obj,
                "testcase": collect_testcase(test_id),
                "result": {
                    "path": str(diff_path),
                    "content": load_json(diff_path)
                },
            }
            out_name = f"{underspec_file.stem}__{test_id}__{idx}.json"
            out_path = OUT_DIR / out_name
            with out_path.open("w", encoding="utf-8") as fp:
                json.dump(out, fp, indent=2)


if __name__ == "__main__":
    main()
