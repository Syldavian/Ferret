#!/usr/bin/env python3
"""
Runs CNAME/DNAME loop tests against implementations one by one and records outputs.

Example:
  python3 Scripts/test_loop_zones.py
  python3 Scripts/test_loop_zones.py -i powerdns bind -l
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List


DEFAULT_IMPLS = [
    "bind",
    "nsd",
    "knot",
    "powerdns",
    "coredns",
    "yadifa",
    "maradns",
    "trustdns",
]

DEFAULT_ZONES = [
    "cname_loop.db",
    "dname_loop.db",
]

ZONE_QUERIES: Dict[str, List[List[str]]] = {
    "cname_loop.db": [
        ["dig", "+norecurse", "loop1.example.com.", "A"],
        ["dig", "+norecurse", "loop2.example.com.", "A"],
    ],
    "dname_loop.db": [
        ["dig", "+norecurse", "x.a.example.com.", "A"],
        ["dig", "+norecurse", "x.b.example.com.", "A"],
    ],
}


def run_cmd(cmd: List[str]) -> Dict[str, str]:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {
        "cmd": " ".join(cmd),
        "returncode": str(proc.returncode),
        "stdout": proc.stdout.decode("utf-8", errors="replace"),
        "stderr": proc.stderr.decode("utf-8", errors="replace"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CNAME/DNAME loop tests against DNS implementations."
    )
    parser.add_argument(
        "-i",
        "--impls",
        nargs="+",
        default=DEFAULT_IMPLS,
        help="Implementations to test (default: common implementations).",
    )
    parser.add_argument(
        "-z",
        "--zones",
        nargs="+",
        default=DEFAULT_ZONES,
        help="Zone file names to test (default: cname_loop.db dname_loop.db).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="CustomTests/LoopResults",
        help="Directory to write results.",
    )
    parser.add_argument(
        "-p",
        "--base-port",
        type=int,
        default=8053,
        help="Starting host port for the first implementation.",
    )
    parser.add_argument(
        "-l",
        "--latest",
        action="store_true",
        help="Use :latest image tag when starting containers.",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Do not stop/remove containers after each test.",
    )
    args = parser.parse_args()

    diff_dir = Path(__file__).resolve().parents[1]
    impl_dir = diff_dir / "Implementations"
    zones_dir = diff_dir / "CustomTests" / "ZoneFiles"
    output_dir = diff_dir / args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    missing = [z for z in args.zones if not (zones_dir / z).exists()]
    if missing:
        print(f"Missing zone files in {zones_dir}: {', '.join(missing)}", file=sys.stderr)
        return 1

    for idx, impl in enumerate(args.impls):
        port = args.base_port + idx
        for zone_name in args.zones:
            zone_path = zones_dir / zone_name
            cname = f"looptest_{impl}_{zone_path.stem}"
            results = {
                "implementation": impl,
                "zone": str(zone_path),
                "port": port,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "start": {},
                "queries": [],
                "cleanup": {},
            }

            start_cmd = [
                sys.executable,
                str(impl_dir / "main.py"),
                "-i",
                impl,
                "-p",
                str(port),
                "-c",
                cname,
                "-z",
                str(zone_path),
            ]
            if args.latest:
                start_cmd.append("-l")

            results["start"] = run_cmd(start_cmd)

            if results["start"]["returncode"] == "0":
                for q in ZONE_QUERIES.get(zone_name, []):
                    cmd = q[:]
                    cmd.insert(1, "@127.0.0.1")
                    cmd.insert(2, "-p")
                    cmd.insert(3, str(port))
                    results["queries"].append(run_cmd(cmd))

            if not args.no_cleanup:
                results["cleanup"] = run_cmd(["docker", "rm", "-f", cname])

            impl_out_dir = output_dir / impl
            impl_out_dir.mkdir(parents=True, exist_ok=True)
            output_path = impl_out_dir / f"{zone_path.stem}.json"
            with open(output_path, "w", encoding="utf-8") as fp:
                json.dump(results, fp, indent=2)
            print(f"Wrote {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
