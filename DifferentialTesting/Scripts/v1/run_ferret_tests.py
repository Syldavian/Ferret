#!/usr/bin/env python3
"""
Wrapper to run ferret_tests through test_with_valid_zone_files.

Example:
  python3 Scripts/run_ferret_tests.py
  python3 Scripts/run_ferret_tests.py -path ../ferret_tests -id 2 -r 0 10 -b -c -y -m -t -e
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List


def build_cmd(args: argparse.Namespace) -> List[str]:
    cmd = [sys.executable, "-m", "Scripts.test_with_valid_zone_files"]
    cmd.extend(["-path", args.path])
    cmd.extend(["-id", str(args.id)])
    if args.range:
        cmd.extend(["-r", str(args.range[0]), str(args.range[1])])
    if args.latest:
        cmd.append("-l")
    # Disable flags pass-through
    for flag in ["b", "n", "k", "p", "c", "y", "m", "t", "e"]:
        if getattr(args, flag):
            cmd.append(f"-{flag}")
    return cmd


def main() -> int:
    default_path = str((Path(__file__).resolve().parents[1] / "ferret_tests").resolve())
    parser = argparse.ArgumentParser(description="Run DifferentialTesting/ferret_tests.")
    parser.add_argument("-path", default=default_path, help="Path to ferret_tests directory.")
    parser.add_argument("-id", type=int, default=1, help="Unique id for containers.")
    parser.add_argument("-r", dest="range", nargs=2, type=int, metavar=("START", "END"),
                        help="Optional test index range to run.")
    parser.add_argument("-l", "--latest", action="store_true",
                        help="Use latest image tags.")
    # Disable implementations
    parser.add_argument("-b", action="store_true", help="Disable Bind.")
    parser.add_argument("-n", action="store_true", help="Disable NSD.")
    parser.add_argument("-k", action="store_true", help="Disable Knot.")
    parser.add_argument("-p", action="store_true", help="Disable PowerDNS.")
    parser.add_argument("-c", action="store_true", help="Disable CoreDNS.")
    parser.add_argument("-y", action="store_true", help="Disable Yadifa.")
    parser.add_argument("-m", action="store_true", help="Disable MaraDNS.")
    parser.add_argument("-t", action="store_true", help="Disable TrustDNS.")
    parser.add_argument("-e", action="store_true", help="Disable Technitium.")
    parser.add_argument("--dry-run", action="store_true", help="Print the command and exit.")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Path does not exist: {path}", file=sys.stderr)
        return 1
    if not (path / "ZoneFiles").exists() or not (path / "Queries").exists():
        print(f"Expected ZoneFiles/ and Queries/ under: {path}", file=sys.stderr)
        return 1

    cmd = build_cmd(args)
    if args.dry_run:
        print(" ".join(cmd))
        return 0

    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
