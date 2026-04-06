#!/usr/bin/env python3
"""
Run wildcard-DNAME authoritative + resolver tests across implementations.

Assumptions:
- Unbound (or another resolver) is already running on resolver host/port.
- The resolver is configured to forward/stub example.com to the auth port.
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


def run_cmd(cmd: List[str]) -> Dict[str, str]:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {
        "cmd": " ".join(cmd),
        "returncode": str(proc.returncode),
        "stdout": proc.stdout.decode("utf-8", errors="replace"),
        "stderr": proc.stderr.decode("utf-8", errors="replace"),
    }


def dig_cmd(host: str, port: int, name: str, qtype: str, norecurse: bool) -> List[str]:
    cmd = ["dig", f"@{host}", "-p", str(port)]
    if norecurse:
        cmd.append("+norecurse")
    cmd.extend([name, qtype])
    return cmd


def dig_cmd_resolver(host: str, port: int, name: str, qtype: str) -> List[str]:
    cmd = ["dig", f"@{host}", "-p", str(port), name, qtype, "+time=2", "+tries=1"]
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run wildcard DNAME tests against authoritative implementations and a resolver."
    )
    parser.add_argument(
        "-i",
        "--impls",
        nargs="+",
        default=DEFAULT_IMPLS,
        help="Implementations to test.",
    )
    parser.add_argument(
        "-z",
        "--zone",
        default="wildcard_dname.db",
        help="Zone file name under CustomTests/ZoneFiles.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="CustomTests/WildcardDnameResults",
        help="Directory to write results.",
    )
    parser.add_argument(
        "--auth-port",
        type=int,
        default=8053,
        help="Host port to map to the authoritative server.",
    )
    parser.add_argument(
        "--resolver-host",
        default="127.0.0.1",
        help="Resolver host.",
    )
    parser.add_argument(
        "--resolver-port",
        type=int,
        default=5353,
        help="Resolver port.",
    )
    parser.add_argument(
        "-l",
        "--latest",
        action="store_true",
        help="Use :latest image tag when starting containers.",
    )
    parser.add_argument(
        "--skip-resolver",
        action="store_true",
        help="Skip resolver queries (only authoritative queries).",
    )
    parser.add_argument(
        "--flush-between",
        action="store_true",
        help="Run 'unbound-control flush_zone example.com' between resolver sequences.",
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
    zone_path = zones_dir / args.zone
    output_dir = diff_dir / args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    if not zone_path.exists():
        print(f"Missing zone file: {zone_path}", file=sys.stderr)
        return 1

    for impl in args.impls:
        cname = f"wildcard_dname_{impl}"
        results: Dict[str, object] = {
            "implementation": impl,
            "zone": str(zone_path),
            "auth_port": args.auth_port,
            "resolver": {"host": args.resolver_host, "port": args.resolver_port},
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "start": {},
            "authoritative_queries": [],
            "resolver_sequences": {},
            "cleanup": {},
        }

        # Ensure stale container is gone before starting.
        run_cmd(["docker", "rm", "-f", cname])

        start_cmd = [
            sys.executable,
            str(impl_dir / "main.py"),
            "-i",
            impl,
            "-p",
            str(args.auth_port),
            "-c",
            cname,
            "-z",
            str(zone_path),
        ]
        if args.latest:
            start_cmd.append("-l")

        results["start"] = run_cmd(start_cmd)

        if results["start"]["returncode"] == "0":
            # Step 4: authoritative checks.
            auth_queries = [
                dig_cmd("127.0.0.1", args.auth_port, "foo.example.com.", "A", True),
                dig_cmd("127.0.0.1", args.auth_port, "bar.foo.example.com.", "A", True),
            ]
            for q in auth_queries:
                results["authoritative_queries"].append(run_cmd(q))

            # Step 6: resolver sequences (order effects).
            if not args.skip_resolver:
                seq_a = [
                    dig_cmd_resolver(args.resolver_host, args.resolver_port,
                                     "foo.example.com.", "A"),
                    dig_cmd_resolver(args.resolver_host, args.resolver_port,
                                     "bar.foo.example.com.", "A"),
                ]
                seq_b = [
                    dig_cmd_resolver(args.resolver_host, args.resolver_port,
                                     "bar.foo.example.com.", "A"),
                    dig_cmd_resolver(args.resolver_host, args.resolver_port,
                                     "foo.example.com.", "A"),
                ]
                results["resolver_sequences"]["A"] = [run_cmd(q) for q in seq_a]
                if args.flush_between:
                    results["resolver_sequences"]["flush_between"] = run_cmd(
                        ["unbound-control", "flush_zone", "example.com"]
                    )
                results["resolver_sequences"]["B"] = [run_cmd(q) for q in seq_b]

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
