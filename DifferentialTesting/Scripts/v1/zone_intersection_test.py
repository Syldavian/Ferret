#!/usr/bin/env python3
"""
Automated "Conflicting Parent/Child Authority (Zone Intersection)" test.

Starts multiple authoritative servers (except MaraDNS/Technitium), loads
campus.edu and ns1.campus.edu zones, then queries for data below the cut.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple, Union

import dns.message
import dns.name
import dns.query


PARENT_ZONE = """$ORIGIN campus.edu.
@  500  IN SOA ns1.campus.edu. root.campus.edu. 1 500 86400 2419200 500
@  500  IN NS  ns1.campus.edu.

; delegation
ns1 500 IN NS ns1.ns1.campus.edu.

; glue
ns1.ns1 500 IN A 192.0.2.53

; conflicting data below the cut (should be ignored if child loaded)
host.ns1 500 IN A 192.0.2.99
"""

CHILD_ZONE = """$ORIGIN ns1.campus.edu.
@  500 IN SOA ns1.ns1.campus.edu. root.ns1.campus.edu. 1 500 86400 2419200 500
@  500 IN NS  ns1.ns1.campus.edu.
ns1 500 IN A 192.0.2.53
host 500 IN A 198.51.100.7
"""


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def querier(name: str, rtype: str, port: int) -> Union[str, dns.message.Message]:
    try:
        query = dns.message.make_query(dns.name.from_text(name), rtype)
        query.flags = 0
        return dns.query.udp(query, "127.0.0.1", 3, port=port, ignore_trailing=True)
    except dns.exception.Timeout:
        return "No response"
    except Exception as exc:  # pylint: disable=broad-except
        return f"Unexpected error {exc}"


def start_container(cname: str, image: str, port: int) -> None:
    run(["docker", "container", "rm", cname, "-f"])
    res = run(["docker", "run", "-dp", f"{port}:53/udp", "--name=" + cname, image])
    if res.returncode != 0:
        sys.exit(f"Failed to start {cname}: {res.stderr.strip()}")


def bind_setup(cname: str, temp: Path) -> None:
    named_conf = temp / "named.conf"
    write_text(
        named_conf,
        """options { recursion no; };
zone "campus.edu" { type master; check-names ignore; file "/usr/local/etc/db.campus.edu"; };
zone "ns1.campus.edu" { type master; check-names ignore; file "/usr/local/etc/db.ns1.campus.edu"; };
""",
    )
    run(["docker", "cp", str(temp / "db.campus.edu"), f"{cname}:/usr/local/etc/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"), f"{cname}:/usr/local/etc/db.ns1.campus.edu"])
    run(["docker", "cp", str(named_conf), f"{cname}:/usr/local/etc/named.conf"])
    run(["docker", "exec", cname, "pkill", "-f", "named"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         "named -c /usr/local/etc/named.conf -g > /usr/local/var/log/named.log 2>&1 &"])


def nsd_setup(cname: str, temp: Path) -> None:
    nsd_conf = temp / "nsd.conf"
    write_text(
        nsd_conf,
        """server:
  port: 53
  ip4-only: yes
  username: root
  zonesdir: "/etc/nsd/zones/"

zone:
  name: campus.edu.
  zonefile: db.campus.edu

zone:
  name: ns1.campus.edu.
  zonefile: db.ns1.campus.edu
""",
    )
    run(["docker", "cp", str(temp / "db.campus.edu"), f"{cname}:/etc/nsd/zones/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"), f"{cname}:/etc/nsd/zones/db.ns1.campus.edu"])
    run(["docker", "cp", str(nsd_conf), f"{cname}:/etc/nsd/nsd.conf"])
    run(["docker", "exec", cname, "pkill", "-f", "nsd"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         "nsd -d -c /etc/nsd/nsd.conf > /var/log/nsd.log 2>&1 &"])


def knot_setup(cname: str, temp: Path) -> None:
    knot_conf = temp / "knot.conf"
    write_text(
        knot_conf,
        """server:
  listen: 0.0.0.0@53
  listen: ::@53
  rundir: "/usr/local/var/run/knot"

zone:
  - domain: campus.edu.
    storage: /usr/local/var/lib/knot/
    file: db.campus.edu
  - domain: ns1.campus.edu.
    storage: /usr/local/var/lib/knot/
    file: db.ns1.campus.edu
""",
    )
    run(["docker", "cp", str(temp / "db.campus.edu"), f"{cname}:/usr/local/var/lib/knot/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"), f"{cname}:/usr/local/var/lib/knot/db.ns1.campus.edu"])
    run(["docker", "cp", str(knot_conf), f"{cname}:/usr/local/etc/knot/knot.conf"])
    run(["docker", "exec", cname, "pkill", "-f", "knotd"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         "knotd -c /usr/local/etc/knot/knot.conf -v > /var/log/knot.log 2>&1 &"])


def powerdns_setup(cname: str, temp: Path) -> None:
    bindbackend = temp / "bindbackend.conf"
    write_text(
        bindbackend,
        """zone "campus.edu" {
  file "/usr/local/etc/db.campus.edu";
  type master;
};
zone "ns1.campus.edu" {
  file "/usr/local/etc/db.ns1.campus.edu";
  type master;
};
""",
    )
    run(["docker", "cp", str(temp / "db.campus.edu"), f"{cname}:/usr/local/etc/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"), f"{cname}:/usr/local/etc/db.ns1.campus.edu"])
    run(["docker", "cp", str(bindbackend), f"{cname}:/usr/local/etc/bindbackend.conf"])
    run(["docker", "exec", cname, "dos2unix", "/usr/local/etc/bindbackend.conf"])
    run(["docker", "exec", cname, "pkill", "-f", "pdns_server"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         "/usr/local/sbin/pdns_server --daemon=no --guardian=no --config-dir=/usr/local/etc "
         "> /usr/local/var/log/pdns_server.log 2>&1 &"])


def yadifa_setup(cname: str, temp: Path) -> None:
    # Base config from repo, append second zone
    base_conf = (Path(__file__).resolve().parents[1] / "Implementations" / "Yadifa" / "yadifad.conf").read_text(encoding="utf-8")
    extra_zone = """
<zone>
        type                    master
        domain                  ns1.campus.edu.
        file                    db.ns1.campus.edu
</zone>
"""
    yadifa_conf = temp / "yadifad.conf"
    write_text(yadifa_conf, base_conf + extra_zone)
    run(["docker", "cp", str(temp / "db.campus.edu"), f"{cname}:/usr/local/var/zones/masters/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"), f"{cname}:/usr/local/var/zones/masters/db.ns1.campus.edu"])
    run(["docker", "cp", str(yadifa_conf), f"{cname}:/usr/local/etc/yadifad.conf"])
    run(["docker", "exec", cname, "pkill", "-f", "yadifad"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         "yadifad -d > /usr/local/var/log/yadifa/yadifad.log 2>&1 &"])


def trustdns_setup(cname: str, temp: Path) -> None:
    config = temp / "config.toml"
    write_text(
        config,
        """[[zones]]
zone = "campus.edu"
zone_type = "Primary"
file = "db.campus.edu"

[[zones]]
zone = "ns1.campus.edu"
zone_type = "Primary"
file = "db.ns1.campus.edu"
""",
    )
    run(["docker", "cp", str(temp / "db.campus.edu"),
         f"{cname}:/trust-dns/tests/test-data/named_test_configs/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"),
         f"{cname}:/trust-dns/tests/test-data/named_test_configs/db.ns1.campus.edu"])
    run(["docker", "cp", str(config),
         f"{cname}:/trust-dns/tests/test-data/named_test_configs/config.toml"])
    # Find server binary
    res = run(["docker", "exec", cname, "sh", "-c",
               "for f in /trust-dns/target/release/*; do [ -x \"$f\" ] && echo \"$f\"; done"])
    server_bin = ""
    for line in res.stdout.splitlines():
        base = line.rsplit("/", 1)[-1]
        if base in ("named", "hickory-dns", "hickory-dns-server", "hickory"):
            server_bin = line
            break
        if "hickory" in base and "test" not in base:
            server_bin = line
            break
    if not server_bin:
        sys.exit("Could not find TrustDNS server binary in container")
    run(["docker", "exec", cname, "pkill", "-f", "hickory"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         f"{server_bin} -c /trust-dns/tests/test-data/named_test_configs/config.toml "
         f"-z /trust-dns/tests/test-data/named_test_configs >> /var/log/hickory-dns.log 2>&1"])


def coredns_setup(cname: str, temp: Path) -> None:
    corefile = temp / "Corefile"
    write_text(
        corefile,
        """campus.edu.:53 {
    file db.campus.edu
    log
    errors
}
ns1.campus.edu.:53 {
    file db.ns1.campus.edu
    log
    errors
}
""",
    )
    run(["docker", "cp", str(temp / "db.campus.edu"), f"{cname}:/go/coredns/db.campus.edu"])
    run(["docker", "cp", str(temp / "db.ns1.campus.edu"), f"{cname}:/go/coredns/db.ns1.campus.edu"])
    run(["docker", "cp", str(corefile), f"{cname}:/go/coredns/Corefile"])
    run(["docker", "exec", cname, "pkill", "-f", "coredns"])
    run(["docker", "exec", "-d", cname, "sh", "-lc",
         "cd /go/coredns && ./coredns -conf /go/coredns/Corefile "
         "> /go/coredns/coredns.log 2>&1 &"])


SETUP_FUNCS = {
    "bind": bind_setup,
    "nsd": nsd_setup,
    "knot": knot_setup,
    "powerdns": powerdns_setup,
    "yadifa": yadifa_setup,
    "trustdns": trustdns_setup,
    "coredns": coredns_setup,
}

PORTS = {
    "bind": 8000,
    "nsd": 8100,
    "knot": 8200,
    "powerdns": 8300,
    "yadifa": 8400,
    "coredns": 8500,
    "trustdns": 8700,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Zone intersection test (parent/child authority conflict).")
    parser.add_argument("--tag", default=":latest", help="Image tag, e.g. ':latest' or ':oct'.")
    parser.add_argument("--id", type=int, default=1, help="ID multiplier for ports/containers.")
    parser.add_argument("--keep", action="store_true", help="Keep containers after test.")
    args = parser.parse_args()

    impls = list(SETUP_FUNCS.keys())
    with tempfile.TemporaryDirectory() as tmpdir:
        temp = Path(tmpdir)
        write_text(temp / "db.campus.edu", PARENT_ZONE)
        write_text(temp / "db.ns1.campus.edu", CHILD_ZONE)

        results: Dict[str, Dict[str, Union[str, List[str]]]] = {}
        for impl in impls:
            cname = f"{args.id}_{impl}_zonecut"
            port = PORTS[impl] * args.id
            start_container(cname, impl + args.tag, port)
            SETUP_FUNCS[impl](cname, temp)
            # Wait briefly for SOA readiness
            deadline = time.time() + 8
            ready = False
            while time.time() < deadline:
                resp = querier("campus.edu.", "SOA", port)
                if isinstance(resp, dns.message.Message):
                    ready = True
                    break
                time.sleep(0.5)
            results[impl] = {"ready": str(ready)}

            # Queries
            a_resp = querier("host.ns1.campus.edu.", "A", port)
            soa_resp = querier("ns1.campus.edu.", "SOA", port)
            results[impl]["A host.ns1.campus.edu."] = (
                a_resp.to_text().split("\n") if isinstance(a_resp, dns.message.Message) else a_resp
            )
            results[impl]["SOA ns1.campus.edu."] = (
                soa_resp.to_text().split("\n") if isinstance(soa_resp, dns.message.Message) else soa_resp
            )

        # Output summary
        for impl, data in results.items():
            print(f"\n== {impl} ==")
            print(f"ready: {data['ready']}")
            print("A host.ns1.campus.edu.:")
            print("\n".join(data["A host.ns1.campus.edu."]) if isinstance(data["A host.ns1.campus.edu."], list) else data["A host.ns1.campus.edu."])
            print("SOA ns1.campus.edu.:")
            print("\n".join(data["SOA ns1.campus.edu."]) if isinstance(data["SOA ns1.campus.edu."], list) else data["SOA ns1.campus.edu."])

        if not args.keep:
            for impl in impls:
                run(["docker", "container", "rm", f"{args.id}_{impl}_zonecut", "-f"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
