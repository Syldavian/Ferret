"""
Script uses Technitium HTTP API to create a new zone and seed records. It also deletes all zones except the default ones.
The DNS server is started on the container port 53, which is mapped to a host port.
"""

#!/usr/bin/env python3

import pathlib
import subprocess
import time
import os
from typing import Optional

import requests

import dns.query
import dns.rcode
import dns.update
import dns.zone
from dns.rdatatype import RdataType


def _post(url: str, data: dict, context: str) -> Optional[requests.Response]:
    response = requests.post(url, data=data, timeout=3)
    if response.status_code != 200 or response.json()['status'] == "error":
        print(f"{context} failed with status code {response.status_code} and response {response.json()}")
        return None
    return response


def _send_update(update: dns.update.Update, port: int, context: str) -> bool:
    try:
        response = dns.query.udp(update, "127.0.0.1", port=port, timeout=3)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"{context} failed with exception: {exc}")
        return False
    rcode_text = dns.rcode.to_text(response.rcode())
    if rcode_text != "NOERROR":
        print(f"{context} failed with rcode {rcode_text}: {response.to_text()}")
        return False
    return True


def _load_zone_records_via_update(zone_file: pathlib.Path, zone_domain: str, port: int) -> None:
    zone = dns.zone.from_file(str(zone_file), relativize=False, origin=zone_domain)
    for name, node in zone.nodes.items():
        owner = name.to_text()
        for rdataset in node.rdatasets:
            rdtype_text = dns.rdatatype.to_text(rdataset.rdtype)
            for rdata in rdataset:
                update = dns.update.Update(zone_domain)
                update.add(owner, rdataset.ttl, rdtype_text, rdata.to_text())
                if not _send_update(update, port, f"Seed UPDATE for {zone_file.stem}: {owner} {rdtype_text} {rdata.to_text()}"):
                    raise RuntimeError(f"Seed UPDATE failed for {owner} {rdtype_text} {rdata.to_text()}")


def _load_zone_records_via_import(zone_file: pathlib.Path, zone_domain: str, port: int, token: str) -> None:
    import_url = f'http://localhost:{str(port + 1)}/api/zones/import'
    params = {
        "token": token,
        "zone": zone_domain,
        "overwrite": "true",
        "overwriteZone": "true",
        "overwriteSoaSerial": "true",
    }
    response = requests.post(
        import_url,
        params=params,
        data=zone_file.read_text(encoding="utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
        timeout=10,
    )
    if response.status_code != 200 or response.json()['status'] == "error":
        raise RuntimeError(f"Zone import failed with status code {response.status_code} and response {response.json()}")


def _load_zone_records_via_api(zone_file: pathlib.Path, zone_domain: str, port: int, token: str) -> None:
    zone = dns.zone.from_file(str(zone_file), relativize=False, origin=zone_domain)
    ns_count = 0
    for name, node in zone.nodes.items():
        rdatasets = node.rdatasets
        for rdataset in rdatasets:
            for rdata in rdataset:
                rdata_dict = {"type": dns.rdatatype.to_text(rdata.rdtype),
                              "ttl": rdataset.ttl,
                              "zone": zone_domain,
                              "domain": name.to_text(),
                              "token": token}
                if rdata.rdtype == RdataType.SOA:
                    # Technitium synthesizes a default SOA at zone-create time
                    # (PrimaryZone.cs constructor — MNAME = container hostname,
                    # default RFC defaults for timers). Replace it with the
                    # operator-supplied SOA from the master file via the SOA
                    # branch of /api/zones/records/update. Without this, every
                    # apex SOA query against Technitium returns the synthesized
                    # default, which diverges from bind/knot/yadifa and breaks
                    # any rrset_equals prereq that targets the apex SOA.
                    update_url = f'http://localhost:{str(port + 1)}/api/zones/records/update'
                    soa_data = {
                        "token": token,
                        "zone": zone_domain,
                        "domain": name.to_text(),
                        "type": "SOA",
                        "ttl": str(rdataset.ttl),
                        "primaryNameServer": rdata.mname.to_text().rstrip('.'),
                        "responsiblePerson": rdata.rname.to_text().rstrip('.'),
                        "serial": str(rdata.serial),
                        "refresh": str(rdata.refresh),
                        "retry": str(rdata.retry),
                        "expire": str(rdata.expire),
                        "minimum": str(rdata.minimum),
                    }
                    _post(update_url, soa_data, f"SOA update for zone {zone_file.stem}")
                    continue
                add_url = f'http://localhost:{str(port + 1)}/api/zones/records/add'
                if rdata.rdtype == RdataType.A or rdata.rdtype == RdataType.AAAA:
                    rdata_dict.update({
                        "ipAddress": rdata.address,
                    })
                elif rdata.rdtype == RdataType.CNAME:
                    rdata_dict.update({
                        "cname": rdata.target.to_text(),
                    })
                elif rdata.rdtype == RdataType.DNAME:
                    rdata_dict.update({
                        "dname": rdata.target.to_text(),
                    })
                elif rdata.rdtype == RdataType.TXT:
                    rdata_dict.update({
                        "text": rdata.strings[0].decode(),
                    })
                elif rdata.rdtype == RdataType.MX:
                    rdata_dict.update({
                        "preference": rdata.preference,
                        "exchange": rdata.exchange.to_text(),
                    })
                elif rdata.rdtype == RdataType.NS:
                    rdata_dict.update({
                        "nameServer": rdata.target.to_text(),
                    })
                    if name.to_text() == zone_domain:
                        if ns_count == 0:
                            rdata_dict.update({
                                "overwrite": True,
                            })
                        ns_count += 1
                _post(add_url, rdata_dict, f"Add record for zone {zone_file.stem}")


def run(zone_file: pathlib.Path, zone_domain: str, cname: str, port: int, restart: bool, tag: str) -> None:
    """
    :param zone_file: Path to the Bind-style zone file
    :param zone_domain: The domain name of the zone
    :param cname: Container name
    :param port: The host port which is mapped to the port 53 of the container
    :param restart: Whether to load the input zone file in a new container
                        or reuse the existing container
    :param tag: The image tag to be used if restarting the container
    """
    if restart:
        subprocess.run(['docker', 'container', 'rm', cname, '-f'],
                       stdout=subprocess.PIPE, check=False)
        subprocess.run(['docker', 'run', '-dp', str(port) + ':53/udp', '-p', f'{str(port + 1)}:5380/tcp',
                        '--name=' + cname, "technitium" + tag], check=True)
    else:
        # Stop the running server instance inside the container
        subprocess.run(['docker', 'exec', cname, 'pkill', '-9', '-f', 'DnsServerApp.dll'],
                       stdout=subprocess.PIPE, check=False)
    # Start the server from the publish directory so it can find its web assets and config.
    subprocess.run(
        ['docker', 'exec', '-d', cname, 'sh', '-lc',
         'cd /DnsServer/DnsServerApp/bin/Release/publish && dotnet DnsServerApp.dll > /tmp/technitium.log 2>&1'],
        stdout=subprocess.PIPE, check=False,
    )
    time.sleep(2)

    login_url = f'http://localhost:{str(port + 1)}/api/user/login'
    login_data = {"user": "admin", "pass": "admin"}
    response = None
    for _ in range(10):
        try:
            response = _post(login_url, login_data, f"Login request for zone {zone_file.stem}")
        except requests.exceptions.RequestException:
            response = None
        if response:
            break
        time.sleep(1)
    if response:
        token = response.json()['token']
        default_zones = ["0.in-addr.arpa", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
                         "127.in-addr.arpa", "255.in-addr.arpa", "localhost", "ntp.org"]
        zones_list_url = f'http://localhost:{str(port + 1)}/api/zones/list'
        zones_list_data = {"token": token}
        response = _post(zones_list_url, zones_list_data, f"Zones list request for zone {zone_file.stem}")
        if response:
            zones_list = response.json()['response']['zones']
            delete_zones = []
            for zone in zones_list:
                if zone["name"] not in default_zones:
                    delete_zones.append(zone["name"])
            for delete_zone in delete_zones:
                zones_delete_url = f'http://localhost:{str(port + 1)}/api/zones/delete'
                zones_delete_data = {"token": token, "zone": delete_zone}
                _post(zones_delete_url, zones_delete_data, f"Zones delete request for {delete_zone}")
            zones_add_url = f'http://localhost:{str(port + 1)}/api/zones/create'
            zones_add_data = {"token": token, "zone": zone_domain}
            response = _post(zones_add_url, zones_add_data, f"Zones add request for zone {zone_file.stem}")
            if response:
                zone_options_url = f'http://localhost:{str(port + 1)}/api/zones/options/set'
                zone_options_data = {
                    "token": token,
                    "zone": zone_domain,
                    "update": "Allow",
                    "updateNetworkACL": False,
                    "updateSecurityPolicies": False,
                }
                _post(zone_options_url, zone_options_data, f"Zone options update request for zone {zone_file.stem}")
                try:
                    load_method = os.environ.get("FERRET_TECHNITIUM_ZONE_LOAD_METHOD", "api").lower()
                    if load_method == "update":
                        _load_zone_records_via_update(zone_file, zone_domain, port)
                    elif load_method == "import":
                        _load_zone_records_via_import(zone_file, zone_domain, port, token)
                    else:
                        _load_zone_records_via_api(zone_file, zone_domain, port, token)
                except Exception as e:
                    print(
                        f"An error occurred while reading the zone file ({zone_file.stem}): {e}")
                    raise
