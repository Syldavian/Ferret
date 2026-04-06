"""
Script copies the input zone file and the necessary configuration file "config.toml"
into an existing or a new TrustDNS container and starts the DNS server on container
port 53, which is mapped to a host port.
"""

#!/usr/bin/env python3

import pathlib
import subprocess
import time
from typing import Optional


def _exec_test(cname: str, path: str) -> bool:
    result = subprocess.run(
        ['docker', 'exec', cname, 'test', '-x', path],
        stdout=subprocess.PIPE, check=False
    )
    return result.returncode == 0


def _find_named_binary(cname: str) -> Optional[str]:
    candidates = [
        '/trust-dns/target/release/named',
        '/trust-dns/target/release/hickory-dns',
        '/trust-dns/target/release/hickory-dns-server',
        '/trust-dns/target/release/hickory',
    ]
    for path in candidates:
        if _exec_test(cname, path):
            return path
    # Fallback: pick any executable that looks like a server binary
    result = subprocess.run(
        ['docker', 'exec', cname, 'sh', '-c',
         'for f in /trust-dns/target/release/*; do [ -x "$f" ] && echo "$f"; done'],
        stdout=subprocess.PIPE, check=False
    )
    for line in result.stdout.decode('utf-8').splitlines():
        base = line.rsplit('/', 1)[-1]
        if base in ('named', 'hickory-dns', 'hickory-dns-server', 'hickory'):
            return line
        if 'hickory' in base and 'test' not in base:
            return line
    return None


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
        subprocess.run(['docker', 'run', '-dp', str(port)+':53/udp',
                        '--name=' + cname, 'trustdns' + tag], stdout=subprocess.PIPE, check=False)
    else:
        # Kill the running server instance inside the container
        subprocess.run(['docker', 'exec', cname, 'pkill', 'named'],
                       stdout=subprocess.PIPE, check=False)
        subprocess.run(['docker', 'exec', cname, 'pkill', 'hickory-dns'],
                       stdout=subprocess.PIPE, check=False)
        subprocess.run(['docker', 'exec', cname, 'pkill', 'hickory'],
                       stdout=subprocess.PIPE, check=False)
        time.sleep(0.5)
    # Copy the new zone file into the container
    subprocess.run(['docker', 'cp', str(zone_file), cname +
                    ':trust-dns/tests/test-data/named_test_configs/'],
                   stdout=subprocess.PIPE, check=False)
    # Create the TrustDNS-specific configuration file
    zone_name = zone_domain.rstrip('.')
    config = f'[[zones]]\nzone = "{zone_name}"\nzone_type = "Primary"\nfile = "{zone_file.name}"'
    with open(cname + '_config.toml', 'w') as file_pointer:
        file_pointer.write(config)
    # Copy the configuration file into the container as "config.toml"
    subprocess.run(['docker', 'cp', cname + '_config.toml', cname +
                    ':trust-dns/tests/test-data/named_test_configs/config.toml'],
                   stdout=subprocess.PIPE, check=False)
    pathlib.Path(cname + '_config.toml').unlink()
    server_bin = _find_named_binary(cname)
    if not server_bin:
        print(f'Could not find TrustDNS server binary in container {cname}')
        return
    subprocess.run(['docker', 'exec', cname, 'mkdir', '-p', '/var/log'],
                   stdout=subprocess.PIPE, check=False)
    # Start the server
    subprocess.run([
        'docker', 'exec', '-d', cname, 'sh', '-c',
        f'{server_bin} -c /trust-dns/tests/test-data/named_test_configs/config.toml '
        f'-z /trust-dns/tests/test-data/named_test_configs >> /var/log/hickory-dns.log 2>&1'
    ], stdout=subprocess.PIPE, check=False)
    time.sleep(1)
