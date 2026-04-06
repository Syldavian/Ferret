"""
Script copies the input zone file and the necessary configuration file "config.toml"
into an existing or a new TrustDNS container and starts the DNS server on container
port 53, which is mapped to a host port.
"""

#!/usr/bin/env python3

import base64
import pathlib
import subprocess
import time
from typing import Any, Dict, Optional

CONFIG_DIR = '/var/lib/hickory-dns'


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


def run(
    zone_file: pathlib.Path,
    zone_domain: str,
    cname: str,
    port: int,
    restart: bool,
    tag: str,
    auth: Optional[Dict[str, Any]] = None,
) -> None:
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
    config_dir = CONFIG_DIR
    subprocess.run(['docker', 'exec', cname, 'mkdir', '-p', config_dir],
                   stdout=subprocess.PIPE, check=False)
    auth = auth or {"Mode": "none"}
    subprocess.run(['docker', 'exec', cname, 'sh', '-lc',
                    f'rm -f {config_dir}/*.jrnl {config_dir}/*.key {config_dir}/config.toml {config_dir}/*.txt'],
                   stdout=subprocess.PIPE, check=False)
    # Copy the new zone file into the container
    subprocess.run(['docker', 'cp', str(zone_file), cname + ':' + config_dir + '/'],
                   stdout=subprocess.PIPE, check=False)
    # Create the TrustDNS-specific configuration file
    zone_name = zone_domain.rstrip('.')
    if auth.get("Mode", "none") == "tsig":
        secret_path = pathlib.Path(cname + '_tsig.key')
        secret_path.write_bytes(base64.b64decode(auth["Secret"]))
        subprocess.run(['docker', 'cp', str(secret_path), cname + ':' + config_dir + '/'],
                       stdout=subprocess.PIPE, check=False)
        secret_path.unlink()
        config = (
            f'[[zones]]\n'
            f'zone = "{zone_name}"\n'
            f'zone_type = "Primary"\n'
            f'[zones.stores]\n'
            f'type = "sqlite"\n'
            f'zone_path = "{zone_file.name}"\n'
            f'journal_path = "{zone_file.stem}.jrnl"\n'
            f'allow_update = true\n\n'
            f'[[zones.stores.tsig_keys]]\n'
            f'name = "{auth["KeyName"]}"\n'
            f'key_file = "{cname}_tsig.key"\n'
            f'algorithm = "{auth.get("Algorithm", "hmac-sha256").rstrip(".")}"\n'
            f'fudge = {int(auth.get("Fudge", 300))}\n'
        )
    else:
        config = f'[[zones]]\nzone = "{zone_name}"\nzone_type = "Primary"\nfile = "{zone_file.name}"'
    with open(cname + '_config.toml', 'w') as file_pointer:
        file_pointer.write(config)
    # Copy the configuration file into the container as "config.toml"
    subprocess.run(['docker', 'cp', cname + '_config.toml', cname +
                    f':{config_dir}/config.toml'],
                   stdout=subprocess.PIPE, check=False)
    pathlib.Path(cname + '_config.toml').unlink()
    subprocess.run(['docker', 'exec', cname, 'chown', '-R', 'nobody:nobody', config_dir],
                   stdout=subprocess.PIPE, check=False)
    server_bin = _find_named_binary(cname)
    if not server_bin:
        print(f'Could not find TrustDNS server binary in container {cname}')
        return
    subprocess.run(['docker', 'exec', cname, 'mkdir', '-p', '/var/log'],
                   stdout=subprocess.PIPE, check=False)
    # Start the server
    subprocess.run([
        'docker', 'exec', '-d', cname, 'sh', '-c',
        f'{server_bin} -c {config_dir}/config.toml '
        f'-z {config_dir} >> /var/log/hickory-dns.log 2>&1'
    ], stdout=subprocess.PIPE, check=False)
    time.sleep(1)
