"""
Script copies the input zone file and the necessary configuration file "named.conf"
into an existing or a new Bind container and starts the DNS server on container
port 53, which is mapped to a host port.
"""

#!/usr/bin/env python3

import pathlib
import subprocess
from typing import Any, Dict, Optional


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
                        '--name=' + cname, 'bind' + tag],
                       stdout=subprocess.PIPE, check=False)
    else:
        # Kill the running server instance inside the container
        subprocess.run(
            ['docker', 'exec', cname, 'pkill', 'named'], check=False)
    # Remove stale journals from previous runs for the same zone file.
    subprocess.run(['docker', 'exec', cname, 'sh', '-lc',
                    f'rm -f /usr/local/etc/{zone_file.name}.jnl /usr/local/etc/{zone_file.name}.jnw '
                    f'/usr/local/etc/{zone_file.name}.jbk'],
                   stdout=subprocess.PIPE, check=False)
    # Copy the new zone file into the container
    subprocess.run(['docker', 'cp', str(zone_file), cname +
                    ':/usr/local/etc'], stdout=subprocess.PIPE, check=False)
    auth = auth or {"Mode": "none"}
    if auth.get("Mode", "none") == "tsig":
        key_name = auth["KeyName"]
        secret = auth["Secret"]
        algorithm = auth.get("Algorithm", "hmac-sha256").rstrip(".")
        auth_block = (
            f'key "{key_name}" {{\n'
            f'    algorithm {algorithm};\n'
            f'    secret "{secret}";\n'
            '};\n\n'
        )
        allow_update_clause = f'allow-update {{ key "{key_name}"; }};'
    else:
        auth_block = ""
        allow_update_clause = "allow-update { any; };"
    # Create the Bind-specific configuration file
    named = f'''
    options{{
    recursion no;
    directory "/usr/local/etc";
    }};

    {auth_block}
    zone "{zone_domain}" {{
        type master;
        check-names ignore;
        file "{"/usr/local/etc/"+ zone_file.name}";
        {allow_update_clause}
    }};
    '''
    with open('named_'+cname+'.conf', 'w') as file_pointer:
        file_pointer.write(named)
    # Copy the configuration file into the container as "named.conf"
    subprocess.run(['docker', 'cp', 'named_'+cname+'.conf', cname +
                    ':/usr/local/etc/named.conf'], stdout=subprocess.PIPE, check=False)
    pathlib.Path('named_'+cname+'.conf').unlink()
    subprocess.run(['docker', 'exec', cname, 'mkdir', '-p', '/var/log'],
                   stdout=subprocess.PIPE, check=False)
    # Start the server in foreground mode so update failures are visible in container logs.
    subprocess.run(['docker', 'exec', '-d', cname, 'sh', '-lc',
                    'named -g -c /usr/local/etc/named.conf > /var/log/named.log 2>&1'],
                   stdout=subprocess.PIPE, check=False)
    subprocess.run(['docker', 'exec', cname, 'rndc', 'flush'],
                   stdout=subprocess.PIPE, check=False)
