"""
Script copies the input zone file and the necessary configuration file "knot.conf"
into an existing or a new Knot container and starts the DNS server on container
port 53, which is mapped to a host port.
"""

#!/usr/bin/env python3

import pathlib
import subprocess
import time


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
        subprocess.run(['docker', 'run', '-dp', str(port)+':53/udp', '--name=' +
                        cname, 'knot' + tag], stdout=subprocess.PIPE, check=False)
    else:
        # Stop any running server instance inside the container
        subprocess.run(['docker', 'exec', cname, 'pkill', 'knotd'],
                       stdout=subprocess.PIPE, check=False)
        # Allow knotd to exit and release confdb/lock files
        time.sleep(0.5)
    # Copy the new zone file into the container
    subprocess.run(['docker', 'cp', str(zone_file), cname +
                    ':/usr/local/var/lib/knot/'], stdout=subprocess.PIPE, check=False)
    # Ensure rundir exists for knotd
    subprocess.run(['docker', 'exec', cname, 'mkdir', '-p', '/usr/local/var/run/knot'],
                   stdout=subprocess.PIPE, check=False)
    # Create the Knot-specific configuration file
    knot_conf = (
        'server:\n'
        '    listen: 0.0.0.0@53\n'
        '    listen: ::@53\n'
        '    rundir: "/usr/local/var/run/knot"\n\n'
    )
    knot_conf += (
        'zone:\n'
        f'  - domain: {zone_domain}\n'
        '    storage: /usr/local/var/lib/knot/\n'
        f'    file: {zone_file.name}\n\n'
    )
    knot_conf += 'log:\n  - target: /var/log/knot.log\n    any: debug'
    with open('knot_'+cname+'.conf', 'w') as file_pointer:
        file_pointer.write(knot_conf)
    # Copy the configuration file into the container as "knot.conf"
    subprocess.run(['docker', 'cp', 'knot_'+cname+'.conf',
                    cname + ':/usr/local/etc/knot/knot.conf'], stdout=subprocess.PIPE, check=False)
    pathlib.Path('knot_'+cname+'.conf').unlink()
    # Convert the zone file to Unix style (CRLF to LF)
    subprocess.run(['docker', 'exec', cname, 'dos2unix', '/usr/local/var/lib/knot/' +
                    zone_file.name], stdout=subprocess.PIPE, check=False)
    # Start the server in foreground and capture logs
    subprocess.run([
        'docker', 'exec', '-d', cname, 'sh', '-c',
        'knotd -c /usr/local/etc/knot/knot.conf -v >> /var/log/knot.log 2>&1'
    ], stdout=subprocess.PIPE, check=False)

    # Wait for knotd process to appear
    deadline = time.time() + 8
    while time.time() < deadline:
        running = subprocess.run(
            ['docker', 'exec', cname, 'sh', '-c', 'ps aux | grep -q "[k]notd"'],
            stdout=subprocess.PIPE, check=False
        )
        if running.returncode == 0:
            break
        time.sleep(0.5)
