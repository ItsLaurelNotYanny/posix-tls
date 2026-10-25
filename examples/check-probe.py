#!/usr/bin/env python3
"""Run local pinned P2P and Public PKI fullchain TLS 1.3 TCP probe checks."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def reserve_port() -> int:
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def run_exchange(probe: str, log_path: Path, server_args: list[str], client_args: list[str]) -> str:
    with log_path.open('w+') as log:
        server = subprocess.Popen([probe, 'server', '--once', *server_args],
                                  stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while True:
                log.seek(0)
                output = log.read()
                if 'Server listening' in output:
                    break
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Server did not start: ' + output)
                time.sleep(0.05)
            client = subprocess.check_output([probe, 'client', *client_args],
                                             text=True, timeout=10)
            print(client)
            if server.wait(timeout=5) != 0:
                raise RuntimeError('Server exchange failed')
            log.seek(0)
            output = log.read()
            if 'TLSv1.3' not in output or 'HTTP/1.1 200 OK' not in client:
                raise RuntimeError('Missing TLS 1.3 or response status evidence: ' + output)
            return client
        finally:
            if server.poll() is None:
                server.kill()
                server.wait()


probe = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/host/posix_tls_probe').resolve())
with tempfile.TemporaryDirectory(prefix='posix-tls-example-') as directory:
    work = Path(directory)

    # 1. Pinned P2P TLS 1.3 TCP exchange
    cert, key = work / 'cert.pem', work / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost',
                    '-days', '1', '-keyout', str(key), '-out', str(cert)],
                   check=True, capture_output=True, timeout=15)
    pin = subprocess.check_output([probe, 'fingerprint', '--cert', str(cert)],
                                  text=True, timeout=5).strip()
    port_p2p = reserve_port()
    run_exchange(
        probe,
        work / 'server-p2p.log',
        ['--port', str(port_p2p), '--cert', str(cert), '--key', str(key), '--min-tls-version', 'TLSv1.3'],
        ['--url', 'https://127.0.0.1:%d/' % port_p2p, '--expected-pin', pin, '--min-tls-version', 'TLSv1.3'],
    )

    # 2. Public PKI root -> intermediate -> leaf fullchain TLS 1.3 TCP exchange
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=Example Root CA',
                    '-days', '1', '-keyout', str(work / 'root.key'), '-out', str(work / 'root.pem'),
                    '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
                   check=True, capture_output=True, timeout=15)
    for prefix, cn in (('int', 'Example Intermediate CA'), ('leaf', 'localhost')):
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=' + cn,
                        '-keyout', str(work / (prefix + '.key')),
                        '-out', str(work / (prefix + '.csr'))],
                       check=True, capture_output=True, timeout=15)
    (work / 'int.ext').write_text(
        'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n',
        encoding='utf-8',
    )
    (work / 'leaf.ext').write_text(
        'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n',
        encoding='utf-8',
    )
    subprocess.run(['openssl', 'x509', '-req', '-in', str(work / 'int.csr'),
                    '-CA', str(work / 'root.pem'), '-CAkey', str(work / 'root.key'),
                    '-CAcreateserial', '-days', '1', '-extfile', str(work / 'int.ext'),
                    '-out', str(work / 'int.pem')],
                   check=True, capture_output=True, timeout=15)
    subprocess.run(['openssl', 'x509', '-req', '-in', str(work / 'leaf.csr'),
                    '-CA', str(work / 'int.pem'), '-CAkey', str(work / 'int.key'),
                    '-CAcreateserial', '-days', '1', '-extfile', str(work / 'leaf.ext'),
                    '-out', str(work / 'leaf.pem')],
                   check=True, capture_output=True, timeout=15)
    fullchain = work / 'fullchain.pem'
    fullchain.write_bytes((work / 'leaf.pem').read_bytes() + (work / 'int.pem').read_bytes())

    port_pki = reserve_port()
    run_exchange(
        probe,
        work / 'server-pki.log',
        ['--port', str(port_pki), '--cert', str(fullchain), '--key', str(work / 'leaf.key'),
         '--min-tls-version', 'TLSv1.3'],
        ['--url', 'https://localhost:%d/' % port_pki, '--ca-bundle', str(work / 'root.pem'),
         '--min-tls-version', 'TLSv1.3'],
    )
    print('OK: pinned P2P and fullchain Public PKI TLS 1.3 TCP exchanges')
