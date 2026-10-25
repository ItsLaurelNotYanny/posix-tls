#!/usr/bin/env python3
"""Run a local pinned TLS 1.3 TCP client/server example with bounded waits."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

probe = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/host/posix_tls_probe').resolve())
with tempfile.TemporaryDirectory(prefix='posix-tls-example-') as directory:
    work = Path(directory)
    cert, key = work / 'cert.pem', work / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost',
                    '-days', '1', '-keyout', str(key), '-out', str(cert)],
                   check=True, capture_output=True, timeout=15)
    pin = subprocess.check_output([probe, 'fingerprint', '--cert', str(cert)],
                                  text=True, timeout=5).strip()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    with (work / 'server.log').open('w+') as log:
        server = subprocess.Popen([probe, 'server', '--once', '--port', str(port),
                                   '--cert', str(cert), '--key', str(key),
                                   '--min-tls-version', 'TLSv1.3'],
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
            client = subprocess.check_output(
                [probe, 'client', '--url', 'https://127.0.0.1:%d/' % port,
                 '--expected-pin', pin, '--min-tls-version', 'TLSv1.3'],
                text=True, timeout=10)
            print(client)
            if server.wait(timeout=5) != 0:
                raise RuntimeError('Server exchange failed')
            log.seek(0)
            output = log.read()
            if 'TLSv1.3' not in output or 'HTTP/1.1 200 OK' not in client:
                raise RuntimeError('Missing TLS 1.3 or response status evidence: ' + output)
            print('OK: pinned TLS 1.3 TCP client/server exchange')
        finally:
            if server.poll() is None:
                server.kill()
                server.wait()
