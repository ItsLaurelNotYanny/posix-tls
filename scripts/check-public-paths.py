#!/usr/bin/env python3
"""Verify public repository hygiene: no developer home paths, CJK text, or legacy names."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

PRIVATE_PATH = re.compile(
    r"/(?:home|Users)/[A-Za-z0-9_.-]+/[^\s\"'<>?\\]*"
    r'|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]'
)
CJK_TEXT = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]")
LEGACY_ID = re.compile("(?:" + "bb10" + "_tls|" + "BB10" + "_TLS)")


def self_test():
    assert PRIVATE_PATH.search('/' + 'home' + '/developer/project')
    assert PRIVATE_PATH.search('file:' + '///' + 'Users' + '/developer/project')
    assert PRIVATE_PATH.search('C:' + '\\' + 'Users' + '\\developer\\project')
    assert not PRIVATE_PATH.search('/opt/bb10-toolchain.cmake')
    assert not PRIVATE_PATH.search('https://example.org/docs')
    assert CJK_TEXT.search('\u4e2d\u6587')
    assert LEGACY_ID.search('bb10' + '_tls_connect')
    assert not LEGACY_ID.search('posix_tls_connect')


def main():
    self_test()
    if sys.argv[1:] == ['--self-test']:
        print('OK: public path and hygiene guard self-check')
        return 0
    if sys.argv[1:]:
        raise SystemExit('Usage: check-public-paths.py [--self-test]')

    names = subprocess.check_output(
        ['git', '-C', str(ROOT), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']
    )
    failures = []
    checked = 0
    for raw_name in sorted(set(names.split(b'\0'))):
        if not raw_name:
            continue
        name = raw_name.decode('utf-8')
        file_path = ROOT / name
        if not file_path.is_file():
            continue
        content = file_path.read_bytes()
        if b'\0' in content:
            continue
        checked += 1
        text = content.decode('utf-8', errors='strict')
        for number, line in enumerate(text.splitlines(), 1):
            if PRIVATE_PATH.search(line):
                failures.append(f'private home-directory path in {name}:{number}')
            if CJK_TEXT.search(line):
                failures.append(f'non-English CJK text in {name}:{number}')
            if LEGACY_ID.search(line):
                failures.append(f'legacy identifier in {name}:{number}')

    if checked == 0:
        print('FAIL: no public files checked', file=sys.stderr)
        return 1
    for item in failures:
        print('FAIL: ' + item, file=sys.stderr)
    if failures:
        return 1
    print(f'OK: verified public hygiene across {checked} files (no developer paths, CJK, or legacy IDs)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
