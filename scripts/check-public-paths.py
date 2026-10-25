#!/usr/bin/env python3
"""Verify public repository hygiene: no developer home paths, CJK text, or legacy names."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE_FILES = 1000
MAX_TEXT_BYTES = 2 * 1024 * 1024
SKIP_ANY_DIRS = {'build', '__pycache__'}
SKIP_ROOT_DIRS = {'vendor'}
SKIP_SUFFIXES = ('.o', '.a', '.so')

PRIVATE_PATH = re.compile(
    r"/(?:home|Users)/[A-Za-z0-9_.-]+/[^\s\"'<>?\\]*"
    r'|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]'
)
CJK_TEXT = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]")
LEGACY_ID = re.compile("(?:" + "bb10" + "_tls|" + "BB10" + "_TLS)")


def list_public_files(root: Path) -> list[str]:
    root = root.resolve()
    if (root / '.git').exists():
        names = subprocess.check_output(
            ['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']
        )
        return sorted(
            raw.decode('utf-8')
            for raw in set(names.split(b'\0'))
            if raw
        )

    collected: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        cur = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_ANY_DIRS and not (cur == root and d in SKIP_ROOT_DIRS)
        )
        for fname in sorted(filenames):
            if fname == '.DS_Store' or fname.endswith(SKIP_SUFFIXES):
                continue
            fpath = cur / fname
            if fpath.is_symlink() or not fpath.is_file():
                continue
            collected.append(fpath.relative_to(root).as_posix())
            if len(collected) > MAX_ARCHIVE_FILES:
                raise RuntimeError(
                    f'archive file inventory exceeded bound ({MAX_ARCHIVE_FILES})'
                )
    return sorted(collected)


def self_test():
    assert PRIVATE_PATH.search('/' + 'home' + '/developer/project')
    assert PRIVATE_PATH.search('file:' + '///' + 'Users' + '/developer/project')
    assert PRIVATE_PATH.search('C:' + '\\' + 'Users' + '\\developer\\project')
    assert not PRIVATE_PATH.search('/opt/bb10-toolchain.cmake')
    assert not PRIVATE_PATH.search('https://example.org/docs')
    assert CJK_TEXT.search('\u4e2d\u6587')
    assert LEGACY_ID.search('bb10' + '_tls_connect')
    assert not LEGACY_ID.search('posix_tls_connect')
    with tempfile.TemporaryDirectory(prefix='posix-tls-hygiene-selftest-') as tmp:
        outer_git = Path(tmp) / 'outer'
        (outer_git / '.git').mkdir(parents=True)
        extracted = outer_git / 'posix-tls-archive'
        (extracted / 'src').mkdir(parents=True)
        (extracted / 'build').mkdir(parents=True)
        (extracted / 'vendor' / 'sources').mkdir(parents=True)
        (extracted / 'README.md').write_text('# posix-tls\n', encoding='utf-8')
        (extracted / 'src' / 'lib.c').write_text('int x = 0;\n', encoding='utf-8')
        (extracted / 'build' / 'ignored.txt').write_text('ignored\n', encoding='utf-8')
        (extracted / 'vendor' / 'sources' / 'cacert.pem').write_text('ignored\n', encoding='utf-8')
        assert list_public_files(extracted) == ['README.md', 'src/lib.c']


def main():
    self_test()
    if sys.argv[1:] == ['--self-test']:
        print('OK: public path and hygiene guard self-check')
        return 0
    if sys.argv[1:]:
        raise SystemExit('Usage: check-public-paths.py [--self-test]')

    try:
        candidates = list_public_files(ROOT)
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1

    failures = []
    checked = 0
    for name in candidates:
        file_path = ROOT / name
        if not file_path.is_file():
            continue
        if file_path.stat().st_size > MAX_TEXT_BYTES:
            failures.append(f'oversized file in public tree: {name}')
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
