"""Compare two local bodies against a GitHub webhook signature."""
import hmac
import json
import os
import posixpath
import re
import stat
import sys

MAX_KEY = 4096
MAX_HEADER = 73
MAX_BODY = 1048576
HEADER = re.compile(rb'sha256=([0-9a-f]{64})(?:\r?\n)?')
DEVICE = re.compile(r'CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³]')
NATIVE_ROOTS = {'??', 'device', 'dosdevices', 'global??', 'systemroot', 'globalroot'}


def require_local(path):
    normalized = path.replace('\\', '/')
    if not normalized or normalized == '-' or normalized.startswith('//'):
        raise ValueError
    if any(ord(c) < 32 for c in path):
        raise ValueError
    if normalized.startswith('/'):
        for rooted in (normalized, posixpath.normpath(normalized)):
            root = rooted[1:].partition('/')[0].rstrip(' .').lower()
            if root in NATIVE_ROOTS:
                raise ValueError
    tail = normalized[2:] if re.match(r'^[A-Za-z]:/', normalized) else normalized
    if ':' in tail:
        raise ValueError
    for part in tail.split('/'):
        stem = part.partition('.')[0].rstrip(' ').upper()
        if DEVICE.fullmatch(stem):
            raise ValueError


def require_regular(info, limit):
    if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= limit:
        raise ValueError


def read_local(path, limit):
    require_regular(os.stat(path), limit)
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        require_regular(os.fstat(fd), limit)
        with os.fdopen(fd, 'rb', closefd=False) as file:
            data = file.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError
    return data


def compare(key, header, captured, candidate):
    expected = bytes.fromhex(header.group(1).decode('ascii'))
    return {
        'captured_match': hmac.compare_digest(hmac.digest(key, captured, 'sha256'), expected),
        'candidate_match': hmac.compare_digest(hmac.digest(key, candidate, 'sha256'), expected),
    }


def emit(data, status):
    try:
        while data:
            count = os.write(1, data)
            if count <= 0:
                return 2
            data = data[count:]
    except OSError:
        return 2
    return status


def main(args):
    if args in (['--help'], ['-h']):
        return emit(b'Usage: python webhook_body_witness.py KEY SIGNATURE CAPTURE CANDIDATE\n', 0)
    try:
        key_path, signature_path, capture_path, candidate_path = args
        for path in args:
            require_local(path)
        header = HEADER.fullmatch(read_local(signature_path, MAX_HEADER))
        if header is None:
            raise ValueError
        key = read_local(key_path, MAX_KEY)
        if not key:
            raise ValueError
        report = compare(key, header, read_local(capture_path, MAX_BODY),
                         read_local(candidate_path, MAX_BODY))
        status = 0 if report['captured_match'] else 1
    except (OSError, ValueError):
        report, status = {'status': 'invalid'}, 2
    data = json.dumps(report, separators=(',', ':')).encode('ascii')
    return emit(data + b'\n', status)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
