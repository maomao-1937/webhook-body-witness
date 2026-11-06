import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'webhook_body_witness.py'
DEMO_KEY = b"It's a Secret to Everybody"
BODY = b'Hello, World!'
SIGNATURE = b'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17'


class WitnessTests(unittest.TestCase):
    def invoke(self, key=DEMO_KEY, signature=SIGNATURE, captured=BODY, candidate=BODY):
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / f'private-{i}' for i in range(4)]
            inputs = [key, signature, captured, candidate]
            for path, data in zip(paths, inputs):
                path.write_bytes(data)
            result = subprocess.run([sys.executable, '-B', SCRIPT, *map(str, paths)],
                                    cwd=ROOT, capture_output=True, timeout=10)
            self.assertEqual([p.read_bytes() for p in paths], inputs)
            return result

    def check(self, result, code, report):
        self.assertEqual((result.returncode, result.stderr), (code, b''))
        self.assertEqual(json.loads(result.stdout), report)

    def test_official_vector_and_transformed_body(self):
        self.check(self.invoke(candidate=BODY + b'\n'), 0,
                   {'captured_match': True, 'candidate_match': False})

    def test_captured_mismatch_even_when_candidate_matches(self):
        self.check(self.invoke(captured=BODY + b'\r\n'), 1,
                   {'captured_match': False, 'candidate_match': True})

    def test_key_bytes_are_exact_and_signature_file_endings(self):
        for ending in (b'', b'\n', b'\r\n'):
            self.check(self.invoke(signature=SIGNATURE + ending), 0,
                       {'captured_match': True, 'candidate_match': True})
        self.check(self.invoke(key=DEMO_KEY + b'\n'), 1,
                   {'captured_match': False, 'candidate_match': False})

    def test_empty_bodies_are_supported(self):
        signature = b'sha256=' + hmac.digest(DEMO_KEY, b'', 'sha256').hex().encode()
        self.check(self.invoke(signature=signature, captured=b'', candidate=b''), 0,
                   {'captured_match': True, 'candidate_match': True})

    def test_invalid_signatures_and_limits(self):
        invalid = {'status': 'invalid'}
        for signature in [b'', SIGNATURE + b'\n\n', SIGNATURE[:-1], SIGNATURE.upper(),
                          SIGNATURE + b' ', b'sha256=' + b'x' * 64]:
            self.check(self.invoke(signature=signature), 2, invalid)
        self.check(self.invoke(key=b''), 2, invalid)
        self.check(self.invoke(key=b'x' * 4097), 2, invalid)
        self.check(self.invoke(candidate=b'x' * (1048576 + 1)), 2, invalid)

    def test_every_argument_is_checked_before_file_access(self):
        import webhook_body_witness as tool

        for i in range(4):
            for bad in ['https://example.test/x', r'/\server\x', r'\Device\Mup\host',
                        r'\SystemRoot\x', '/GlobalRoot/x', r'\GlobalRoot.\x',
                        r'\folder\..\Device\x', 'NUL .txt', 'C:relative']:
                args = ['local'] * 4
                args[i] = bad
                with self.subTest(i=i, bad=bad), patch.object(tool.os, 'stat',
                        side_effect=AssertionError('stat called')), patch.object(tool, 'emit', return_value=2):
                    self.assertEqual(tool.main(args), 2)

    def test_closed_stdout(self):
        for args in (['--help'], []):
            reader, writer = os.pipe()
            os.close(reader)
            with os.fdopen(writer, 'wb') as pipe:
                result = subprocess.run([sys.executable, '-B', SCRIPT, *args], cwd=ROOT,
                                        stdout=pipe, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual((result.returncode, result.stderr), (2, b''))
