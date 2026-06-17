import _path  
import hashlib
import os
import unittest

from primitives.sha256 import sha256, sha256_hex, SHA256


class TestSHA256(unittest.TestCase):

    def test_official_vectors(self):
        vectors = {
            b"abc":
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            b"":
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        }
        for msg, expected in vectors.items():
            self.assertEqual(sha256_hex(msg), expected)

    def test_long_message(self):
        # One million 'a' characters (NIST long test).
        self.assertEqual(
            sha256_hex(b"a" * 1_000_000),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        )

    def test_incremental_matches_oneshot(self):
        data = b"the quick brown fox jumps over the lazy dog"
        h = SHA256()
        for byte in data:
            h.update(bytes([byte]))
        self.assertEqual(h.digest(), sha256(data))

    def test_cross_check_hashlib(self):
        for _ in range(50):
            data = os.urandom(os.urandom(1)[0])
            self.assertEqual(sha256(data), hashlib.sha256(data).digest())


if __name__ == "__main__":
    unittest.main()
