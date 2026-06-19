import _path 
import hashlib
import hmac as std_hmac
import os
import unittest

from primitives.hmac import hmac_sha256_hex, hmac_sha256, compare_digest


def h(s):
    return bytes.fromhex(s)


class TestHMAC(unittest.TestCase):

    def test_rfc4231_vectors(self):
        cases = [
            # (key, data, expected) — RFC 4231 test cases 1-4, 6, 7
            (h("0b" * 20), b"Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (h("aa" * 20), h("dd" * 50),
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (h("0102030405060708090a0b0c0d0e0f10111213141516171819"), h("cd" * 50),
             "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            (h("aa" * 131),
             b"Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            (h("aa" * 131),
             b"This is a test using a larger than block-size key and a larger "
             b"than block-size data. The key needs to be hashed before being "
             b"used by the HMAC algorithm.",
             "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
        ]
        for key, data, expected in cases:
            self.assertEqual(hmac_sha256_hex(key, data), expected)

    def test_compare_digest(self):
        self.assertTrue(compare_digest(b"abcdef", b"abcdef"))
        self.assertFalse(compare_digest(b"abcdef", b"abcdeg"))
        self.assertFalse(compare_digest(b"abc", b"abcd"))

    def test_cross_check_stdlib(self):
        for _ in range(50):
            key = os.urandom(os.urandom(1)[0] + 1)
            msg = os.urandom(os.urandom(1)[0])
            ref = std_hmac.new(key, msg, hashlib.sha256).digest()
            self.assertEqual(hmac_sha256(key, msg), ref)


if __name__ == "__main__":
    unittest.main()
