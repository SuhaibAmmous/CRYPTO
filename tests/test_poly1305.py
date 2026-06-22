  

import _path  # noqa: F401
import unittest

from primitives.poly1305 import poly1305_mac


def h(s):
    return bytes.fromhex(s)


class TestPoly1305(unittest.TestCase):

    def test_rfc8439_2_5_2(self):
        key = h("85d6be7857556d337f4452fe42d506a8"
                "0103808afb0db2fd4abff6af4149f51b")
        msg = b"Cryptographic Forum Research Group"
        self.assertEqual(poly1305_mac(msg, key).hex(),
                         "a8061dc1305136c6c22b8baf0c0127a9")

    def test_appendix_a3_vector_1(self):
        # All-zero key over all-zero message -> all-zero tag.
        key = h("00" * 32)
        msg = h("00" * 64)
        self.assertEqual(poly1305_mac(msg, key).hex(), "00" * 16)

    def test_appendix_a3_vector_2(self):
        key = h("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e")
        msg = (b"Any submission to the IETF intended by the Contributor for "
               b"publication as all or part of an IETF Internet-Draft or RFC "
               b"and any statement made within the context of an IETF activity "
               b"is considered an \"IETF Contribution\". Such statements include "
               b"oral statements in IETF sessions, as well as written and "
               b"electronic communications made at any time or place, which are "
               b"addressed to")
        self.assertEqual(poly1305_mac(msg, key).hex(),
                         "36e5f6b5c5e06070f0efca96227a863e")

    def test_appendix_a3_vector_3(self):
        key = h("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000")
        msg = (b"Any submission to the IETF intended by the Contributor for "
               b"publication as all or part of an IETF Internet-Draft or RFC "
               b"and any statement made within the context of an IETF activity "
               b"is considered an \"IETF Contribution\". Such statements include "
               b"oral statements in IETF sessions, as well as written and "
               b"electronic communications made at any time or place, which are "
               b"addressed to")
        self.assertEqual(poly1305_mac(msg, key).hex(),
                         "f3477e7cd95417af89a6b8794c310cf0")


if __name__ == "__main__":
    unittest.main()
