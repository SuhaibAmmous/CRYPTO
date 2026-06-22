 

import _path  # noqa: F401
import unittest

from primitives.chacha20 import chacha20_block, chacha20_encrypt, chacha20_decrypt


def h(s):
    return bytes.fromhex(s)


class TestChaCha20(unittest.TestCase):

    def test_block_function(self):
        key = h("000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f")
        nonce = h("000000090000004a00000000")
        block = chacha20_block(key, 1, nonce)
        self.assertEqual(
            block.hex(),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")

    def test_encryption(self):
        key = h("000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f")
        nonce = h("000000000000004a00000000")
        plaintext = (b"Ladies and Gentlemen of the class of '99: If I could "
                     b"offer you only one tip for the future, sunscreen would "
                     b"be it.")
        ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
        self.assertEqual(
            ciphertext.hex(),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42874d")

    def test_round_trip(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        for length in (0, 1, 63, 64, 65, 200):
            pt = bytes((i * 7) & 0xFF for i in range(length))
            ct = chacha20_encrypt(key, 7, nonce, pt)
            self.assertEqual(chacha20_decrypt(key, 7, nonce, ct), pt)


if __name__ == "__main__":
    unittest.main()
