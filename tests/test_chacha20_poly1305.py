 

import _path  # noqa: F401
import os
import unittest

from primitives.chacha20_poly1305 import encrypt, decrypt, AEADError


def h(s):
    return bytes.fromhex(s)


class TestChaCha20Poly1305(unittest.TestCase):

    def setUp(self):
        self.key = h("808182838485868788898a8b8c8d8e8f"
                     "909192939495969798999a9b9c9d9e9f")
        self.nonce = h("070000004041424344454647")
        self.aad = h("50515253c0c1c2c3c4c5c6c7")
        self.pt = (b"Ladies and Gentlemen of the class of '99: If I could "
                   b"offer you only one tip for the future, sunscreen would "
                   b"be it.")

    def test_encrypt_vector(self):
        out = encrypt(self.key, self.nonce, self.pt, self.aad)
        ciphertext, tag = out[:-16], out[-16:]
        self.assertEqual(
            ciphertext.hex(),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116")
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")

    def test_decrypt_round_trip(self):
        out = encrypt(self.key, self.nonce, self.pt, self.aad)
        self.assertEqual(decrypt(self.key, self.nonce, out, self.aad), self.pt)

    def test_ciphertext_tamper_rejected(self):
        out = bytearray(encrypt(self.key, self.nonce, self.pt, self.aad))
        out[0] ^= 0x01
        with self.assertRaises(AEADError):
            decrypt(self.key, self.nonce, bytes(out), self.aad)

    def test_aad_tamper_rejected(self):
        out = encrypt(self.key, self.nonce, self.pt, self.aad)
        with self.assertRaises(AEADError):
            decrypt(self.key, self.nonce, out, self.aad + b"\x00")

    def test_random_round_trips(self):
        for _ in range(30):
            pt = os.urandom(os.urandom(1)[0])
            aad = os.urandom(os.urandom(1)[0])
            out = encrypt(self.key, self.nonce, pt, aad)
            self.assertEqual(decrypt(self.key, self.nonce, out, aad), pt)


if __name__ == "__main__":
    unittest.main()
