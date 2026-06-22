import _path  
import unittest

from primitives import x25519 as x25519_mod
x25519 = x25519_mod.x25519
derive_public_key = x25519_mod.derive_public_key
compute_shared_secret = x25519_mod.compute_shared_secret


def h(s):
    return bytes.fromhex(s)


class TestX25519(unittest.TestCase):

    def test_section_5_2_vectors(self):
        # Vector 1
        k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(
            x25519(k, u).hex(),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        # Vector 2
        k = h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        u = h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        self.assertEqual(
            x25519(k, u).hex(),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

    def test_section_6_1_diffie_hellman(self):
        a_priv = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        b_priv = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        a_pub = derive_public_key(a_priv)
        b_pub = derive_public_key(b_priv)
        self.assertEqual(
            a_pub.hex(),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(
            b_pub.hex(),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        self.assertEqual(compute_shared_secret(a_priv, b_pub).hex(), shared)
        self.assertEqual(compute_shared_secret(b_priv, a_pub).hex(), shared)

    def test_iterated_one_round(self):
        # RFC 7748 5.2: after 1 iteration k=u=base point 9.
        k = h("0900000000000000000000000000000000000000000000000000000000000000")
        u = k
        result = x25519(k, u)
        self.assertEqual(
            result.hex(),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")

    def test_iterated_thousand_rounds(self):
        # RFC 7748 5.2: after 1,000 iterations (kept modest to stay fast).
        k = h("0900000000000000000000000000000000000000000000000000000000000000")
        u = k
        for _ in range(1000):
            k, u = x25519(k, u), k
        self.assertEqual(
            k.hex(),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")


if __name__ == "__main__":
    unittest.main()
