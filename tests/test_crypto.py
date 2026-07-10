import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import hashing, key_derivation, encryption, random_generator


class TestHashing(unittest.TestCase):
    def test_hash_and_verify(self):
        h = hashing.hash_master_password("Sup3rSecret!")
        self.assertTrue(hashing.verify_master_password("Sup3rSecret!", h))

    def test_wrong_password_fails(self):
        h = hashing.hash_master_password("Sup3rSecret!")
        self.assertFalse(hashing.verify_master_password("WrongPassword!", h))


class TestKeyDerivation(unittest.TestCase):
    def test_deterministic_with_same_salt(self):
        salt = key_derivation.generate_kdf_salt()
        k1 = key_derivation.derive_key("password123", salt)
        k2 = key_derivation.derive_key("password123", salt)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_different_salt_different_key(self):
        k1 = key_derivation.derive_key("password123", key_derivation.generate_kdf_salt())
        k2 = key_derivation.derive_key("password123", key_derivation.generate_kdf_salt())
        self.assertNotEqual(k1, k2)


class TestEncryption(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        token = encryption.encrypt("hello world", key)
        self.assertEqual(encryption.decrypt(token, key), "hello world")

    def test_tamper_detection(self):
        key = os.urandom(32)
        token = encryption.encrypt("secret data", key)
        tampered = token[:-4] + "AAAA"
        with self.assertRaises(encryption.DecryptionError):
            encryption.decrypt(tampered, key)

    def test_wrong_key_fails(self):
        key1, key2 = os.urandom(32), os.urandom(32)
        token = encryption.encrypt("secret data", key1)
        with self.assertRaises(encryption.DecryptionError):
            encryption.decrypt(token, key2)


class TestPasswordGenerator(unittest.TestCase):
    def test_default_length(self):
        pw = random_generator.generate_password()
        self.assertEqual(len(pw), 20)

    def test_custom_length(self):
        pw = random_generator.generate_password(length=32)
        self.assertEqual(len(pw), 32)

    def test_uniqueness(self):
        passwords = {random_generator.generate_password() for _ in range(50)}
        self.assertEqual(len(passwords), 50)

    def test_length_bounds(self):
        with self.assertRaises(ValueError):
            random_generator.generate_password(length=4)


if __name__ == "__main__":
    unittest.main()
