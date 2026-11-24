import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
import unittest

from src.aes.key_schedule import expand_key
from src.aes.standard_aes import encrypt_block


class TestAESKeySchedule(unittest.TestCase):

    def setUp(self):
        self.key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
        )
    def test_expand_key_count(self):
        round_keys = expand_key(self.key)
        self.assertEqual(len(round_keys), 11)
    def test_round_key_length(self):
        round_keys = expand_key(self.key)
        for round_key in round_keys:
            self.assertEqual(len(round_key), 16)
    def test_first_round_keys(self):
        round_keys = expand_key(self.key)
        self.assertEqual(
            round_keys[0].hex(),
            "000102030405060708090a0b0c0d0e0f"
        )
        self.assertEqual(
            round_keys[1].hex(),
            "d6aa74fdd2af72fadaa678f1d6ab76fe"
        )
    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            expand_key(b"12345678")
class TestAESStandard(unittest.TestCase):
    def test_encrypt_block(self):
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
        )
        plaintext = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
        )
        expected = bytes.fromhex(
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        )
        round_keys = expand_key(key)
        ciphertext = encrypt_block(round_keys, plaintext)

        self.assertEqual(ciphertext, expected)
if __name__ == "__main__":
    unittest.main()
