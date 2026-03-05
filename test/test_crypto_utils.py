"""
Test Suite for crypto_utils Module.

Tests SHA-256 hashing, AES-256-ECB firmware decryption, and
input validation without any hardware dependencies.

Run with:
    python test/test_crypto_utils.py
or:
    pytest test/test_crypto_utils.py -v
"""

import sys
import os
import hashlib
from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.crypto_utils import generate_hash, decrypt_file


# ---------------------------------------------------------------------------
# generate_hash tests
# ---------------------------------------------------------------------------

def test_generate_hash_known_value():
    """SHA-256 of known hex data must match expected digest."""
    print("Testing generate_hash with known value...")

    # b'hello' in hex
    hex_data = "68656c6c6f"
    expected = hashlib.sha256(b"hello").hexdigest()

    result = generate_hash(hex_data)

    assert result == expected, f"Hash mismatch: {result} != {expected}"
    assert len(result) == 64, "SHA-256 digest must be 64 hex chars"
    print(f"  ✓ generate_hash correct: {result[:16]}...")


def test_generate_hash_empty_bytes():
    """SHA-256 of empty bytes (empty hex string)."""
    print("Testing generate_hash with empty hex...")

    empty_hex = ""
    expected = hashlib.sha256(b"").hexdigest()
    result = generate_hash(empty_hex)

    assert result == expected
    print("  ✓ generate_hash handles empty hex correctly")


def test_generate_hash_returns_lowercase_hex():
    """Returned digest must be lowercase hexadecimal."""
    print("Testing generate_hash output format...")

    result = generate_hash("deadbeef")
    assert result == result.lower(), "Digest must be lowercase"
    assert all(c in "0123456789abcdef" for c in result), "Digest must be hex chars only"
    print("  ✓ generate_hash output is lowercase hex")


def test_generate_hash_invalid_hex_raises():
    """Non-hex input must raise ValueError."""
    print("Testing generate_hash with invalid hex...")

    try:
        generate_hash("ZZZZ_not_hex")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  ✓ generate_hash raises ValueError for invalid hex")


# ---------------------------------------------------------------------------
# decrypt_file tests
# ---------------------------------------------------------------------------

def _make_encrypted_block(plaintext: bytes, key: bytes) -> str:
    """Helper: AES-256-ECB encrypt plaintext and return hex string."""
    # Pad to 16-byte block boundary
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(padded)
    return encrypted.hex()


def test_decrypt_file_basic_roundtrip():
    """Encrypt then decrypt must recover original plaintext."""
    print("Testing decrypt_file basic roundtrip...")

    key = bytes(range(32))  # 32 deterministic bytes
    plaintext = b"CZAR_BOOTLOADER_FIRMWARE_TEST_OK"

    encrypted_hex = _make_encrypted_block(plaintext, key)
    result = decrypt_file(encrypted_hex, key)

    assert result == plaintext, f"Plaintext mismatch: {result}"
    print("  ✓ decrypt_file roundtrip successful")


def test_decrypt_file_wrong_key_length_raises():
    """Key shorter or longer than 32 bytes must raise ValueError."""
    print("Testing decrypt_file with wrong key length...")

    bad_key_16 = bytes(16)
    bad_key_48 = bytes(48)
    dummy_hex = "00" * 16

    for bad_key in (bad_key_16, bad_key_48):
        try:
            decrypt_file(dummy_hex, bad_key)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "32 bytes" in str(e), f"Unexpected error message: {e}"

    print("  ✓ decrypt_file raises ValueError for wrong key length")


def test_decrypt_file_key_must_be_bytes():
    """Passing a string key must raise ValueError."""
    print("Testing decrypt_file with non-bytes key...")

    try:
        decrypt_file("deadbeef" * 4, "a" * 32)  # string key
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "bytes" in str(e).lower()
    print("  ✓ decrypt_file raises ValueError for non-bytes key")


def test_decrypt_file_different_keys_give_different_output():
    """Two distinct keys must produce different decrypted content."""
    print("Testing decrypt_file with different keys...")

    key1 = bytes(range(32))
    key2 = bytes(reversed(range(32)))
    plaintext = b"TEST_FIRMWARE_BLOCK_16B!"  # 24 bytes

    encrypted_hex = _make_encrypted_block(plaintext, key1)

    result1 = decrypt_file(encrypted_hex, key1)
    result2 = decrypt_file(encrypted_hex, key2)

    assert result1 != result2, "Different keys must yield different outputs"
    print("  ✓ decrypt_file produces different output for different keys")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print("=" * 60)
    print("crypto_utils Test Suite")
    print("=" * 60)

    try:
        test_generate_hash_known_value()
        test_generate_hash_empty_bytes()
        test_generate_hash_returns_lowercase_hex()
        test_generate_hash_invalid_hex_raises()

        test_decrypt_file_basic_roundtrip()
        test_decrypt_file_wrong_key_length_raises()
        test_decrypt_file_key_must_be_bytes()
        test_decrypt_file_different_keys_give_different_output()

        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED")
        print("=" * 60)
        return True

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback; traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback; traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
