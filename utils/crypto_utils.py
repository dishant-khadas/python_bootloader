"""
Cryptographic Utilities for Python Bootloader Application.

Provides SHA-256 hashing, AES-256-ECB firmware decryption, and
AWS KMS key decryption. Previously part of the monolithic du_utils.py.

Functions:
    generate_hash: SHA-256 hash of hex-encoded data.
    decrypt_file: AES-256-ECB firmware file decryption.
    decrypt_key_kms: AWS KMS data key decryption.
"""

import hashlib
import boto3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from utils.logger import logger


def generate_hash(hex_data: str) -> str:
    """
    Generate SHA-256 hash of hex-encoded data.
    
    Args:
        hex_data (str): Hex string of data to hash.
        
    Returns:
        str: SHA-256 hash as 64-character hex string.
        
    Raises:
        ValueError: If hex_data is not valid hexadecimal.
    """
    try:
        file_bytes = bytes.fromhex(hex_data)
    except Exception as e:
        raise ValueError(f"generate_hash: invalid hex data: {e}")

    h = hashlib.sha256()
    h.update(file_bytes)
    return h.hexdigest()


def decrypt_file(hex_data: str, key: bytes) -> bytes:
    """
    Decrypt firmware file using AES-256-ECB.
    
    Args:
        hex_data (str): Hex string of encrypted file data.
        key (bytes): 32-byte AES key.
        
    Returns:
        bytes: Decrypted file content.
        
    Raises:
        ValueError: If key is not bytes or not 32 bytes long.
        
    Note:
        Attempts PKCS7 unpadding. If unpadding fails (custom padding
        or exact block alignment), returns raw decrypted data.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("decrypt_file: key must be bytes")

    if len(key) != 32:
        raise ValueError("decrypt_file: key must be 32 bytes for AES-256")

    encrypted_bytes = bytes.fromhex(hex_data)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_bytes)

    # Attempt PKCS7 unpadding
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        # If padding is incorrect, return raw decrypted data
        return decrypted


def decrypt_key_kms(ciphertext: bytes, region: str = "ap-south-1") -> bytes | None:
    """
    Decrypt a data encryption key using AWS KMS.
    
    Uses the AWS KMS decrypt API to decrypt a ciphertext blob that
    was previously encrypted with a KMS customer master key.
    
    Args:
        ciphertext (bytes): Encrypted key ciphertext blob.
        region (str): AWS region for KMS. Default is "ap-south-1".
        
    Returns:
        bytes | None: Decrypted key bytes, or None on error.
    """
    try:
        client = boto3.client("kms", region_name=region)
        resp = client.decrypt(CiphertextBlob=ciphertext)
        return resp.get("Plaintext")
    except Exception as e:
        logger.error(f"decrypt_key_kms error: {e}")
        return None


__all__ = [
    "generate_hash",
    "decrypt_file",
    "decrypt_key_kms",
]
