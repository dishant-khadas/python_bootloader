"""
Decryption and Encryption Utilities Module for Python Bootloader Application.

This module provides AES-256-CBC encryption and decryption functions used for
securing firmware data during the bootloader update process.

These functions are Python ports of the original JavaScript implementations,
maintaining byte-level compatibility with the Node.js version.

Algorithm: AES-256-CBC (Cipher Block Chaining)
Key Size: 256 bits (32 bytes)
IV Size: 128 bits (16 bytes)

Security Note:
    AES keys are imported from utils/encKey.py and should be kept secure.
    Never commit encryption keys to version control.

Functions:
    decrypt_hex_block: Decrypt a hex-encoded encrypted block.
    encrypt_hex_block: Encrypt a hex-encoded plaintext block.
"""

from Crypto.Cipher import AES
from utils.encKey import AES_KEY, AES_IV


def decrypt_hex_block(encrypted_hex: str) -> str:
    """
    Decrypt a hex-encoded encrypted data block using AES-256-CBC.
    
    This is a Python port of the JavaScript Decrypt() function:
    
        async function Decrypt(encryptedHex) {
            const data = Buffer.from(encryptedHex, "hex");
            const decipher = crypto.createDecipheriv("aes-256-cbc", key, ivKey);
            decipher.setAutoPadding(false);
            let decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
            return decrypted.toString("hex");
        }
    
    Args:
        encrypted_hex (str): Hex-encoded string of the encrypted data.
                            Length must be a multiple of 32 (16 bytes = AES block size).
        
    Returns:
        str: Hex-encoded string of the decrypted data.
        
    Note:
        Auto-padding is disabled to match the JavaScript implementation.
        Input length must be a multiple of the AES block size (16 bytes).
    """
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    # SECURITY: Never log actual encryption keys
    print(f"Decrypting with AES key: {len(AES_KEY)} bytes, IV: {len(AES_IV)} bytes")

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(encrypted_bytes)

    return decrypted.hex()


def encrypt_hex_block(plain_hex: str) -> str:
    """
    Encrypt a hex-encoded plaintext block using AES-256-CBC.
    
    This is a Python port of the JavaScript Encrypt() function.
    
    Args:
        plain_hex (str): Hex-encoded string of the plaintext data.
                        Length must be a multiple of 32 (16 bytes = AES block size).
        
    Returns:
        str: Hex-encoded string of the encrypted data.
        
    Note:
        No padding is applied. Input length must be a multiple of 
        the AES block size (16 bytes / 32 hex characters).
    """
    data = bytes.fromhex(plain_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(data)
    return encrypted.hex()
