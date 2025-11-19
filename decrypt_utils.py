# decrypt_utils.py
from Crypto.Cipher import AES

# ----------------------------------------------------
# AES-256-CBC KEYS (converted from your keys.js)
# ----------------------------------------------------

AES_KEY = bytes([
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
])

AES_IV = bytes([
    0x2e, 0xf4, 0x51, 0xf1, 0xde, 0x8a, 0x2f, 0xde,
    0x02, 0xa9, 0xfc, 0x34, 0x72, 0x8d, 0x2a, 0x66
])


# ----------------------------------------------------
# EXACT replica of JS DECRYPT()
# ----------------------------------------------------
def decrypt_hex_block(encrypted_hex: str) -> str:
    """
    Python version of:

    async function Decrypt(encryptedHex) {
        const data = Buffer.from(encryptedHex, "hex");
        const decipher = crypto.createDecipheriv("aes-256-cbc", key, ivKey);
        decipher.setAutoPadding(false);
        let decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
        return decrypted.toString("hex");
    }
    """
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(encrypted_bytes)

    return decrypted.hex()


# ----------------------------------------------------
# EXACT replica of JS Encrypt()
# ----------------------------------------------------
def encrypt_hex_block(plain_hex: str) -> str:
    data = bytes.fromhex(plain_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(data)
    return encrypted.hex()
