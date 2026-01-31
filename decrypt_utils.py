# decrypt_utils.py
from Crypto.Cipher import AES

# ----------------------------------------------------
# AES-256-CBC KEYS (converted from your keys.js)
# ----------------------------------------------------

from utils.encKey import AES_KEY, AES_IV

# ----------------------------------------------------
# AES-256-CBC KEYS (Imported from utils/encKey.py)
# ----------------------------------------------------

# AES_KEY and AES_IV are imported above



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

    print("AES_KEY:", AES_KEY.hex())
    print("AES_IV:", AES_IV.hex())

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



