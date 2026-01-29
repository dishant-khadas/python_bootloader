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


ans = decrypt_hex_block("db0435df103dfd77b2e1b45b06f343e6baf3ac5ec8f68d4daa046661b2f70153e2e2d246c9c9bd00d8cfdbcbfa567a47631c36ab51ada14b6b86081b51d862203d187183aefe23409c05e512dc41f66175da90945ab6c258b5e53a7905c0e8c40b4a7acd4f92729fefa149982449fb40973fd03e727dce219f20f85646cf9a275788e81cc73ce986a6aa2d2418b9f4adcd5dfd9fc77d4b47d257e82af781ef3f94effeb824cea0ccdd88f04605c61ae02726f5cc11e1e844582d5ec5e510c363e619703de07a90ab4547ad732ca2390edfb9769fd1523e21b2341275bbe569f7e3f28f2d70edecf70f0abf3a9ee766010c17ad54cc412f008e94f33b8a79370bf40d8013fa4ad5a1fe509dfc82dc891bcacfd933231ece42ff97351ae249c22b0e18c0821bee09833b648bd21e3d6ee8957a68094d0c335aca47fe66260e2eba021dc0fe44583722514b65a2c3f1e9691e601ef2ef5a51138e9354e9cf70246c9228e805ec7d84acc4e5d87bc6426c5c35c74a5e2b68cb8b0cbffa5ea64a594bd6634d2f2c5ea28b50ea760764791eba9a22bec6e14b5924d77df97ba8fdedd008b436a5f05e5b2500c974937ec33846be798285db23b9a24dc312f0c979b39c8c7403fe2347478ad85db0f15f3af20cf98d95a20f4a9db1822ddc8925cc64863438aa7edd30331b1a55b8f585bc5ce7fa512a6446c62869cf8fa00495190b20")
print("Decrypted hex:", ans)