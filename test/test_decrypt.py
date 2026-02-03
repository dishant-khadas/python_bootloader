# #!/usr/bin/env python3
# """
# Test decryption with the same data as JavaScript
# """

# from Crypto.Cipher import AES

# # Keys from user's JavaScript code

# # ===== KEY (32 bytes) =====


# # ===== KEY (32 bytes) =====
# AES_KEY = bytes([
#     0x60, 0x3d, 0xeb, 0x10, 0x16, 0xca, 0x71, 0xbe,
#     0x2b, 0x73, 0xae, 0xf2, 0x85, 0x7d, 0x77, 0x81,
#     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
#     0x2b, 0x94, 0x12, 0xa3, 0x09, 0x14, 0xf5, 0xf4
# ])

# # ===== IV (16 bytes) =====
# AES_IV = bytes([
#     0x2e, 0xf4, 0x51, 0xf1, 0xde, 0x8a, 0x2f, 0xde,
#     0x02, 0xa9, 0xfc, 0x34, 0x72, 0x8d, 0x2a, 0x66
# ])


# # Test data from your hardware
# encrypted_hex = "db0435df103dfd77b2e1b45b06f343e6baf3ac5ec8f68d4daa046661b2f70153e2e2d246c9c9bd00d8cfdbcbfa567a47631c36ab51ada14b6b86081b51d862203d187183aefe23409c05e512dc41f66175da90945ab6c258b5e53a7905c0e8c40b4a7acd4f92729fefa149982449fb40973fd03e727dce219f20f85646cf9a275788e81cc73ce986a6aa2d2418b9f4adcd5dfd9fc77d4b47d257e82af781ef3f94effeb824cea0ccdd88f04605c61ae02726f5cc11e1e844582d5ec5e510c363e619703de07a90ab4547ad732ca2390edfb9769fd1523e21b2341275bbe569f7e3f28f2d70edecf70f0abf3a9ee766010c17ad54cc412f008e94f33b8a79370bf40d8013fa4ad5a1fe509dfc82dc891bcacfd933231ece42ff97351ae249c22b0e18c0821bee09833b648bd21e3d6ee8957a68094d0c335aca47fe66260e2eba021dc0fe44583722514b65a2c3f1e9691e601ef2ef5a51138e9354e9cf70246c9228e805ec7d84acc4e5d87bc6426c5c35c74a5e2b68cb8b0cbffa5ea64a594bd6634d2f2c5ea28b50ea760764791eba9a22bec6e14b5924d77df97ba8fdedd008b436a5f05e5b2500c974937ec33846be798285db23b9a24dc312f0c979b39c8c7403fe2347478ad85db0f15f3af20cf98d95a20f4a9db1822ddc8925cc64863438aa7edd30331b1a55b8f585bc5ce7fa512a6446c62869cf8fa00495190b20"

# print("=" * 60)
# print("AES-256-CBC Decryption Test")
# print("=" * 60)

# print(f"\nAES_KEY (hex): {AES_KEY.hex()}")
# print(f"AES_IV (hex):  {AES_IV.hex()}")
# print(f"\nEncrypted data length: {len(encrypted_hex)} hex chars = {len(encrypted_hex)//2} bytes")

# # Decrypt
# encrypted_bytes = bytes.fromhex(encrypted_hex)
# cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
# decrypted = cipher.decrypt(encrypted_bytes)

# print(f"\n{'=' * 60}")
# print("DECRYPTED OUTPUT:")
# print("=" * 60)
# print(decrypted.hex())

# print(f"\n{'=' * 60}")
# print("FIRST BYTES CHECK:")
# print("=" * 60)
# print(f"Byte 0 (SOP):   {decrypted[0]:02x} (should be 2a)")
# print(f"Byte 509 (EOP): {decrypted[509]:02x} (should be 3c)")


from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

# Key (32 bytes for AES-256)
key = bytes([
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
  0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
  0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
])

# IV (16 bytes)
iv = bytes([
  0x2e, 0xf4, 0x51, 0xf1, 0xde, 0x8a, 0x2f, 0xde, 0x02, 0xa9, 0xfc, 0x34, 0x72,
  0x8d, 0x2a, 0x66,
])

def decrypt(encrypted_hex: str) -> str:
    encrypted_bytes = unhexlify(encrypted_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)

    # same as decrypted.toString("hex") in Node.js
    return hexlify(decrypted_bytes).decode("utf-8")


# ---- Test ----
encrypted_hex = "db0435df103dfd77b2e1b45b06f343e6baf3ac5ec8f68d4daa046661b2f70153e2e2d246c9c9bd00d8cfdbcbfa567a47631c36ab51ada14b6b86081b51d862203d187183aefe23409c05e512dc41f66175da90945ab6c258b5e53a7905c0e8c40b4a7acd4f92729fefa149982449fb40973fd03e727dce219f20f85646cf9a275788e81cc73ce986a6aa2d2418b9f4adcd5dfd9fc77d4b47d257e82af781ef3f94effeb824cea0ccdd88f04605c61ae02726f5cc11e1e844582d5ec5e510c363e619703de07a90ab4547ad732ca2390edfb9769fd1523e21b2341275bbe569f7e3f28f2d70edecf70f0abf3a9ee766010c17ad54cc412f008e94f33b8a79370bf40d8013fa4ad5a1fe509dfc82dc891bcacfd933231ece42ff97351ae249c22b0e18c0821bee09833b648bd21e3d6ee8957a68094d0c335aca47fe66260e2eba021dc0fe44583722514b65a2c3f1e9691e601ef2ef5a51138e9354e9cf70246c9228e805ec7d84acc4e5d87bc6426c5c35c74a5e2b68cb8b0cbffa5ea64a594bd6634d2f2c5ea28b50ea760764791eba9a22bec6e14b5924d77df97ba8fdedd008b436a5f05e5b2500c974937ec33846be798285db23b9a24dc312f0c979b39c8c7403fe2347478ad85db0f15f3af20cf98d95a20f4a9db1822ddc8925cc64863438aa7edd30331b1a55b8f585bc5ce7fa512a6446c62869cf8fa00495190b20"

# print(decrypt(encrypted_hex))
