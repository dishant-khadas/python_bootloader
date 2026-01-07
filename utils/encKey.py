from Crypto.Cipher import AES
import binascii

# ===== KEY (32 bytes) =====
key = bytes([
    0x60, 0x3d, 0xeb, 0x10, 0x16, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf2, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2b, 0x94, 0x12, 0xa3, 0x09, 0x14, 0xf5, 0xf4
])

# ===== IV (16 bytes) =====
iv = bytes([
    0x2e, 0xf2, 0x52, 0xf1, 0xde, 0x8a, 0x2f, 0xd2,
    0x02, 0xa9, 0xf2, 0x34, 0x72, 0x6d, 0x2a, 0x66
])

# ===== HEX DATA (must be multiple of 16 bytes) =====
# hex_data = (
#     "2a05e69ec000b71b00a37f196c552e9ad401f83bc2776e449d0abe88104f2ca9"
#     "6b31f1d760938e251172c8549f0de36ab1485e22917dc30fa86f33e918742a5b"
#     "9cd140668bf02da47c135a99ce08e76d3491bf520a7ed81fc645882b9e03a174"
#     "6fd05cb8197de462900fa53ec18a4d17736b2e98d5f9401ca7568e03c972bf2a6"
#     "49de1305f88a417c67b0d539e41f26ab70cd82599e5134a7f902b6dc158a8f403"
#     "729c1e6fd5b08842a17d9f306ce4125b780ad194f8235e6ac70db94177a3189e6"
#     "42c0f5588d24b7f139ca0e65a318d026fb1c4990e5772da18f03e85647c2ba9d6"
#     "419f08e36d1574c8539a0fb24e7a1d90e8665f2ca13899c70b5e742a8df46119b"
#     "09c536ed1a840720f2bc95d7a1388e460f19e34a7c25b0d6f941872a9e3418f60"
#     "7c1d53b899e42f0a6b459c31d7a180f25e1874c63b9f0da852e16f2590487a1cd"
#     "4b35f88e9026da59c40721bf0e634887f5a13c299d80e614ba1f52d789e406c1f"
#     "b70a558ed12374c960a45b9f186a2cd741e8905e13b1779df034a8621c7be450"
#     "990d5f742a6ec19813a74bf890325d7c1ea46f8819c3532d749f60a138e70b66"
#     "7ad841905e2bc9f418739c0da56f34e188521ab7609f2c4578d40ea1536bc899"
#     "1d72f03e5f842a9ed741608815c374a90f6d2be19c507a34b81f8853c72d996fa"
#     "40e1874e5905b13c8417f2a9ed1660fb3749c2da85e18f4603c0e6b"
# )

# plaintext = bytes.fromhex(hex_data)

# # 🔒 SAFETY CHECK
# assert len(plaintext) % 16 == 0, "Plaintext must be multiple of 16 bytes"

# cipher = AES.new(key, AES.MODE_CBC, iv)
# ciphertext = cipher.encrypt(plaintext)

# print("Plaintext length:", len(plaintext))
# print("Ciphertext length:", len(ciphertext))
# print("Encrypted HEX:")
# print(binascii.hexlify(ciphertext).decode())
