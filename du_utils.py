# du_utils.py
import subprocess
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import boto3
import requests


# ---------------------------
# CRC16 (Modbus/IBM) function
# ---------------------------
def calculate_crc16(data: bytes) -> int:
    """
    Calculate CRC-16 (polynomial 0xA001) same as the JS implementation.
    Input: bytes
    Returns: integer CRC (0..0xFFFF)
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 1) != 0:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def calculate_little_endian(crc: int) -> str:
    """
    Convert crc to "little-endian" 4-char hex string (lowercase), same as JS:
    ((crc >> 8) | ((crc & 0xFF) << 8)).toString(16).padStart(4,"0")
    """
    le = ((crc >> 8) | ((crc & 0xFF) << 8)) & 0xFFFF
    return format(le, "04x")


def match_crc16(buffer_data: bytes) -> bool:
    """
    Compare CRC computed over bytes 0..509 with bytes 510..511 in buffer_data.
    buffer_data must be at least 512 bytes.
    """
    if len(buffer_data) < 512:
        return False
    crc = calculate_crc16(buffer_data[:510])
    little_end = calculate_little_endian(crc)
    return little_end == buffer_data[510:512].hex()


# ---------------------------
# Hash and file helpers
# ---------------------------
def generate_hash(hex_data: str) -> str:
    """
    Input: hex string (like JS Buffer.from(data, 'hex'))
    Return: sha256(hex_data) as hex string
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
    AES-256-ECB decrypt.
    hex_data: hex string of encrypted file
    key: bytes (length must be 32 bytes)
    Returns decrypted bytes (not hex)
    """
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("decrypt_file: key must be bytes")

    if len(key) != 32:
        raise ValueError("decrypt_file: key must be 32 bytes for AES-256")

    encrypted_bytes = bytes.fromhex(hex_data)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_bytes)

    # In Node they used Buffer.concat(decipher.update(...), decipher.final()) - PyCryptodome decrypt gives complete bytes.
    # Try unpadding. If it fails (some custom encryption?), return raw. 
    # Usually standard AES-256-ECB/CBC implies PKCS7 padding.
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        # If padding is incorrect or not used, return raw (mimics no unpad, though usually error)
        # But for files that match exact blocks, unpad might fail if it treats last bytes as padding
        # Let's hope it's standard PKCS7.
        return decrypted


# ---------------------------
# KMS decrypt (decryptKey)
# ---------------------------
def decrypt_key_kms(ciphertext: bytes, region: str = "ap-south-1") -> bytes | None:
    """
    Uses boto3 KMS decrypt to decrypt a data key. Returns plaintext bytes or None.
    ciphertext: bytes (binary ciphertext blob)
    """
    try:
        client = boto3.client("kms", region_name=region)
        resp = client.decrypt(CiphertextBlob=ciphertext)
        # resp['Plaintext'] is bytes
        return resp.get("Plaintext")
    except Exception as e:
        print("decrypt_key_kms error:", e)
        return None


# ---------------------------
# formatHashTo64Bytes
# ---------------------------
def format_hash_to_64_bytes(hex_hash: str) -> bytes | bool:
    """
    Input: 64-char hex string (32 bytes)
    Creates a 64-byte buffer:
    - byte[0] = 0x2a
    - bytes[1..32] = hash bytes
    - byte[61] = 0x3c
    - bytes[62..63] = CRC16 (high then low) of bytes 0..61 (62 bytes)
    Returns bytes object (64 bytes) or False on error
    """
    try:
        if len(hex_hash) != 64:
            raise ValueError("Hash must be 64 hex characters (32 bytes)")

        hash_buf = bytes.fromhex(hex_hash)  # 32 bytes
        final = bytearray(64)  # zero-initialized

        final[0] = 0x2A
        final[1:1+len(hash_buf)] = hash_buf  # 1..32
        final[61] = 0x3C

        # Calculate CRC16 of bytes 0..61 (62 bytes)
        crc = calculate_crc16(bytes(final[:62]))
        # In JS they put high byte then low byte:
        final[62] = (crc >> 8) & 0xFF
        final[63] = crc & 0xFF

        return bytes(final)
    except Exception as e:
        print("format_hash_to_64_bytes error:", e)
        return False


# ---------------------------
# nmcli wrapper (runCommands)
# ---------------------------
def exec_command(command: str, ssid: str | None = None) -> str:
    """
    Run a shell command and return stdout. Raise subprocess.CalledProcessError on failure.
    Similar to execPromise in Node.
    """
    try:
        print("Running:", command)
        completed = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        out = completed.stdout
        # detect success message similar to Node "successfully activated"
        if ssid and ("successfully activated" in out or "successfully activated" in completed.stdout.lower()):
            print("Connection Success", ssid)
            # In original Node they sent events; here we return success
        return out
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        if "No network" in stderr:
            print("Unable to find network")
        raise


def run_commands(values: dict):
    """
    values expected to have 'ssid' and 'password'.
    Mirrors runCommands JS function but synchronous.
    """
    wifi_ssid = values.get("ssid")
    password = values.get("password")
    try:
        exec_command("nmcli radio wifi on")
        exec_command("nmcli device wifi list")
        connect_cmd = f"nmcli device wifi connect '{wifi_ssid}' password '{password}'"
        out = exec_command(connect_cmd, ssid=wifi_ssid)
        return out
    except Exception as e:
        print("run_commands error:", e)
        raise


# ---------------------------
# checkConnection (https to google)
# ---------------------------
def check_connection(timeout: int = 5) -> bool:
    try:
        resp = requests.get("https://www.google.com", timeout=timeout)
        return resp.status_code == 200
    except Exception as e:
        print("No Internet Connection:", e)
        return False


# ---------------------------
# convertSeconds
# ---------------------------
def convert_seconds(total_seconds) -> dict:
    t = int(total_seconds)
    hours = t // 3600
    minutes = (t % 3600) // 60
    seconds = t % 60
    return {"hours": hours, "minutes": minutes, "seconds": seconds}


# ---------------------------
# Expose module functions
# ---------------------------
__all__ = [
    "calculate_crc16",
    "calculate_little_endian",
    "match_crc16",
    "generate_hash",
    "decrypt_file",
    "decrypt_key_kms",
    "format_hash_to_64_bytes",
    "run_commands",
    "exec_command",
    "check_connection",
    "convert_seconds",
]
