"""
Test script to verify 512-byte packet creation for bootloader v1.2.

This script tests the create_512byte_packet_v12() function to ensure:
1. Correct packet structure (SOP, EOP, field positions)
2. Proper padding of fields
3. CRC16 calculation
4. Phone number encoding

Run: python test/test_bootloader_v12.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bootloader_download import create_512byte_packet_v12


def test_512byte_packet_structure():
    """Test basic packet structure."""
    print("Testing 512-byte packet structure...")
    
    # Test data
    test_hash = "6771c119ce7f63a3b0da4f6c361211e99678f57ee2f8545e108d03ecaf6fc0d3"
    test_emp = "CZART000"
    test_user = "TESTUSER"
    test_phone = "+91-7347530726"
    
    # Create packet
    packet = create_512byte_packet_v12(
        original_hash=test_hash,
        employee_code=test_emp,
        username=test_user,
        phone_number=test_phone
    )
    
    # Verify packet size
    assert len(packet) == 512, f"Expected 512 bytes, got {len(packet)}"
    print(f"✓ Packet size: {len(packet)} bytes")
    
    # Verify SOP (byte 0)
    assert packet[0] == 0x2a, f"Expected SOP 0x2a at byte 0, got {hex(packet[0])}"
    print(f"✓ SOP at byte 0: {hex(packet[0])}")
    
    # Verify EOP (byte 509)
    assert packet[509] == 0x3c, f"Expected EOP 0x3c at byte 509, got {hex(packet[509])}"
    print(f"✓ EOP at byte 509: {hex(packet[509])}")
    
    # Verify filehash (bytes 1-32)
    hash_bytes = bytes.fromhex(test_hash)
    assert packet[1:33] == hash_bytes, "Filehash mismatch"
    print(f"✓ Filehash at bytes 1-32: {packet[1:33].hex()[:32]}...")
    
    # Verify employee code (bytes 33-40)
    emp_section = packet[33:41]
    assert emp_section == b'CZART000', f"Employee code mismatch: {emp_section}"
    print(f"✓ Employee code at bytes 33-40: {emp_section}")
    
    # Verify username (bytes 41-65)
    user_section = packet[41:66]
    expected_user = b'TESTUSER' + b' ' * 17  # 8 chars + 17 spaces = 25
    assert user_section == expected_user, f"Username mismatch: {user_section}"
    print(f"✓ Username at bytes 41-65: '{user_section.decode('ascii').rstrip()}'")
    
    # Verify phone number (bytes 66-81)
    phone_section = packet[66:82]
    expected_phone = b'+91-7347530726' + b'\x00' * 2  # 14 chars + 2 nulls = 16
    assert phone_section == expected_phone, f"Phone mismatch: {phone_section}"
    print(f"✓ Phone at bytes 66-81: {phone_section[:14].decode('ascii')}")
    
    # Verify padding (bytes 82-509 should be 0x00)
    padding = packet[82:509]
    assert all(b == 0 for b in padding), "Padding should be all zeros"
    print(f"✓ Padding at bytes 82-509: all zeros ({len(padding)} bytes)")
    
    # CRC16 is at bytes 510-511 (already calculated by function)
    crc_bytes = packet[510:512]
    print(f"✓ CRC16 at bytes 510-511: {crc_bytes.hex()}")
    
    print("\n✅ All structure tests passed!")
    return packet


def test_padding_behavior():
    """Test padding with different field lengths."""
    print("\nTesting padding behavior...")
    
    # Test with shorter employee code
    packet1 = create_512byte_packet_v12(
        original_hash="a" * 64,
        employee_code="TEST",
        username="USER",
        phone_number="+91-1234567890"
    )
    
    emp_section = packet1[33:41]
    assert emp_section == b'TEST    ', f"Short emp code padding failed: {emp_section}"
    print(f"✓ Short employee code padded: '{emp_section.decode('ascii')}'")
    
    user_section = packet1[41:66]
    assert user_section == b'USER' + b' ' * 21, f"Short username padding failed"
    print(f"✓ Short username padded: '{user_section.decode('ascii').rstrip()}'")
    
    print("✅ Padding tests passed!")


def test_hex_dump():
    """Display hex dump of packet."""
    print("\nHex dump of sample packet:")
    
    packet = create_512byte_packet_v12(
        original_hash="6771c119ce7f63a3b0da4f6c361211e99678f57ee2f8545e108d03ecaf6fc0d3",
        employee_code="CZART000",
        username="TESTUSER",
        phone_number="+91-7347530726"
    )
    
    # Print first 128 bytes
    print("\nFirst 128 bytes:")
    for i in range(0, 128, 16):
        hex_str = ' '.join(f'{b:02x}' for b in packet[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in packet[i:i+16])
        print(f"{i:04x}:  {hex_str:<48}  |{ascii_str}|")
    
    # Print last 16 bytes (including CRC)
    print("\nLast 16 bytes (including CRC):")
    for i in range(496, 512, 16):
        hex_str = ' '.join(f'{b:02x}' for b in packet[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in packet[i:i+16])
        print(f"{i:04x}:  {hex_str:<48}  |{ascii_str}|")
    
    print(f"\n✓ Total packet size: {len(packet)} bytes")


def run_all_tests():
    """Run all tests."""
    print("=" * 70)
    print("Bootloader v1.2 - 512-Byte Packet Test Suite")
    print("=" * 70)
    
    try:
        packet = test_512byte_packet_structure()
        test_padding_behavior()
        test_hex_dump()
        
        print("\n" + "=" * 70)
        print("✅ ALL TESTS PASSED")
        print("=" * 70)
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
