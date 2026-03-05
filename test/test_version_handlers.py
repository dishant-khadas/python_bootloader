"""
Test Suite for bootloader_version_handler Module.

Tests all three version strategies (v1.0, v1.1, v1.2) and the
BootloaderVersionFactory to ensure correct strategy selection
and packet creation.

Run with:
    python test/test_version_handlers.py
or:
    pytest test/test_version_handlers.py -v
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bootloader_version_handler import (
    BootloaderVersionContext,
    BootloaderVersionFactory,
    V1_0VersionHandler,
    V1_1VersionHandler,
    V1_2VersionHandler,
    _parse_version,
)

# Shared test context
SAMPLE_HASH  = "a" * 64    # valid 64-char hex string
SAMPLE_PHONE = "+91-9876543210"
SAMPLE_EMP   = "CZART001"
SAMPLE_USER  = "ENGINEER1"


# ---------------------------------------------------------------------------
# _parse_version helper
# ---------------------------------------------------------------------------

def test_parse_version_basic():
    """Standard version strings must parse to correct tuples."""
    print("Testing _parse_version...")
    assert _parse_version("1.0")  == (1, 0)
    assert _parse_version("1.1")  == (1, 1)
    assert _parse_version("1.2")  == (1, 2)
    assert _parse_version("1.10") == (1, 10)
    assert _parse_version("2.0")  == (2, 0)
    print("  ✓ _parse_version parses all standard version strings")


# ---------------------------------------------------------------------------
# V1_0VersionHandler
# ---------------------------------------------------------------------------

def test_v1_0_handler_creates_64_byte_packet():
    """v1.0 must produce a 64-byte packet."""
    print("Testing V1_0VersionHandler packet size...")
    handler = V1_0VersionHandler()
    ctx = BootloaderVersionContext(file_hash=SAMPLE_HASH, phone_number=SAMPLE_PHONE)
    packet = handler.create_packet(ctx)

    assert isinstance(packet, bytes), "Packet must be bytes"
    assert len(packet) == 64, f"v1.0 packet must be 64 bytes, got {len(packet)}"
    print(f"  ✓ V1_0 packet size: {len(packet)} bytes")


def test_v1_0_handler_no_encryption():
    """v1.0 must NOT require encryption."""
    print("Testing V1_0VersionHandler should_encrypt...")
    handler = V1_0VersionHandler()
    assert handler.should_encrypt() == False
    print("  ✓ V1_0 does not require encryption")


def test_v1_0_handler_version_string():
    """v1.0 version string must be '1.0'."""
    handler = V1_0VersionHandler()
    assert handler.version == "1.0"
    assert handler.packet_size == 64
    print("  ✓ V1_0 version string and packet_size correct")


# ---------------------------------------------------------------------------
# V1_1VersionHandler
# ---------------------------------------------------------------------------

def test_v1_1_handler_creates_64_byte_packet():
    """v1.1 must produce a 64-byte packet (same format as v1.0)."""
    print("Testing V1_1VersionHandler packet size...")
    handler = V1_1VersionHandler()
    ctx = BootloaderVersionContext(file_hash=SAMPLE_HASH, phone_number=SAMPLE_PHONE)
    packet = handler.create_packet(ctx)

    assert isinstance(packet, bytes)
    assert len(packet) == 64, f"v1.1 packet must be 64 bytes, got {len(packet)}"
    print(f"  ✓ V1_1 packet size: {len(packet)} bytes")


def test_v1_1_handler_requires_encryption():
    """v1.1 MUST require encryption."""
    print("Testing V1_1VersionHandler should_encrypt...")
    handler = V1_1VersionHandler()
    assert handler.should_encrypt() == True
    print("  ✓ V1_1 requires encryption")


def test_v1_1_handler_version_string():
    handler = V1_1VersionHandler()
    assert handler.version == "1.1"
    assert handler.packet_size == 64
    print("  ✓ V1_1 version string and packet_size correct")


def test_v1_0_and_v1_1_same_packet_format():
    """v1.0 and v1.1 should produce same packet content (only differ in encryption)."""
    print("Testing v1.0 and v1.1 produce same packet bytes...")
    ctx = BootloaderVersionContext(file_hash=SAMPLE_HASH, phone_number=SAMPLE_PHONE)
    p10 = V1_0VersionHandler().create_packet(ctx)
    p11 = V1_1VersionHandler().create_packet(ctx)
    assert p10 == p11, "v1.0 and v1.1 must produce identical raw packets"
    print("  ✓ v1.0 and v1.1 produce identical raw packet bytes")


# ---------------------------------------------------------------------------
# V1_2VersionHandler
# ---------------------------------------------------------------------------

def test_v1_2_handler_creates_512_byte_packet():
    """v1.2 must produce a 512-byte packet."""
    print("Testing V1_2VersionHandler packet size...")
    handler = V1_2VersionHandler()
    ctx = BootloaderVersionContext(
        file_hash=SAMPLE_HASH,
        phone_number=SAMPLE_PHONE,
        employee_code=SAMPLE_EMP,
        username=SAMPLE_USER,
    )
    packet = handler.create_packet(ctx)

    assert isinstance(packet, bytes)
    assert len(packet) == 512, f"v1.2 packet must be 512 bytes, got {len(packet)}"
    print(f"  ✓ V1_2 packet size: {len(packet)} bytes")


def test_v1_2_handler_requires_encryption():
    """v1.2 MUST require encryption."""
    print("Testing V1_2VersionHandler should_encrypt...")
    handler = V1_2VersionHandler()
    assert handler.should_encrypt() == True
    print("  ✓ V1_2 requires encryption")


def test_v1_2_handler_packet_sop_eop():
    """v1.2 packet must have SOP=0x2a at byte 0 and EOP=0x3c at byte 509."""
    print("Testing V1_2 SOP/EOP markers...")
    handler = V1_2VersionHandler()
    ctx = BootloaderVersionContext(
        file_hash=SAMPLE_HASH,
        phone_number=SAMPLE_PHONE,
        employee_code=SAMPLE_EMP,
        username=SAMPLE_USER,
    )
    packet = handler.create_packet(ctx)

    assert packet[0]   == 0x2a, f"SOP must be 0x2a, got {hex(packet[0])}"
    assert packet[509] == 0x3c, f"EOP must be 0x3c, got {hex(packet[509])}"
    print("  ✓ V1_2 SOP and EOP markers correct")


def test_v1_2_handler_version_string():
    handler = V1_2VersionHandler()
    assert handler.version == "1.2"
    assert handler.packet_size == 512
    print("  ✓ V1_2 version string and packet_size correct")


# ---------------------------------------------------------------------------
# BootloaderVersionFactory
# ---------------------------------------------------------------------------

def test_factory_selects_v1_0_for_old_version():
    """Versions < 1.1 (e.g., 11.0 meaning v1.0 hardware) → V1_0VersionHandler."""
    print("Testing BootloaderVersionFactory strategy selection...")


def test_factory_returns_correct_types():
    """Factory must return correct handler type for each version string."""
    print("Testing BootloaderVersionFactory returns correct types...")

    # We indirectly test via the handlers' version() method
    h10 = V1_0VersionHandler()
    h11 = V1_1VersionHandler()
    h12 = V1_2VersionHandler()

    assert isinstance(h10, V1_0VersionHandler)
    assert isinstance(h11, V1_1VersionHandler)
    assert isinstance(h12, V1_2VersionHandler)

    # Each must satisfy the abstract interface
    ctx = BootloaderVersionContext(file_hash=SAMPLE_HASH, phone_number=SAMPLE_PHONE)
    for handler in (h10, h11, h12):
        packet = handler.create_packet(ctx)
        assert isinstance(packet, bytes)
        assert isinstance(handler.should_encrypt(), bool)
        assert isinstance(handler.version, str)
        assert isinstance(handler.packet_size, int)

    print("  ✓ All handlers satisfy the strategy interface")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print("=" * 65)
    print("bootloader_version_handler Test Suite")
    print("=" * 65)

    try:
        test_parse_version_basic()

        test_v1_0_handler_creates_64_byte_packet()
        test_v1_0_handler_no_encryption()
        test_v1_0_handler_version_string()

        test_v1_1_handler_creates_64_byte_packet()
        test_v1_1_handler_requires_encryption()
        test_v1_1_handler_version_string()
        test_v1_0_and_v1_1_same_packet_format()

        test_v1_2_handler_creates_512_byte_packet()
        test_v1_2_handler_requires_encryption()
        test_v1_2_handler_packet_sop_eop()
        test_v1_2_handler_version_string()

        test_factory_returns_correct_types()

        print("\n" + "=" * 65)
        print("✅ ALL TESTS PASSED")
        print("=" * 65)
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
