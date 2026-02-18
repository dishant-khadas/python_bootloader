"""
Test Suite for AppState Singleton Class.

This module provides unit tests for the AppState singleton class,
verifying singleton pattern, thread safety, state management, and
bootloader version extraction from 512-byte data.

Run tests with:
    python test/test_app_state.py
or:
    pytest test/test_app_state.py -v
"""

import sys
import os
import threading
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.app_state import AppState


def test_singleton_pattern():
    """Test that only one instance of AppState exists."""
    print("Testing singleton pattern...")
    
    instance1 = AppState.get_instance()
    instance2 = AppState.get_instance()
    
    assert instance1 is instance2, "Singleton pattern failed: different instances returned"
    print("✓ Singleton pattern works correctly")


def test_auth_state():
    """Test authentication state management."""
    print("\nTesting authentication state...")
    
    state = AppState.get_instance()
    state.reset()
    
    # Set auth
    state.set_auth(phone="+911234567890", token="test_token_123")
    
    assert state.phone_number == "+911234567890", "Phone number not stored correctly"
    assert state.jwt_token == "test_token_123", "JWT token not stored correctly"
    
    print("✓ Authentication state stored correctly")


def test_bootloader_version_extraction():
    """Test bootloader version extraction from 512-byte data."""
    print("\nTesting bootloader version extraction...")
    
    state = AppState.get_instance()
    state.reset()
    
    # Create dummy 512-byte data with bootloader version at bytes 392-393
    buffer_bytes = bytearray(512)
    buffer_bytes[392] = 11  # Version byte 1
    buffer_bytes[393] = 8   # Version byte 2
    
    # Set DU data
    state.set_du_data(
        du_number="99123456",
        display_number="12345678",
        raw_bytes=bytes(buffer_bytes),
        is_encrypted=False,
        encryption_key=None
    )
    
    # Verify extraction
    assert state.bootloader_version == (11, 8), "Bootloader version tuple incorrect"
    assert state.bootloader_version_string == "11.8", "Bootloader version string incorrect"
    assert state.du_number == "99123456", "DU number not stored"
    assert state.display_number == "12345678", "Display number not stored"
    
    print(f"✓ Bootloader version extracted correctly: {state.bootloader_version_string}")


def test_encryption_state():
    """Test encryption state management."""
    print("\nTesting encryption state...")
    
    state = AppState.get_instance()
    state.reset()
    
    # Create 32-byte encryption key
    enc_key = bytes([i % 256 for i in range(32)])
    
    state.is_encryption_enabled = True
    state.encryption_key = enc_key
    
    assert state.is_encryption_enabled == True, "Encryption flag not set"
    assert state.encryption_key == enc_key, "Encryption key not stored"
    assert len(state.encryption_key) == 32, "Encryption key wrong length"
    
    print("✓ Encryption state managed correctly")


def test_firmware_selection():
    """Test firmware selection state."""
    print("\nTesting firmware selection...")
    
    state = AppState.get_instance()
    state.reset()
    
    state.set_firmware_selection("file_id_123", "firmware_v1.2.3.bin")
    
    assert state.selected_file_id == "file_id_123", "File ID not stored"
    assert state.selected_file_name == "firmware_v1.2.3.bin", "File name not stored"
    
    print("✓ Firmware selection stored correctly")


def test_thread_safety():
    """Test thread-safe concurrent access."""
    print("\nTesting thread safety...")
    
    state = AppState.get_instance()
    state.reset()
    
    results = []
    errors = []
    
    def worker(thread_id):
        try:
            for i in range(100):
                # Set values
                state.jwt_token = f"token_{thread_id}_{i}"
                state.phone_number = f"+91{thread_id}{i:04d}"
                
                # Read values (should not raise errors or corrupt data)
                token = state.jwt_token
                phone = state.phone_number
                
                time.sleep(0.001)  # Small delay to increase chance of race conditions
            
            results.append(thread_id)
        except Exception as e:
            errors.append(f"Thread {thread_id}: {e}")
    
    # Create multiple threads
    threads = []
    for i in range(10):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
    
    # Wait for all threads
    for t in threads:
        t.join()
    
    assert len(errors) == 0, f"Thread safety errors: {errors}"
    assert len(results) == 10, "Not all threads completed successfully"
    
    print("✓ Thread safety verified (10 concurrent threads, 100 operations each)")


def test_reset():
    """Test state reset functionality."""
    print("\nTesting state reset...")
    
    state = AppState.get_instance()
    
    # Set all state
    state.set_auth("+911234567890", "token_xyz")
    
    buffer_bytes = bytearray(512)
    buffer_bytes[392] = 12
    buffer_bytes[393] = 5
    state.set_du_data("99111111", "12222222", bytes(buffer_bytes), True, bytes(32))
    state.set_firmware_selection("file_id", "firmware.bin")
    
    # Reset
    state.reset()
    
    # Verify all cleared
    assert state.phone_number is None, "Phone not cleared"
    assert state.jwt_token is None, "Token not cleared"
    assert state.du_number is None, "DU number not cleared"
    assert state.bootloader_version is None, "Bootloader version not cleared"
    assert state.encryption_key is None, "Encryption key not cleared"
    assert state.selected_file_id is None, "File ID not cleared"
    
    print("✓ State reset works correctly")


def test_validation():
    """Test input validation."""
    print("\nTesting input validation...")
    
    state = AppState.get_instance()
    state.reset()
    
    # Test 512-byte validation
    try:
        state.set_du_data("99111111", "12222222", bytes(100), False, None)
        assert False, "Should have raised ValueError for wrong buffer size"
    except ValueError as e:
        assert "Expected 512 bytes" in str(e)
        print("✓ Buffer size validation works")
    
    # Test encryption key size validation
    try:
        state.encryption_key = bytes(16)  # Wrong size
        assert False, "Should have raised ValueError for wrong key size"
    except ValueError as e:
        assert "must be 32 bytes" in str(e)
        print("✓ Encryption key size validation works")


def test_state_summary():
    """Test state summary for debugging."""
    print("\nTesting state summary...")
    
    state = AppState.get_instance()
    state.reset()
    state.set_auth("+911234567890", "token_abc")
    
    summary = state.get_state_summary()
    
    assert summary["has_auth"] == True, "Summary should show auth present"
    assert summary["phone_number"] == "+911234567890", "Summary should show phone"
    assert summary["bootloader_version"] is None, "Summary should show no bootloader version yet"
    
    print(f"✓ State summary works: {summary}")


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("AppState Test Suite")
    print("=" * 60)
    
    try:
        test_singleton_pattern()
        test_auth_state()
        test_bootloader_version_extraction()
        test_encryption_state()
        test_firmware_selection()
        test_thread_safety()
        test_reset()
        test_validation()
        test_state_summary()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED")
        print("=" * 60)
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
