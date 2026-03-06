"""
Test Suite for system_utils Module.

Tests convert_seconds (pure logic) and mocked exec_command /
check_connection without making real network or subprocess calls.

Run with:
    python test/test_system_utils.py
or:
    pytest test/test_system_utils.py -v
"""

import sys
import os
import subprocess
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.system_utils import convert_seconds, exec_command, check_connection


# ---------------------------------------------------------------------------
# convert_seconds — pure math, no mocking needed
# ---------------------------------------------------------------------------

def test_convert_seconds_zero():
    """Zero seconds → all fields zero."""
    print("Testing convert_seconds(0)...")
    result = convert_seconds(0)
    assert result == {"hours": 0, "minutes": 0, "seconds": 0}
    print("  ✓ convert_seconds(0) = {hours:0, minutes:0, seconds:0}")


def test_convert_seconds_exact_minute():
    """60 seconds → 1 minute, 0 seconds."""
    print("Testing convert_seconds(60)...")
    result = convert_seconds(60)
    assert result == {"hours": 0, "minutes": 1, "seconds": 0}
    print("  ✓ convert_seconds(60) = {hours:0, minutes:1, seconds:0}")


def test_convert_seconds_exact_hour():
    """3600 seconds → 1 hour, 0 minutes, 0 seconds."""
    print("Testing convert_seconds(3600)...")
    result = convert_seconds(3600)
    assert result == {"hours": 1, "minutes": 0, "seconds": 0}
    print("  ✓ convert_seconds(3600) = {hours:1, minutes:0, seconds:0}")


def test_convert_seconds_mixed():
    """3661 seconds → 1 hour, 1 minute, 1 second."""
    print("Testing convert_seconds(3661)...")
    result = convert_seconds(3661)
    assert result == {"hours": 1, "minutes": 1, "seconds": 1}
    print("  ✓ convert_seconds(3661) = {hours:1, minutes:1, seconds:1}")


def test_convert_seconds_large_value():
    """90061 seconds → 25 hours, 1 minute, 1 second."""
    print("Testing convert_seconds(90061)...")
    result = convert_seconds(90061)
    assert result == {"hours": 25, "minutes": 1, "seconds": 1}
    print("  ✓ convert_seconds(90061) = {hours:25, minutes:1, seconds:1}")


def test_convert_seconds_returns_dict_with_correct_keys():
    """Return value must always have exactly three specific keys."""
    print("Testing convert_seconds return structure...")
    result = convert_seconds(42)
    assert set(result.keys()) == {"hours", "minutes", "seconds"}
    print("  ✓ convert_seconds returns dict with correct keys")


def test_convert_seconds_with_float_input():
    """Float seconds should be cast to int before conversion."""
    print("Testing convert_seconds with float input...")
    result = convert_seconds(90.9)  # should behave like 90
    assert result == {"hours": 0, "minutes": 1, "seconds": 30}
    print("  ✓ convert_seconds handles float input correctly")


# ---------------------------------------------------------------------------
# exec_command — mocked subprocess
# ---------------------------------------------------------------------------

def test_exec_command_string_mode_success():
    """String command mode (shell=True) returns stdout on success."""
    print("Testing exec_command string mode...")

    mock_result = MagicMock()
    mock_result.stdout = "command output"
    mock_result.returncode = 0

    with patch("utils.system_utils.subprocess.run", return_value=mock_result) as mock_run:
        output = exec_command("echo hello")
        assert output == "command output"
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") == True
    print("  ✓ exec_command string mode calls shell=True and returns stdout")


def test_exec_command_array_mode_success():
    """Array command mode (use_array=True) uses shell=False."""
    print("Testing exec_command array mode (secure)...")

    mock_result = MagicMock()
    mock_result.stdout = "array output"
    mock_result.returncode = 0

    cmd = ["nmcli", "radio", "wifi", "on"]

    with patch("utils.system_utils.subprocess.run", return_value=mock_result) as mock_run:
        output = exec_command(cmd, use_array=True)
        assert output == "array output"
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") == False
    print("  ✓ exec_command array mode uses shell=False (secure)")


def test_exec_command_failure_raises():
    """Failed subprocess must propagate CalledProcessError."""
    print("Testing exec_command failure raises...")

    err = subprocess.CalledProcessError(1, "bad_command", stderr="error msg")

    with patch("utils.system_utils.subprocess.run", side_effect=err):
        try:
            exec_command("bad_command")
            assert False, "Should have raised CalledProcessError"
        except subprocess.CalledProcessError:
            print("  ✓ exec_command propagates CalledProcessError")


def test_exec_command_invalid_array_mode_raises():
    """use_array=True with a list but bad command raises CalledProcessError."""
    print("Testing exec_command with bad array command...")

    bad_cmd = ["this_command_does_not_exist_xyz"]
    err = subprocess.CalledProcessError(127, bad_cmd, stderr="not found")

    with patch("utils.system_utils.subprocess.run", side_effect=err):
        try:
            exec_command(bad_cmd, use_array=True)
            assert False, "Should have raised CalledProcessError"
        except subprocess.CalledProcessError:
            print("  ✓ exec_command propagates CalledProcessError for bad array command")


# ---------------------------------------------------------------------------
# check_connection — mocked requests
# ---------------------------------------------------------------------------

def test_check_connection_returns_true_on_200():
    """Returns True when Google responds with 200."""
    print("Testing check_connection when internet available...")

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("utils.system_utils.requests.get", return_value=mock_resp):
        result = check_connection()
        assert result == True
    print("  ✓ check_connection returns True on HTTP 200")


def test_check_connection_returns_false_on_non_200():
    """Returns False for non-200 status codes."""
    print("Testing check_connection on non-200 response...")

    mock_resp = MagicMock()
    mock_resp.status_code = 503

    with patch("utils.system_utils.requests.get", return_value=mock_resp):
        result = check_connection()
        assert result == False
    print("  ✓ check_connection returns False on non-200 status")


def test_check_connection_returns_false_on_exception():
    """Returns False when network request raises any exception."""
    print("Testing check_connection when exception raised...")

    with patch("utils.system_utils.requests.get", side_effect=Exception("No route to host")):
        result = check_connection()
        assert result == False
    print("  ✓ check_connection returns False on network exception")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print("=" * 60)
    print("system_utils Test Suite")
    print("=" * 60)

    try:
        test_convert_seconds_zero()
        test_convert_seconds_exact_minute()
        test_convert_seconds_exact_hour()
        test_convert_seconds_mixed()
        test_convert_seconds_large_value()
        test_convert_seconds_returns_dict_with_correct_keys()
        test_convert_seconds_with_float_input()

        test_exec_command_string_mode_success()
        test_exec_command_array_mode_success()
        test_exec_command_failure_raises()
        test_exec_command_invalid_array_mode_raises()

        test_check_connection_returns_true_on_200()
        test_check_connection_returns_false_on_non_200()
        test_check_connection_returns_false_on_exception()

        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED")
        print("=" * 60)
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
