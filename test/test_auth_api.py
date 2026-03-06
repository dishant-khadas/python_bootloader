"""
Test Suite for auth_api Module (login_api function).

All tests mock the HTTP layer so no real network calls are made.
Covers the three code paths: success, login_failed, and network errors.

Run with:
    python test/test_auth_api.py
or:
    pytest test/test_auth_api.py -v
"""

import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.auth_api import login_api


# ---------------------------------------------------------------------------
# Happy path — successful login
# ---------------------------------------------------------------------------

def test_login_api_success():
    """200 response with token → returns (True, token, 'success')."""
    print("Testing login_api success path...")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"token": "jwt_test_token_abc123"}
    mock_resp.text = '{"token":"jwt_test_token_abc123"}'

    with patch("api.auth_api.requests.post", return_value=mock_resp):
        success, result, error_type = login_api("+919876543210", "correctpass")

    assert success == True,              f"Expected True, got {success}"
    assert result == "jwt_test_token_abc123", f"Expected token, got '{result}'"
    assert error_type == "success",      f"Expected 'success', got '{error_type}'"
    print("  ✓ login_api returns (True, token, 'success') on 200 response")


def test_login_api_success_stores_correct_token():
    """The exact token from server response is returned unchanged."""
    print("Testing login_api token passthrough...")

    expected_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"token": expected_token}
    mock_resp.text = f'{{"token":"{expected_token}"}}'

    with patch("api.auth_api.requests.post", return_value=mock_resp):
        _, result, _ = login_api("+919876543210", "pass")

    assert result == expected_token
    print("  ✓ login_api returns exact token string from server")


# ---------------------------------------------------------------------------
# Login failure — bad credentials
# ---------------------------------------------------------------------------

def test_login_api_invalid_credentials_401():
    """Non-200 response → returns (False, error_msg, 'login_failed')."""
    print("Testing login_api with invalid credentials (401)...")

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"message": "Invalid credentials"}
    mock_resp.text = '{"message":"Invalid credentials"}'

    with patch("api.auth_api.requests.post", return_value=mock_resp):
        success, result, error_type = login_api("+919876543210", "wrongpass")

    assert success == False
    assert error_type == "login_failed", f"Expected 'login_failed', got '{error_type}'"
    print("  ✓ login_api returns (False, msg, 'login_failed') on 401")


def test_login_api_200_without_token_key():
    """200 response missing 'token' key → treated as login failure."""
    print("Testing login_api 200 response with no token key...")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"message": "OK but no token"}  # no 'token' key
    mock_resp.text = '{"message":"OK but no token"}'

    with patch("api.auth_api.requests.post", return_value=mock_resp):
        success, result, error_type = login_api("+919876543210", "pass")

    assert success == False
    assert error_type == "login_failed"
    print("  ✓ login_api treats 200-without-token as login_failed")


def test_login_api_500_server_error():
    """500 server error → returns (False, msg, 'login_failed')."""
    print("Testing login_api with 500 server error...")

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.json.return_value = {"error": "Internal Server Error"}
    mock_resp.text = '{"error":"Internal Server Error"}'

    with patch("api.auth_api.requests.post", return_value=mock_resp):
        success, result, error_type = login_api("+919876543210", "pass")

    assert success == False
    assert error_type == "login_failed"
    print("  ✓ login_api treats 500 as login_failed")


# ---------------------------------------------------------------------------
# Network errors
# ---------------------------------------------------------------------------

def test_login_api_connection_error():
    """ConnectionError → returns (False, msg, 'network_error')."""
    print("Testing login_api with ConnectionError (no internet)...")

    import requests as req_lib
    with patch("api.auth_api.requests.post",
               side_effect=req_lib.exceptions.ConnectionError("No route to host")):
        success, result, error_type = login_api("+919876543210", "pass")

    assert success == False
    assert error_type == "network_error", f"Expected 'network_error', got '{error_type}'"
    assert "internet" in result.lower() or "connection" in result.lower()
    print("  ✓ login_api returns 'network_error' on ConnectionError")


def test_login_api_timeout():
    """Request Timeout → returns (False, msg, 'network_error')."""
    print("Testing login_api with Timeout...")

    import requests as req_lib
    with patch("api.auth_api.requests.post",
               side_effect=req_lib.exceptions.Timeout("Request timed out")):
        success, result, error_type = login_api("+919876543210", "pass")

    assert success == False
    assert error_type == "network_error"
    assert "timeout" in result.lower() or "connection" in result.lower()
    print("  ✓ login_api returns 'network_error' on Timeout")


def test_login_api_generic_exception():
    """Unexpected exception → returns (False, msg, 'network_error')."""
    print("Testing login_api with generic exception...")

    with patch("api.auth_api.requests.post",
               side_effect=Exception("Unexpected socket error")):
        success, result, error_type = login_api("+919876543210", "pass")

    assert success == False
    assert error_type == "network_error"
    print("  ✓ login_api returns 'network_error' on generic exception")


# ---------------------------------------------------------------------------
# Return type contract
# ---------------------------------------------------------------------------

def test_login_api_always_returns_three_tuple():
    """login_api must always return a 3-tuple regardless of outcome."""
    print("Testing login_api return type contract...")

    import requests as req_lib

    scenarios = [
        # (mock setup callable, description)
        (lambda: patch("api.auth_api.requests.post",
                       return_value=_make_mock_resp(200, {"token": "t"})), "success"),
        (lambda: patch("api.auth_api.requests.post",
                       return_value=_make_mock_resp(401, {})), "failure"),
        (lambda: patch("api.auth_api.requests.post",
                       side_effect=req_lib.exceptions.ConnectionError()), "error"),
    ]

    for patcher_factory, desc in scenarios:
        with patcher_factory():
            result = login_api("+919876543210", "pass")
            assert isinstance(result, tuple) and len(result) == 3, \
                f"Expected 3-tuple for '{desc}', got {result}"
            assert isinstance(result[0], bool), "First element must be bool"
            assert isinstance(result[1], str),  "Second element must be str"
            assert isinstance(result[2], str),  "Third element must be str"
    print("  ✓ login_api always returns (bool, str, str)")


def _make_mock_resp(status_code: int, json_data: dict) -> MagicMock:
    """Helper: create a mock requests.Response."""
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data
    m.text = str(json_data)
    return m


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_tests():
    print("=" * 60)
    print("auth_api Test Suite")
    print("=" * 60)

    try:
        test_login_api_success()
        test_login_api_success_stores_correct_token()

        test_login_api_invalid_credentials_401()
        test_login_api_200_without_token_key()
        test_login_api_500_server_error()

        test_login_api_connection_error()
        test_login_api_timeout()
        test_login_api_generic_exception()

        test_login_api_always_returns_three_tuple()

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
