import pytest
import time
from unittest.mock import patch

from fastapi import HTTPException

from utils.jwt_utils import check_token_expiration, verify_iap_jwt


# Mock utility functions
def mock_verify_iap_jwt(apikey, audience):
    if apikey == "valid-api-key" and audience == "/projects/123/apps/test-app":
        return {"exp": time.time() + 3600}
    raise HTTPException(status_code=401, detail="Invalid API key or audience")


# Tests for `check_token_expiration`
def test_valid_token():
    decoded_jwt = {"exp": time.time() + 3600}
    try:
        check_token_expiration(decoded_jwt)
    except HTTPException:
        pytest.fail("HTTPException was raised for a valid token.")


def test_nearing_expiration_token():
    decoded_jwt = {"exp": time.time() + 200}
    with pytest.raises(HTTPException, match="Token expired or nearing expiration."):
        check_token_expiration(decoded_jwt, threshold=300)


def test_expired_token():
    decoded_jwt = {"exp": time.time() - 10}
    with pytest.raises(HTTPException, match="Token expired or nearing expiration."):
        check_token_expiration(decoded_jwt)


def test_missing_exp_claim():
    decoded_jwt = {}
    with pytest.raises(HTTPException, match="Token does not have an expiration claim"):
        check_token_expiration(decoded_jwt)


# Tests for `verify_iap_jwt`
@patch("utils.jwt_utils.verify_oauth2_token")
@patch("utils.jwt_utils.GoogleAuthRequest")
def test_verify_iap_jwt_success(mock_google_request, mock_verify_oauth2_token):
    mock_verify_oauth2_token.return_value = {"exp": time.time() + 3600}
    decoded_jwt = verify_iap_jwt("valid-token", "test-audience")
    assert decoded_jwt["exp"] > time.time()


@patch("utils.jwt_utils.verify_oauth2_token")
@patch("utils.jwt_utils.GoogleAuthRequest")
def test_verify_iap_jwt_expired(mock_google_request, mock_verify_oauth2_token):
    mock_verify_oauth2_token.return_value = {"exp": time.time() - 10}
    with pytest.raises(HTTPException, match="Unauthorized: Token has expired"):
        verify_iap_jwt("expired-token", "test-audience")


@patch("utils.jwt_utils.verify_oauth2_token")
@patch("utils.jwt_utils.GoogleAuthRequest")
def test_verify_iap_jwt_invalid_token(mock_google_request, mock_verify_oauth2_token):
    mock_verify_oauth2_token.side_effect = ValueError("Invalid token")
    with pytest.raises(HTTPException, match="Unauthorized: Invalid token"):
        verify_iap_jwt("invalid-token", "test-audience")

