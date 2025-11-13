#    Copyright 2025 FAO
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
#    Author: Carlo Cancellieri (ccancellieri@gmail.com)
#    Company: FAO, Viale delle Terme di Caracalla, 00100 Rome, Italy
#    Contact: copyright@fao.org - http://fao.org/contact-us/terms/en/

# utils/jwt_utils.py

import time
import logging
from functools import lru_cache
from typing import Mapping, Any, Optional
import httpx
from jose import jwt, exceptions

try:
    from google.oauth2.id_token import verify_oauth2_token
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google.auth.transport import requests
    from google.oauth2 import id_token
except ImportError:
    verify_oauth2_token = None
    GoogleAuthRequest = None
    id_token = None
    requests = None

logger = logging.getLogger(__name__)

class IdentityException(Exception):
    """Custom exception for identity validation errors, independent of web framework."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"[{status_code}] {detail}")


IAP_PUBLIC_KEYS_URL = "https://www.gstatic.com/iap/verify/public_keys"

def check_token_expiration(decoded_jwt: Mapping[str, Any], threshold: int = 300):
    """
    Checks if a JWT token is expired or nearing expiration.

    Args:
        decoded_jwt (dict): The decoded JWT containing the `exp` claim.
        threshold (int): Time in seconds before expiration to consider the token invalid.

    Raises:
        IdentityException: If the token is expired or nearing expiration.
    """
    current_time = time.time()
    expire_time = int(decoded_jwt.get("exp", -1))
    if expire_time == -1:
        raise IdentityException(status_code=401, detail="Token does not have an expiration claim")
    # Check if the token is already expired or nearing expiration
    if current_time > expire_time - threshold:
        raise IdentityException(
            status_code=401, detail="Token expired or nearing expiration."
        )


def verify_iap_jwt(iap_jwt: str, audience: str) -> dict:
    """
    Verifies the IAP JWT using Google's public keys, checks expiration, and returns the decoded JWT.

    Args:
        iap_jwt (str): The JWT token extracted from headers.
        audience (str): The expected audience string for the JWT token.

    Returns:
        dict: Decoded JWT if valid.

    Raises:
        IdentityException: If the token is expired or invalid.
    """
    if not verify_oauth2_token or not GoogleAuthRequest:
        raise ImportError(
            "The 'google-auth' library is required for IAP JWT validation. "
            "Please install it with `pip install identify-middleware[google]`."
        )
    try:
        # Google's verification requires a special `Request` object for HTTP transport
        google_request = GoogleAuthRequest()

        # Attempt to decode and verify the JWT using the public keys and audience
        decoded_jwt = verify_oauth2_token(
            id_token=iap_jwt, request=google_request, audience=audience
        )
        # logger.debug(f"Decoded IAP token: {decoded_jwt}")

        return decoded_jwt

    except ValueError as e:
        # Any other issue with the token (e.g., invalid token)
        raise IdentityException(
            status_code=403, detail=f"Unauthorized: Invalid IAP token ({str(e)})"
        ) from e
    except Exception as e:
        logger.error(f"Unexpected error during IAP JWT validation: {e}")
        raise IdentityException(status_code=500, detail="An unexpected error occurred during IAP token validation.") from e

@lru_cache(maxsize=1)
def get_iap_public_keys() -> dict:
    """
    Fetches Google's IAP public keys from a well-known URL and caches them.
    This function is designed to be called once at application startup.

    Returns:
        dict: A dictionary containing the public keys.

    Raises:
        IdentityException: If there's an error fetching the keys.
    """
    try:
        logger.info(f"Fetching IAP public keys from {IAP_PUBLIC_KEYS_URL}")
        # Use synchronous httpx.Client for fetching keys, as this function
        # is called at startup.
        with httpx.Client(timeout=10) as client:
            response = client.get(IAP_PUBLIC_KEYS_URL)
            response.raise_for_status()
        keys = response.json()
        logger.info("Successfully fetched IAP public keys.")
        return keys
    except httpx.RequestError as e:
        logger.error(f"Error fetching IAP public keys: {e}")
        raise IdentityException(status_code=500, detail="Could not fetch IAP public keys.") from e
    except Exception as e:
        logger.error(f"Unexpected error fetching IAP public keys: {e}")
        raise IdentityException(status_code=500, detail="An unexpected error occurred while fetching IAP public keys.") from e


def verify_iap_cookie_jwt(iap_jwt_cookie: str, audience: str) -> dict:
    """
    Verifies the IAP JWT from a cookie using Google's public keys.
    This performs local cryptographic validation.

    Args:
        iap_jwt_cookie (str): The JWT token extracted from the GCP_IAP_UID cookie.
        audience (str): The expected audience string for the JWT token.

    Returns:
        dict: Decoded JWT if valid.

    Raises:
        IdentityException: If the token is expired or invalid.
    """
    try:
        public_keys = get_iap_public_keys()
        # IAP JWTs from cookies typically use ES256 algorithm
        decoded_jwt = jwt.decode(
            iap_jwt_cookie,
            public_keys,
            algorithms=["ES256"],
            audience=audience,
            options={"verify_exp": True, "verify_aud": True}
        )
        # logger.debug(f"Decoded IAP cookie token: {decoded_jwt}")
        return decoded_jwt
    except exceptions.JWTError as e:
        logger.warning(f"IAP cookie JWT validation failed: {e}")
        raise IdentityException(status_code=403, detail=f"Unauthorized: Invalid IAP cookie token ({str(e)})") from e
    except Exception as e:
        logger.error(f"Unexpected error during IAP cookie JWT validation: {e}")
        raise IdentityException(status_code=500, detail="An unexpected error occurred during IAP cookie JWT validation.") from e


def receive_authorized_get_request(request: Any) -> Optional[dict]:
    """Parse the authorization header and decode the information
    being sent by the Bearer token (assuming it's a Google ID Token).

    Args:
        request: FastAPI or Flask request object

    Returns:
        dict: Decoded claims from the Bearer token.
    """
    if not id_token or not requests:
        raise ImportError(
            "The 'google-auth' library is required for OAuth2 token validation. "
            "Please install it with `pip install identify-middleware[google]`."
        )
    auth_header = request.headers.get("Authorization")
    if auth_header:
        try:
            # split the auth type and value from the header.
            auth_type, creds = auth_header.split(" ", 1)
        except ValueError:
            logger.debug("Invalid Authorization header format. Expected 'Bearer <token>'.")
            return None # Not a Bearer token, or malformed

        if auth_type.lower() == "bearer":
            try:
                # verify_oauth2_token checks expiration, signature, and issuer
                # for Google-issued ID tokens.
                claims = id_token.verify_oauth2_token(creds, requests.Request())
                # logger.debug(f"Decoded OAuth2 Bearer token claims: {claims}")
                
                if "email" not in claims and "sub" in claims:
                    claims["email"] = claims["sub"] # Use 'sub' as 'email' if 'email' is missing
                
                if "exp" not in claims:
                    # This should be caught by verify_oauth2_token, but as a safeguard:
                    raise IdentityException(status_code=401, detail="Bearer token missing expiration claim.")
                
                return claims
            except ValueError as e:
                # This catches expired tokens, invalid signatures, wrong issuer, etc.
                logger.info(f"OAuth2 Bearer token validation failed: {e}")
                raise IdentityException(status_code=401, detail=f"Invalid Bearer token: {e}") from e
            except Exception as e:
                logger.error(f"Unexpected error during OAuth2 token validation: {e}")
                raise IdentityException(status_code=500, detail="Unexpected error validating Bearer token.") from e

    return None