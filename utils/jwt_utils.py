import time
import logging
from fastapi import HTTPException
from google.oauth2.id_token import verify_oauth2_token
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.auth.transport import requests
from google.oauth2 import id_token

# Configure logging
log = logging.getLogger(__name__)

def check_token_expiration(decoded_jwt: dict, threshold: int = 300):
    """
    Checks if a JWT token is expired or nearing expiration.

    Args:
        decoded_jwt (dict): The decoded JWT containing the `exp` claim.
        threshold (int): Time in seconds before expiration to consider the token invalid.

    Raises:
        HTTPException: If the token is expired or nearing expiration.
    """
    current_time = time.time()
    expire_time = int(decoded_jwt.get("exp", -1))
    if expire_time == -1:
        raise HTTPException(status_code=401, detail="Token does not have an expiration claim")
    if current_time > expire_time - threshold:
        raise HTTPException(
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
        HTTPException: If the token is expired or invalid.
    """
    try:
        # Google's verification requires a special `Request` object for HTTP transport
        google_request = GoogleAuthRequest()

        # Attempt to decode the JWT using the public keys and audience
        decoded_jwt = verify_oauth2_token(
            id_token=iap_jwt, request=google_request, audience=audience
        )
        log.info(f"Decoded token: {decoded_jwt}")

        # Check if the token has expired by comparing the current time to the 'exp' claim
        current_time = time.time()
        expire_time = int(decoded_jwt.get("exp", -1))
        if current_time > expire_time:
            raise HTTPException(status_code=401, detail="Unauthorized: Token has expired")

        return decoded_jwt

    except ValueError as e:
        # Any other issue with the token (e.g., invalid token)
        raise HTTPException(
            status_code=403, detail=f"Unauthorized: Invalid token ({str(e)})"
        ) from e



def receive_authorized_get_request(request):
    """Parse the authorization header and decode the information
    being sent by the Bearer token.

    Args:
        request: Flask request object

    Returns:
        The email from the request's Authorization header.
    """
    auth_header = request.headers.get("Authorization")
    if auth_header:
        # split the auth type and value from the header.
        auth_type, creds = auth_header.split(" ", 1)

        if auth_type.lower() == "bearer":
            claims = id_token.verify_token(creds, requests.Request())
            log.info(f"claims: {claims}")
            return claims['sub']
    return None