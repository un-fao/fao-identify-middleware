"""
Identify Middleware for FAO FastAPI Applications.

This module provides the `IdentifyMiddleware` class to manage user authentication in a FastAPI app.
It supports multiple validation methods, including API key validation, session-based validation, 
and cookie-based session validation. The module ensures extensibility using a base `IdentityValidator`.

Dependencies:
    - `verify_iap_jwt`: Utility in `utils.jwt_utils` to decode and validate IAP JWT tokens.
    - `check_token_expiration`: Utility in `utils.jwt_utils` to verify token expiration timestamps.
    - `requests`: Library used for HTTP calls to external identity services.

Constants:
    - `KEY_AUTHORIZATION_HEADER`: Default header key to locate the API key.
    - `GCP_IAP_URL`: URL for GCP IAP identity verification.

Usage:
    Add `IdentifyMiddleware` to a FastAPI app with the desired validators. Each validator implements
    a specific authentication method and is applied sequentially during request handling.

Example:
    from fastapi import FastAPI
    from your_project.middleware.identify import (
        IdentifyMiddleware,
        APIKeyValidator,
        SessionIdentityValidator,
        SessionCookieValidator,
    )

    GCP_IAP_URL = "https://data.dev.fao.org/private"

    validators = [
        SessionIdentityValidator(expiration_threshold=300),  # Check session identity
        SessionCookieValidator(gcp_iap_url=GCP_IAP_URL),     # Validate cookies
        APIKeyValidator(audience=f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}"),  # Validate API keys
    ]

    app = FastAPI()

    app.add_middleware(IdentifyMiddleware, validators=validators)
"""

import logging
from abc import ABC, abstractmethod
import httpx
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from utils.jwt_utils import check_token_expiration, verify_iap_jwt

# Configure logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)


class IdentityValidator(ABC):
    """
    Abstract base class for identity validators.

    All validators must implement the `validate` method to check if the request satisfies
    authentication requirements.
    """

    @abstractmethod
    async def validate(self, request: Request) -> bool:
        """
        Validate the request for user authentication.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if validation succeeds, False otherwise.
        """
        pass


class SessionIdentityValidator(IdentityValidator):
    """
    Validator for checking in-memory session identity.

    Validates if a session identity exists and is valid by checking its expiration timestamp.
    """

    def __init__(self, expiration_threshold: int = 300):
        """
        Initialize the SessionIdentityValidator.

        Args:
            expiration_threshold (int): Time in seconds before expiration to consider invalid.
        """
        self.expiration_threshold = expiration_threshold

    async def validate(self, request: Request) -> bool:
        """
        Validate session identity stored in the user's session.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if the session identity is valid, False otherwise.
        """
        session_identity = request.session.get("user")
        if session_identity:
            try:
                check_token_expiration(session_identity, self.expiration_threshold)
                log.info("Session identity is valid.")
                return True
            except HTTPException:
                log.info("Session token expired; revalidation needed.")
        return False


class APIKeyValidator(IdentityValidator):
    """
    Validator for API key-based authentication.

    Validates the API key by verifying and decoding it using the `verify_iap_jwt` utility and ensures
    its validity through token expiration.
    """

    def __init__(
        self,
        audience: str,
        authorization_header_key: str = "X-Goog-Iap-Jwt-Assertion",
    ):
        """
        Initialize the APIKeyValidator.

        Args:
            audience (str): The expected audience for the JWT token.
            authorization_header_key (str, optional): The header key used to retrieve the API key from
                the request. Defaults to "X-Goog-Iap-Jwt-Assertion".
        """
        self.audience = audience
        self.authorization_header_key = authorization_header_key

    async def validate(self, request: Request) -> bool:
        """
        Validate the API key in the request headers.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if the API key is valid, False otherwise.
        """
        apikey = request.headers.get(self.authorization_header_key)
        if apikey:
            log.info("API key detected in request headers.")
            try:
                decoded_jwt = verify_iap_jwt(apikey, self.audience)
                check_token_expiration(decoded_jwt)
                request.session["user"] = decoded_jwt
                return True
            except Exception as e:
                log.error(f"API key validation failed: {e}")
        return False


class SessionCookieValidator(IdentityValidator):
    """
    Validator for session-based authentication using GCP IAP.

    Makes HTTP requests to the GCP IAP identity service to validate session cookies.
    """

    def __init__(self, gcp_iap_url: str):
        """
        Initialize the SessionCookieValidator.

        Args:
            gcp_iap_url (str): URL for the GCP IAP identity verification endpoint.
        """
        self.gcp_iap_url = gcp_iap_url

    async def validate(self, request: Request) -> bool:
        """
        Validate session cookies via GCP IAP identity service.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if session validation succeeds, False otherwise.
        """
        headers = {"X-Requested-With": "XMLHttpRequest", **request.headers}
        headers = {"authorization": headers.get("authorization"), "X-Requested-With": "XMLHttpRequest"}
        # log.info(f"HEADERS: {headers}")
        # headers = {key: value for key, value in request.headers.items()}
        # headers["X-Requested-With"] = "XMLHttpRequest"
        log.info(f"HEADERS: {headers}")
        if await self._attempt_session_validation(request, headers):
            return True

        refresh=True
        log.info(f"Retrying session validation with DO_SESSION_REFRESH={refresh}")
        return await self._attempt_session_validation(request, headers, refresh)

    async def _attempt_session_validation(
        self, request: Request, headers: dict, refresh: bool = False
    ) -> bool:
        """
        Attempt to validate the session via GCP IAP.

        Args:
            request (Request): The incoming FastAPI request object.
            headers (dict): HTTP headers for the request.
            refresh (bool): Whether to enable session refresh mode.

        Returns:
            bool: True if validation succeeds, False otherwise.
        """
        url = f"{self.gcp_iap_url}?gcp-iap-mode=IDENTITY"
        if refresh:
            url += "&DO_SESSION_REFRESH=true"

        cookies = httpx.Cookies()
        for key, value in request.cookies.items():
            cookies.set(key, value)

        async with httpx.AsyncClient(cookies=cookies, timeout=5) as client:
                try:
                    response = await client.get(url, headers=headers)
                    log.info(f"Response status: {response.status_code}")
                    log.info(f"Response body: {response.text}")
                    response.raise_for_status()
                    identity = response.json()
                    log.info(f"Identity: {identity}")
                    if "email" in identity:
                        request.session["user"] = identity
                        return True
                except httpx.RequestError as e:
                    log.error(f"Request error during validation: {e}")
                except httpx.HTTPStatusError as e:
                    log.error(f"HTTP status error: {e.response.status_code} - {e.response.text}")
                except ValueError as e:
                    log.error(f"JSON decoding error: {e}")
                except Exception as e:
                    log.error(f"Unexpected error: {e}")
        return False


class IdentifyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate user identity in a FastAPI application.

    Supports multiple validation methods and applies them sequentially to authenticate users.
    """

    def __init__(self, app, validators: list[IdentityValidator]):
        """
        Initialize the IdentifyMiddleware.

        Args:
            app (ASGIApp): The ASGI app instance.
            validators (List[IdentityValidator]): List of validators to use for authentication.
        """
        super().__init__(app)
        self.validators = validators

    async def dispatch(self, request: Request, call_next):
        """
        Process incoming requests and validate user identity.

        Args:
            request (Request): The incoming FastAPI request object.
            call_next (callable): The next request handler in the middleware chain.

        Returns:
            Response: The HTTP response.
        """
        for validator in self.validators:
            validator_name = validator.__class__.__name__
            try:
                result = await validator.validate(request)
                if result:
                    log.info(f"Validation succeeded with {validator_name}.")
                    break  # Exit loop on first success
                log.info(f"Validation failed for {validator_name}.")
            except Exception as e:
                log.error(f"Error during validation with {validator_name}: {e}")
        else:
            log.info("Unauthenticated request. Treating as public access.")
            request.session.pop("user", None)
            return await call_next(request)

