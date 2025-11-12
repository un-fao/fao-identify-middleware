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
"""
Identify Middleware for FAO FastAPI Applications

This module provides the `IdentifyMiddleware` class, which is used to manage user 
authentication in a FastAPI application. It supports a range of validation methods, 
including API key validation, OAuth2 Bearer token validation, session-based validation, 
and session cookie-based validation. This ensures flexibility in handling different 
authentication mechanisms. The module is designed to be extensible using a base 
`IdentityValidator` class, which enables the seamless addition of custom validators.

Dependencies:
    - `verify_iap_jwt`: A utility in `utils.jwt_utils` for decoding and validating IAP JWT tokens.
    - `check_token_expiration`: A utility in `utils.jwt_utils` for verifying token expiration timestamps.
    - `receive_authorized_get_request`: A utility in `utils.jwt_utils` for decoding OAuth2 Bearer tokens.
    - `httpx`: A library used for HTTP calls to external identity services.

Constants:
    - `KEY_AUTHORIZATION_HEADER`: Defines the default header key for locating the API key.
    - `GCP_IAP_URL`: Specifies the URL for GCP IAP identity verification services.

Features:
    - **Extensibility**: Custom validators can be implemented by extending the `IdentityValidator` class.
    - **Composability**: Multiple validators can be composed and applied sequentially.
    - **Flexibility**: Supports multiple authentication mechanisms, such as API keys, session cookies,
      and OAuth2 tokens.
    - **Logging**: Provides detailed logs for validation success, failure, and errors.

Usage:
    Add `IdentifyMiddleware` to a FastAPI application along with the desired validators.
    Each validator applies a specific authentication mechanism and processes incoming
    requests sequentially. Once a validator succeeds, no further validation is performed.

Example:
    from fastapi import FastAPI
    from your_project.middleware.identify import (
        IdentifyMiddleware,
        IAPSessionValidator,
        Oauth2Validator,
        SessionIdentityValidator,
    )

    GCP_IAP_URL = "https://data.dev.fao.org/private"

    validators = [
        Oauth2Validator(),                                   # Validate OAuth2 Bearer tokens
        IAPSessionValidator(                                 # Validate API keys and session cookies
            audience=f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}",
            gcp_iap_url=GCP_IAP_URL
        ),
        SessionIdentityValidator(expiration_threshold=300),  # Validate in-memory session identity
    ]

    app = FastAPI()

    app.add_middleware(IdentifyMiddleware, validators=validators)
"""


import logging
from abc import ABC, abstractmethod
import httpx
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


from utils.jwt_utils import (
    check_token_expiration,
    verify_iap_jwt,
    receive_authorized_get_request
)

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


class Oauth2Validator(IdentityValidator):
    """
    Validator for OAuth2 Bearer token-based authentication.

    Validates the Bearer token in the `Authorization` header and extracts the user's email from it.
    """

    async def validate(self, request: Request) -> bool:
        """
        Validate the OAuth2 Bearer token in the request.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if the Bearer token is valid and the email is retrieved, False otherwise.
        """
        try:
            sub = receive_authorized_get_request(request)
            if sub:
                request.session["user"] = {"email": sub}
                log.info(f"OAuth2 token validation succeeded for OAuth 2 Client ID: {sub}")
                return True
            log.info("OAuth2 token validation failed: No email retrieved.")
        except Exception as e:
            log.error(f"OAuth2 token validation failed: {e}")
        return False


class IAPSessionValidator(IdentityValidator):
    """
    Validator for API key-based authentication and session-based authentication using GCP IAP.

    Combines:
    - Session cookie validation by making HTTP requests to the GCP IAP identity service.
    - API key validation by verifying and decoding it using the `verify_iap_jwt` utility.
    """

    def __init__(
        self,
        audience: str,
        gcp_iap_url: str,
        authorization_header_key: str = "X-Goog-Iap-Jwt-Assertion",
    ):
        """
        Initialize the IAPSessionValidator.

        Args:
            audience (str): The expected audience for the JWT token.
            gcp_iap_url (str): URL for the GCP IAP identity verification endpoint.
            authorization_header_key (str, optional): The header key used to retrieve the API key from
                the request. Defaults to "X-Goog-Iap-Jwt-Assertion".
        """
        self.audience = audience
        self.gcp_iap_url = gcp_iap_url
        self.authorization_header_key = authorization_header_key

    async def validate(self, request: Request) -> bool:
        """
        Validate the request for both API key-based and session-based authentication.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if any validation succeeds, False otherwise.
        """
        if await self._validate_iap_session_cookies(request):
            return True

        if await self._validate_iap_api_key(request):
            return True

        return False

    async def _validate_iap_api_key(self, request: Request) -> bool:
        """
        Validate the API key in the request headers.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if the API key is valid, False otherwise.
        """
        apikey = request.headers.get(self.authorization_header_key)
        if apikey:
            log.info("IAP API key detected in request headers.")
            try:
                decoded_jwt = verify_iap_jwt(apikey, self.audience)
                check_token_expiration(decoded_jwt)
                request.session["user"] = decoded_jwt
                log.info("IAP API key validation succeeded.")
                return True
            except Exception as e:
                log.error(f"IAP API key validation failed: {e}")
        return False

    async def _validate_iap_session_cookies(self, request: Request) -> bool:
        """
        Validate session cookies via GCP IAP identity service.

        Args:
            request (Request): The incoming FastAPI request object.

        Returns:
            bool: True if session validation succeeds, False otherwise.
        """
        # Build headers explicitly from request headers and override the "X-Requested-With" header.
        headers = dict(request.headers)
        
        # Remove headers that could cause issues with GET request
        headers_to_remove = [
            'content-length',
            'content-type',
            'origin',
            'sec-fetch-mode',
            'sec-fetch-site',
            'sec-fetch-dest'
        ]
        for header in headers_to_remove:
            headers.pop(header, None)
            
        headers["X-Requested-With"] = "XMLHttpRequest"

        log.info(f"IAP Session validation headers: {headers}")

        if await self._attempt_iap_session_validation(request, headers):
            return True

        refresh = True
        log.info(f"Retrying IAP session validation with DO_SESSION_REFRESH={refresh}")
        return await self._attempt_iap_session_validation(request, headers, refresh)

    async def _attempt_iap_session_validation(
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

        # Remove Content-Length header if present to avoid mismatch
        headers.pop('Content-Length', None)
        log.info(f"Request headers - _attempt_iap_session_validation(): {headers}")
        
        async with httpx.AsyncClient(cookies=cookies, timeout=5) as client:
            try:
                # Always use GET for identity validation regardless of original request method
                response = await client.get(url, headers=headers)
                log.info(f"Response status: {response.status_code}")
                log.debug(f"Response headers: {response.headers}")
                log.debug(f"Response body: {response.text}")
                response.raise_for_status()
                identity = response.json()
                log.info(f"Identity: {identity}")
                if "email" in identity:
                    request.session["user"] = identity
                    log.info("IAP Session cookie validation succeeded.")
                    return True
            except httpx.RequestError as e:
                log.error(f"Request error during IAP session validation: {e}")
            except httpx.HTTPStatusError as e:
                log.error(f"HTTP status error: {e.response.status_code} - {e.response.text}")
            except ValueError as e:
                log.error(f"JSON decoding error: {e}")
            except Exception as e:
                log.error(f"Unexpected error during IAP session validation: {e}")
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
                if await validator.validate(request):
                    log.info(f"Validation succeeded with {validator_name}.")
                    return await call_next(request)
                log.debug(f"Validation failed for {validator_name}.")
            except Exception as e:
                log.error(f"Error during validation with {validator_name}: {e}")
        log.info("Unauthenticated request. Treating as public access.")
        request.session.pop("user", None)
        return await call_next(request)
