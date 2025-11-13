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
import logging
import time
from abc import ABC, abstractmethod
from typing import Optional, Callable, Awaitable, Union, Mapping, Any

from models.identity import UserIdentity
from utils.jwt_utils import (
    get_iap_public_keys,
    verify_iap_cookie_jwt,
    check_token_expiration,
    verify_iap_jwt,
    receive_authorized_get_request,
    IdentityException,
)

log = logging.getLogger(__name__)


# Type hint for the custom auth callable
# It takes a token string and returns a UserIdentity or None
AuthCallable = Callable[[str], Awaitable[Optional[UserIdentity]]]


class IdentityValidator(ABC):
    """
    Abstract base class for identity validators.
    All validators must implement the `validate` method.
    """

    @abstractmethod
    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        """
        Validate the request for user authentication.
        Args:
            request: The incoming web framework request object (FastAPI or Flask).
        Returns:
            Optional[UserIdentity]: The UserIdentity object if validation succeeds, None otherwise.
        """
        pass


class SessionPersistenceValidator(IdentityValidator):
    """
    Validator for checking in-memory session identity.
    This should be the *first* validator in the list for performance.
    It relies on an upstream session middleware (e.g., StarletteSessionMiddleware
    or Flask-Session) to populate `request.session`.
    """

    def __init__(self, expiration_threshold: int = 300):
        self.expiration_threshold = expiration_threshold

    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        user_identity_data = request.session.get("user")
        if user_identity_data and isinstance(user_identity_data, dict):
            try:
                user_identity = UserIdentity(**user_identity_data)
                check_token_expiration(
                    user_identity.model_dump(), self.expiration_threshold
                )
                log.info(
                    f"Session persistence validation succeeded for: {user_identity.email}"
                )
                return user_identity
            except IdentityException:
                log.info("Session token expired; revalidation needed.")
                request.session.pop("user", None)  # Clear expired session
            except Exception as e:
                log.warning(f"Could not parse UserIdentity from session: {e}")
                request.session.pop("user", None) # Clear malformed data
        return None


class Oauth2Validator(IdentityValidator):
    """
    Validator for Google OAuth2 / OIDC Bearer tokens.
    It validates a Google-issued ID token sent in the `Authorization` header.
    """

    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        try:
            # receive_authorized_get_request handles Google ID token verification
            claims = receive_authorized_get_request(request)
            if claims and "email" in claims and "exp" in claims:
                auth_header = request.headers.get("Authorization")
                token = (
                    auth_header.split(" ", 1)[1]
                    if auth_header and " " in auth_header
                    else None
                )
                user_identity = UserIdentity(
                    id=claims.get("sub", claims["email"]),
                    email=claims["email"],
                    exp=claims["exp"],
                    provider="oauth2-google",
                    claims=claims,
                    token=token,
                )
                log.info(
                    f"OAuth2 token validation succeeded for email: {user_identity.email}"
                )
                return user_identity
            # No claims found is not an error, just not validated
            log.debug("OAuth2 token validation: No valid Bearer token found.")
        except Exception as e:
            # IdentityException will be caught by middleware, other exceptions logged
            if not isinstance(e, IdentityException):
                log.error(f"OAuth2 token validation failed: {e}")
            else:
                log.info(f"OAuth2 token validation failed: {e.detail}")
        return None


class StaticAPIKeyValidator(IdentityValidator):
    """
    Validator for a simple, static API key.
    Supports a single key or a dictionary mapping multiple keys to user info.
    """

    def __init__(
        self,
        # Can be a single key (str), or a dict mapping keys to user emails
        key_or_map: Union[str, Mapping[str, str]],
        # Ignored if key_or_map is a dict; used as email if key_or_map is a str
        user_email: str = "service-account@example.com",
        header_key: str = "X-API-Key",
    ):
        if not key_or_map:
            raise ValueError("key_or_map cannot be empty.")

        self.key_map = {}
        if isinstance(key_or_map, str):
            self.key_map = {key_or_map: user_email}
        else:
            self.key_map = key_or_map

        self.header_key = header_key
        log.info(f"StaticAPIKeyValidator initialized for header '{header_key}'.")

    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        key_from_header = request.headers.get(self.header_key)
        
        if not key_from_header:
            return None

        # Check if the provided key is in our map
        user_email = self.key_map.get(key_from_header)

        if user_email:
            log.info(f"Static API Key validation succeeded for user: {user_email}")
            # Create a token with a very long expiration (e.g., 10 years)
            far_future_exp = int(time.time() + 315360000)
            user_identity = UserIdentity(
                id=user_email,
                email=user_email,
                exp=far_future_exp,
                provider="static-api-key",
                claims={
                    "sub": user_email,
                    "email": user_email,
                    "exp": far_future_exp,
                    "iat": int(time.time()),
                },
                token=key_from_header,
            )
            return user_identity
        
        log.debug("Static API Key validation failed: Key not found.")
        return None


class CustomTokenValidator(IdentityValidator):
    """
    Validator that uses a custom async callable to validate a token.
    This allows plugging in any auth system (e.g., DB lookup, external API).
    The callable must take a string token and return an Awaitable[Optional[UserIdentity]].
    """

    def __init__(
        self,
        auth_callable: AuthCallable,
        header_key: str = "X-API-Key",
        scheme: Optional[str] = None,  # e.g., "Bearer"
    ):
        self.auth_callable = auth_callable
        self.header_key = header_key
        # Normalize scheme to "bearer " (lowercase, with space) or None
        self.scheme = scheme.lower().strip() + " " if scheme else None
        self.scheme_len = len(self.scheme) if self.scheme else 0
        log.info(f"CustomTokenValidator initialized for header '{header_key}'.")


    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        token_from_header = request.headers.get(self.header_key)

        if not token_from_header:
            return None

        # Handle schemes like "Bearer <token>"
        token: str
        if self.scheme:
            if not token_from_header.lower().startswith(self.scheme):
                log.debug(f"Custom token validation failed: Invalid scheme.")
                return None
            token = token_from_header[self.scheme_len :]
        else:
            token = token_from_header

        if not token:
            log.debug("Custom token validation failed: No token provided after scheme processing.")
            return None

        try:
            user_identity = await self.auth_callable(token)
            if user_identity:
                log.info(
                    f"CustomTokenValidator succeeded for user: {user_identity.email}"
                )
                # Ensure the token is stored in the identity if not already
                if not user_identity.token:
                    user_identity.token = token
                return user_identity
        except Exception as e:
            log.error(f"Error in CustomTokenValidator auth_callable: {e}")
            # Depending on policy, you might want to re-raise as IdentityException
            # raise IdentityException(status_code=500, detail="Auth service error")

        log.debug("Custom token validation failed: Callable returned None.")
        return None


class IAPTokenValidator(IdentityValidator):
    """
    Validates the 'X-Goog-Iap-Jwt-Assertion' header.

    **Note:** This validator uses the 'google-auth' library's
    'verify_oauth2_token' function. This function *may* perform network calls
    to fetch public keys or validate the token with Google's servers, though
    it also employs caching.

    Validator for GCP IAP's `X-Goog-Iap-Jwt-Assertion` header.
    """

    def __init__(
        self,
        audience: str,
        authorization_header_key: str = "X-Goog-Iap-Jwt-Assertion",
    ):
        self.audience = audience
        self.authorization_header_key = authorization_header_key
        get_iap_public_keys()  # Cache keys on startup
        log.info(f"IAPTokenValidator initialized for header '{authorization_header_key}'.")


    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        apikey = request.headers.get(self.authorization_header_key)
        if apikey:
            log.debug("IAP token (X-Goog-Iap-Jwt-Assertion) detected in request headers.")
            try:
                decoded_jwt = verify_iap_jwt(apikey, self.audience)
                user_identity = UserIdentity(
                    id=decoded_jwt.get("sub", "unknown"),
                    email=decoded_jwt.get("email", decoded_jwt.get("sub", "unknown")),
                    exp=decoded_jwt["exp"],
                    claims=decoded_jwt,
                    provider="google-iap-token",
                    token=apikey,
                )
                log.info(
                    f"IAP token validation succeeded for: {user_identity.email}"
                )
                return user_identity
            except IdentityException as e:
                log.info(f"IAP token validation failed: {e.detail}")
            except Exception as e:
                log.error(f"IAP token validation failed with unexpected error: {e}")
        return None


class IAPCookieValidator(IdentityValidator):
    """
    Validates the 'GCP_IAP_UID' cookie.

    **Note:** This validator performs *local* cryptographic validation.
    It uses Google's public keys (cached at startup) to verify the JWT's
    signature and claims (exp, aud) locally. It does **not** make a network
    call to Google for every request.

    Validator for GCP IAP's `GCP_IAP_UID` cookie.
    """

    def __init__(self, audience: str):
        self.audience = audience
        get_iap_public_keys()  # Cache keys on startup
        log.info("IAPCookieValidator initialized.")

    async def validate(self, request: "Request") -> Optional[UserIdentity]:
        iap_cookie = request.cookies.get("GCP_IAP_UID")
        if iap_cookie:
            log.debug("GCP_IAP_UID cookie detected in request.")
            try:
                decoded_jwt = verify_iap_cookie_jwt(iap_cookie, self.audience)
                user_identity = UserIdentity(
                    id=decoded_jwt.get("sub", "unknown"),
                    email=decoded_jwt.get("email", decoded_jwt.get("sub", "unknown")),
                    exp=decoded_jwt["exp"],
                    claims=decoded_jwt,
                    provider="google-iap-cookie",
                    token=iap_cookie,
                )
                log.info(
                    f"IAP cookie validation succeeded for: {user_identity.email}"
                )
                return user_identity
            except IdentityException as e:
                log.info(f"IAP cookie validation failed: {e.detail}")
            except Exception as e:
                log.error(f"IAP cookie validation failed with unexpected error: {e}")
        return None