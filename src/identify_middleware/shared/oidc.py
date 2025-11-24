import logging
import time
from typing import Optional, Any, Dict, List
import httpx
from jose import jwt, jwk
from jose.utils import base64url_decode

from identify_middleware.shared.models import UserIdentity
from identify_middleware.shared.validators import IdentityValidator
from identify_middleware.shared.jwt_utils import IdentityException

logger = logging.getLogger(__name__)

class OIDCTokenValidator(IdentityValidator):
    """
    Validates OIDC JWTs (Bearer tokens) from an Identity Provider (Keycloak, Auth0, etc.).
    It dynamically fetches the JWKS (JSON Web Key Set) from the provider to verify signatures.
    """

    def __init__(
        self,
        discovery_url: str,
        audience: str,
        algorithms: List[str] = ["RS256"],
        header_key: str = "Authorization",
        scheme: str = "Bearer"
    ):
        """
        Args:
            discovery_url: The OIDC discovery URL (e.g., 'https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration')
            audience: The expected 'aud' claim (usually your Client ID).
            algorithms: List of allowed algorithms (default: RS256).
        """
        self.discovery_url = discovery_url
        self.audience = audience
        self.algorithms = algorithms
        self.header_key = header_key
        self.scheme = scheme.lower().strip()
        self.scheme_len = len(self.scheme) + 1 if self.scheme else 0
        
        # Caching
        self._jwks_uri: Optional[str] = None
        self._jwks_cache: Dict[str, Any] = {}
        self._jwks_timestamp: float = 0
        self._cache_ttl = 3600  # Cache keys for 1 hour

    async def _get_jwks(self) -> Dict[str, Any]:
        """Fetches and caches the JWKS keys."""
        # Refresh cache if expired
        if self._jwks_cache and time.time() < self._jwks_timestamp + self._cache_ttl:
            return self._jwks_cache

        async with httpx.AsyncClient() as client:
            # 1. Discover JWKS URI if not known
            if not self._jwks_uri:
                logger.info(f"Fetching OIDC configuration from {self.discovery_url}")
                resp = await client.get(self.discovery_url)
                resp.raise_for_status()
                config = resp.json()
                self._jwks_uri = config.get("jwks_uri")
                if not self._jwks_uri:
                    raise IdentityException(500, "No jwks_uri found in OIDC discovery")

            # 2. Fetch Keys
            logger.info(f"Fetching JWKS from {self._jwks_uri}")
            resp = await client.get(self._jwks_uri)
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._jwks_timestamp = time.time()
            return self._jwks_cache

    async def validate(self, request: Any) -> Optional[UserIdentity]:
        # 1. Extract Token
        auth_header = request.headers.get(self.header_key)
        if not auth_header:
            return None
            
        if self.scheme:
            if not auth_header.lower().startswith(self.scheme + " "):
                return None
            token = auth_header[self.scheme_len:]
        else:
            token = auth_header

        try:
            # 2. Get Key ID (kid) from token header without verification first
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            if not kid:
                 raise IdentityException(401, "Token header missing 'kid'")

            # 3. Get Public Keys
            jwks = await self._get_jwks()
            
            # 4. Verify Signature & Claims
            # python-jose handles searching the JWKS for the matching 'kid'
            payload = jwt.decode(
                token,
                jwks,
                algorithms=self.algorithms,
                audience=self.audience,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_exp": True
                }
            )
            
            # 5. Construct Identity
            user_identity = UserIdentity(
                id=payload.get("sub"),
                email=payload.get("email", payload.get("sub")), # Fallback to sub if email missing
                exp=payload.get("exp"),
                provider="oidc-jwt",
                claims=payload,
                token=token
            )
            logger.info(f"OIDC Token validated for {user_identity.email}")
            return user_identity

        except jwt.ExpiredSignatureError:
            logger.info("OIDC Token expired")
            raise IdentityException(401, "Token expired")
        except jwt.JWTClaimsError as e:
            logger.warning(f"OIDC Token claims invalid: {e}")
            raise IdentityException(403, f"Invalid claims: {str(e)}")
        except jwt.JWTError as e:
            logger.warning(f"OIDC Token signature invalid: {e}")
            raise IdentityException(401, "Invalid token signature")
        except Exception as e:
            logger.error(f"OIDC Validation error: {e}")
            return None