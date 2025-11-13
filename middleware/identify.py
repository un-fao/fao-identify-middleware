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

import logging
from typing import List, Optional

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from .validators import IdentityValidator
from utils.jwt_utils import IdentityException
from models import UserIdentity

log = logging.getLogger(__name__)


class IdentifyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate user identity in a FastAPI application.
    Supports multiple validation methods and applies them sequentially.
    """

    def __init__(self, app, validators: List[IdentityValidator]):
        super().__init__(app)
        self.validators = validators

    async def dispatch(self, request: Request, call_next):
        if not Request or not BaseHTTPMiddleware:
            raise ImportError(
                "The 'fastapi' library is required to use IdentifyMiddleware. "
                "Please install it with `pip install identify-middleware[fastapi]`."
            )
        
        # Ensure session middleware is running
        if "session" not in request.scope:
            log.error("SessionMiddleware not detected. IdentifyMiddleware requires an upstream session middleware.")
            raise RuntimeError("IdentifyMiddleware requires SessionMiddleware to be installed.")

        for validator in self.validators:
            validator_name = validator.__class__.__name__
            log.debug(f"Attempting validation with {validator_name}.")
            try:
                user_identity: Optional[UserIdentity] = await validator.validate(request)
                if user_identity:
                    log.info(f"Validation succeeded with {validator_name} for {user_identity.email}.")
                    request.state.user = user_identity # Store in request.state for current request
                    request.session["user"] = user_identity.model_dump() # Store Pydantic model as dict in session
                    return await call_next(request)
                log.debug(f"Validation failed for {validator_name}.")
            except IdentityException as e:
                log.warning(f"IdentityException from {validator_name}: {e.detail}")
                # Clear potentially bad session data if validation fails
                request.session.pop("user", None)
                raise HTTPException(status_code=e.status_code, detail=e.detail) from e
            except Exception as e:
                log.error(f"Error during validation with {validator_name}: {e}", exc_info=True)
                # Clear session on unexpected error
                request.session.pop("user", None)
                raise HTTPException(status_code=500, detail="Internal server error during authentication.") from e
        
        log.info("Unauthenticated request. Treating as public access.")
        # Ensure user is cleared from state and session if all validators fail
        request.state.user = None
        request.session.pop("user", None)
        return await call_next(request)