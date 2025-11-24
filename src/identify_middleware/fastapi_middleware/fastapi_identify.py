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
from typing import List, Optional

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from identify_middleware.shared.validators import IdentityValidator
from identify_middleware.shared.jwt_utils import IdentityException
from identify_middleware.shared.models import UserIdentity

logger = logging.getLogger(__name__)

class IdentifyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate user identity in a FastAPI application.
    """

    def __init__(self, app, validators: List[IdentityValidator]):
        super().__init__(app)
        self.validators = validators

    async def dispatch(self, request: Request, call_next):
        if "session" not in request.scope:
            logger.error("SessionMiddleware not detected.")
            raise RuntimeError("IdentifyMiddleware requires SessionMiddleware to be installed.")

        for validator in self.validators:
            validator_name = validator.__class__.__name__
            logger.debug(f"Attempting validation with {validator_name}.")
            try:
                user_identity: Optional[UserIdentity] = await validator.validate(request)
                if user_identity:
                    logger.info(f"Validation succeeded with {validator_name} for {user_identity.email}.")
                    request.state.user = user_identity
                    
                    # FIX: Session Size Optimization
                    # Do NOT store full claims or token in session cookie (often >4KB).
                    # Only store reconstruction essentials.
                    session_data = user_identity.model_dump(include={'id', 'email', 'exp', 'provider'})
                    request.session["user"] = session_data
                    
                    return await call_next(request)
                logger.debug(f"Validation failed for {validator_name}.")
            except IdentityException as e:
                logger.warning(f"IdentityException from {validator_name}: {e.detail}")
                request.session.pop("user", None)
                # raise HTTPException is better than returning Response directly in middleware
                # so that ExceptionHandlers can catch it
                # However, BaseHTTPMiddleware expects a Response.
                # We rely on FastAPI's exception handling propagation here.
                raise HTTPException(status_code=e.status_code, detail=e.detail) from e
            except Exception as e:
                logger.error(f"Error during validation with {validator_name}: {e}", exc_info=True)
                request.session.pop("user", None)
                raise HTTPException(status_code=500, detail="Internal server error during authentication.") from e
        
        logger.info("Unauthenticated request. Treating as public access.")
        request.state.user = None
        request.session.pop("user", None)
        return await call_next(request)