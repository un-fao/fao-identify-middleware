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
Flask Identity Middleware

This module provides a Flask-compatible identity middleware that integrates
with the IdentityValidator classes.
It allows Flask applications to use the same authentication mechanisms
as FastAPI applications, ensuring consistent user identity management.
"""

import logging
import asyncio
from models.identity import UserIdentity
from functools import wraps
from typing import Optional, List

try:
    from flask import Flask, request, g, session, abort
    from werkzeug.local import LocalProxy

    def get_current_user() -> Optional[UserIdentity]:
        """Helper function to get the current user identity from Flask's global context."""
        return g.get("user")

    # Create a proxy for the current user, similar to Flask-Login's current_user
    # The type hint helps IDEs, but the proxy itself is not a UserIdentity instance.
    current_user: "UserIdentity" = LocalProxy(get_current_user) # type: ignore

    def require_auth(func):
        """Decorator to protect a Flask route, requiring an authenticated user."""
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if not g.get("user"):
                abort(401, description="Authentication required")
            return func(*args, **kwargs)
        return decorated_function

    __all__ = ["FlaskIdentifyMiddleware", "require_auth", "current_user"]

except ImportError:
    # If flask is not installed, set all to None to avoid runtime errors
    Flask, request, g, session, abort, LocalProxy = (None,) * 6
    get_current_user, current_user = None, None
    __all__ = []

# Assuming the validators are in the parent directory's middleware module
from .validators import IdentityValidator
from utils.jwt_utils import IdentityException

log = logging.getLogger(__name__)

class FlaskIdentifyMiddleware:
    """
    Flask-compatible middleware to validate user identity.

    This class registers a `before_request` handler with the Flask application
    to process incoming requests using a list of `IdentityValidator` instances.
    """

    def __init__(self, app: Flask = None, validators: List[IdentityValidator] = None):
        self.validators = validators if validators is not None else []
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """
        Initializes the Flask application with the identity middleware.

        Args:
            app (Flask): The Flask application instance.
        """
        if not Flask:
            raise ImportError(
                "The 'flask' library is required to use FlaskIdentifyMiddleware. "
                "Please install it with `pip install identify-middleware[flask]`."
            )
        
        # Ensure Flask has a session interface configured
        if not hasattr(app, 'session_interface') or app.session_interface is None:
            log.error("Flask app does not have a session_interface configured. "
                        "FlaskIdentifyMiddleware requires a session manager. "
                        "Ensure app.secret_key is set (for default cookie sessions) "
                        "or Flask-Session is configured.")
            raise RuntimeError("FlaskIdentifyMiddleware requires a session interface to be configured.")

        app.before_request(self._before_request_handler)


    def _before_request_handler(self):
        """
        Handler executed before each request to validate user identity.
        """
        # Run the async validation logic in a sync context
        asyncio.run(self._validate_request())

    async def _validate_request(self):
        # Flask's request object has .headers, .cookies, and session attributes
        # that are compatible with what the validators expect.
        for validator in self.validators:
            validator_name = validator.__class__.__name__
            log.debug(f"Attempting Flask validation with {validator_name}.")
            try:
                # Flask supports async before_request handlers
                user_identity = await validator.validate(request)
                if user_identity:
                    log.info(f"Flask validation succeeded with {validator_name} for {user_identity.email}.")
                    g.user = user_identity # Store in Flask's global context
                    session["user"] = user_identity.model_dump() # Store Pydantic model as dict in session
                    return # Validation successful, proceed with request
                log.debug(f"Flask validation failed for {validator_name}.")
            except IdentityException as e:
                log.warning(f"IdentityException from {validator_name}: {e.detail}")
                session.pop("user", None) # Clear potentially bad session
                abort(e.status_code, description=e.detail)
            except Exception as e:
                log.error(f"Error during Flask validation with {validator_name}: {e}", exc_info=True)
                session.pop("user", None) # Clear session on unexpected error
                abort(500, description="Internal server error during authentication.")
        
        log.info("Unauthenticated Flask request. Treating as public access.")
        g.user = None
        session.pop("user", None) # Clear session user if no validator succeeds