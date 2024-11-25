import secrets
import time

import pytest
from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.testclient import TestClient

from middleware.identify import (
    IdentifyMiddleware,
    APIKeyValidator,
    SessionIdentityValidator,
    SessionCookieValidator,
)

# Mock utility functions
def mock_verify_iap_jwt(apikey, audience):
    if apikey == "valid-api-key" and audience == "/projects/123/apps/test-app":
        return {"exp": time.time() + 3600}
    raise HTTPException(status_code=401, detail="Invalid API key or audience")


@pytest.fixture
def app_with_middleware():
    app = FastAPI()

    # Add SessionMiddleware for session handling
    app.add_middleware(SessionMiddleware, secret_key="test-secret")

    validators = [
        SessionIdentityValidator(expiration_threshold=300),
        SessionCookieValidator(gcp_iap_url="https://mock-gcp-iap-url.com"),
        APIKeyValidator(
            audience="/projects/123/apps/test-app",
            authorization_header_key="X-Goog-Iap-Jwt-Assertion",
        ),
    ]

    app.add_middleware(IdentifyMiddleware, validators=validators)

    @app.get("/secure-endpoint")
    async def secure_endpoint(request: Request):
        user = request.session.get("user", {})
        return {"message": "Access granted", "user": user}

    SECRET_KEY = secrets.token_urlsafe(32)
    app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

    return app

def test_middleware_success_flow(app_with_middleware):
    """
    Test the middleware flow with a valid API key.
    """
    client = TestClient(app_with_middleware)
    response = client.get(
        "/secure-endpoint", headers={"X-Goog-Iap-Jwt-Assertion": "valid-api-key"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Access granted"


def test_middleware_invalid_key_flow(app_with_middleware):
    """
    Test the middleware flow with an invalid API key.
    """
    client = TestClient(app_with_middleware)
    response = client.get(
        "/secure-endpoint", headers={"X-Goog-Iap-Jwt-Assertion": "invalid-api-key"}
    )
    assert response.status_code == 200
    assert response.json()["user"] == {}
