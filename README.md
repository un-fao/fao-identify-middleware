# Identify Middleware for FAO FastAPI Applications

This repository provides a robust middleware solution for managing user authentication in FastAPI applications. The `IdentifyMiddleware` class allows flexible integration of multiple identity validation methods, ensuring security and extensibility for different use cases.

---

## Features

- **Pluggable Validators:**
  - API key-based authentication.
  - OAuth2 Bearer token validation.
  - Session-based validation with expiration checks.
  - Cookie-based session validation using GCP IAP.
- **Extensibility:** Built using a base `IdentityValidator` class to support custom validators.
- **Utilities:** Includes utilities for JWT token decoding and expiration checks.
- **Logging:** Provides detailed logs for validation success, failure, and errors.

---

## Installation
Clone the repository and install it using pip:
```bash
pip install git+https://bitbucket.org/cioapps/fao-identify-middleware.git
```

## Usage
### Example Integration
Here’s an example of integrating `IdentifyMiddleware` into your FastAPI application:

```python
import secrets
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from middleware.identify import (
    IdentifyMiddleware,
    IAPSessionValidator,
    Oauth2Validator,
    SessionIdentityValidator,
)
from utils.jwt_utils import verify_iap_jwt

# GCP configuration values
PROJECT_NUMBER = "your-project-number"
PROJECT_ID = "your-project-id"
GCP_IAP_URL = "https://example_iap.com/secure"

validators = [
    Oauth2Validator(),  # Validate OAuth2 Bearer tokens
    IAPSessionValidator(  # Validate API keys and session cookies
        audience=f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}",
        gcp_iap_url=GCP_IAP_URL,
    ),
    SessionIdentityValidator(expiration_threshold=300),  # Validate in-memory session identity
]

app = FastAPI()

# Add the middleware
app.add_middleware(IdentifyMiddleware, validators=validators)

@app.get("/secure-endpoint")
async def secure_endpoint():
    return {"message": "Access granted"}

SECRET_KEY = secrets.token_urlsafe(32)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
```

## Validators
### APIKeyValidator
Validates API keys by decoding JWT tokens using the `verify_iap_jwt` utility and checking token expiration.

#### Arguments:
- `audience` (str): The expected audience for the JWT token.
- `authorization_header_key` (str): The header key to retrieve the API key (default: `"X-Goog-Iap-Jwt-Assertion"`).

#### Example:
```python
APIKeyValidator(audience=f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}")
```

### SessionIdentityValidator
Checks if a valid session identity exists and is within the expiration threshold.

#### Arguments:
- `expiration_threshold` (int): Time (in seconds) before expiration to consider invalid.

#### Example:
```python
SessionIdentityValidator(expiration_threshold=300)
```

### SessionCookieValidator
Validates session cookies using the GCP IAP identity service.

#### Arguments:
- `gcp_iap_url` (str): URL for GCP IAP identity verification.

#### Example:
```python
SessionCookieValidator(gcp_iap_url=GCP_IAP_URL)
```

## Utilities
### `verify_iap_jwt`
Decodes and validates IAP JWT tokens using Google’s public keys. It ensures the token has not expired and matches the expected audience.

#### Example:
```python
from utils.jwt_utils import verify_iap_jwt

iap_jwt = "your-jwt-token"
audience = f"/projects/{PROJECT_NUMBER}/apps/{PROJECT_ID}"
decoded_token = verify_iap_jwt(iap_jwt, audience)
```

### `check_token_expiration`
Checks if a decoded JWT token is expired or nearing expiration.

#### Example:
```python
from utils.jwt_utils import check_token_expiration

check_token_expiration(decoded_jwt, threshold=300)
```

## Testing
Run the test suite using `pytest`:
```bash
pytest --asyncio-mode=auto tests/
```

### Writing Tests
Tests for validators and utilities can be found in the `tests` folder. To add new tests, create test cases under `tests/` that validate your custom logic.

#### Example Test for `APIKeyValidator`:
```python
from middleware.identify import APIKeyValidator
from fastapi import HTTPException
import pytest

@pytest.mark.asyncio
async def test_api_key_validator_invalid_key():
    validator = APIKeyValidator(audience="test-audience")
    request = Mock()
    request.headers = {"X-Goog-Iap-Jwt-Assertion": "invalid-api-key"}

    with pytest.raises(HTTPException, match="Unauthorized: Invalid token"):
        await validator.validate(request)
```

## Contributing
Contributions are welcome! Fork the repository, make changes, and submit a pull request.

## License
Copyright 2025 FAO

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Carlo Cancellieri (ccancellieri@gmail.com) and Martial Wafo
Company: FAO, Viale delle Terme di Caracalla, 00100 Rome, Italy
Contact: copyright@fao.org - http://fao.org/contact-us/terms/en/
