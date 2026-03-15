# grxm-iam

`grxm-iam` is a highly modular, zero-trust Identity and Access Management (IAM) service designed to act as a centralized bearer authority for consumer applications. It is built in Go and utilizes MongoDB for data storage.

## Core Features

*   **Zero-Trust Bearer Model:** Consumer applications never store sensitive PII (like passwords or phone numbers). The IAM service authenticates users and issues cryptographically signed JSON Web Tokens (JWTs) containing a unique `user_id`.
*   **Decentralized Token Verification:** Consumer APIs can validate the JWT's authenticity instantly using the IAM service's public RSA key, eliminating the need for constant database queries or network requests to the auth server.
*   **Object-Oriented Auth Methods:** Authentication (login/register) is handled via dynamic "methods" constructed from input fields (e.g., `"email-password"`, `"sms-password"`).
*   **Authority WebSocket API:** A persistent, secure WebSocket connection intended only for trusted backend administrative services to mutate user state (like banning users or managing roles) in real-time.
*   **Secure Token Management:** Tokens are issued as `HttpOnly`, `Secure` cookies with configurable absolute refresh deadlines to mitigate XSS and session hijacking risks.

## Quick Start

### Prerequisites
*   Go 1.25+
*   MongoDB instance

### Building and Running
1.  **Clone and build:**
    ```bash
    go build -o iam .
    ```
2.  **Create Keys Directory:**
    The application automatically generates RSA keys if they don't exist. Ensure the directory defined in your config is present:
    ```bash
    mkdir -p keys
    ```
3.  **Run the service:**
    ```bash
    ./iam
    ```
    *Note: By default, the service looks for `./config.json`. Override this using `IAM_CONFIG_LOCATION=/path/to/config.json ./iam`.*

## Configuration (`config.json`)

The IAM service is entirely driven by a `config.json` file. Here is an example configuration:

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8080
    },
    "database": {
        "uri": "mongodb://localhost:27017",
        "database": "grxm_iam"
    },
    "authority": {
        "password": "change-this-in-production-123",
        "path": "/api/v1/authority"
    },
    "default_role": "user",
    "id": {
        "type": "uid",
        "length": 32,
        "charset": "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    },
    "token": {
        "type": "jwt",
        "bits": 2048,
        "algorithm": "RS256",
        "key_path": "./keys/newest",
        "expiration_hours": 24,
        "refresh_max_hours": 168,
        "cookie_name": "grxm_token"
    },
    "email": {
        "username_min_length": 3,
        "username_max_length": 50,
        "username_charlist": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_",
        "domain_min_length": 4,
        "domain_max_length": 50,
        "domain_charlist": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_",
        "domain_whitelist": [],
        "domain_blacklist": []
    },
    "password": {},
    "sms": {},
    "auth_methods": {
        "email-password": { "verify": true },
        "sms-password": { "verify": true },
        "username-password": {
            "verify": true,
            "verify_sources": ["email", "sms"]
        }
    }
}
```

## API Overview

*   `GET /health`: Operational status and database connectivity check.
*   `POST /api/v1/register`: Create a new user account and receive an `HttpOnly` token cookie.
*   `POST /api/v1/login`: Authenticate an existing user and receive an `HttpOnly` token cookie.
*   `POST /api/v1/refresh-token`: Extend a valid session up to the absolute `refresh_max_hours` deadline.
*   `WS /api/v1/authority`: Secure WebSocket endpoint for administrative commands (ban, unban, role management, public key retrieval).

For comprehensive architectural details and API payloads, see the internal documentation.