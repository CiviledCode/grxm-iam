# grxm-iam: API & Integration Reference

This document serves as the comprehensive technical reference for integrating external applications and administrative backend services with the `grxm-iam` (Identity and Access Management) service. `grxm-iam` is designed as a highly modular, zero-trust authentication bearer service.

---

## 1. Core Architecture & Concepts

### Zero-Trust Bearer Model
Consumer applications (like your API servers or frontends) **must never** store sensitive Personally Identifiable Information (PII) such as passwords, emails, or phone numbers in their own databases.
Instead, when a user successfully authenticates through `grxm-iam`, the service returns a signed JSON Web Token (JWT) containing a unique `user_id`. Your consumer applications should only store this `user_id` as the primary identifier to link resources.

### Decentralized Token Verification
Consumer applications validate the authenticity and integrity of the JWT cryptographically using the IAM service's **public key**. Because the token signature guarantees it was minted by the IAM service, your APIs can instantly verify a user's identity and roles without needing to make network requests or query the central IAM database for every single API call.

#### Recommended Token Refresh Flow (Client-Side Orchestration)
To maintain the performance benefits of zero-trust verification while keeping sessions secure, consumer APIs must handle token expiration locally and rely on the frontend application to orchestrate token refreshes:

1.  **Local Verification:** Your consumer API receives a request with the JWT (typically in a cookie). It uses the IAM public key to verify the signature and checks the `exp` (expiration) claim locally.
2.  **Reject Expired Tokens:** If the token is expired, the consumer API **must instantly reject** the request with a `401 Unauthorized` status code. It should **not** attempt to contact the IAM service.
3.  **Frontend Intercept:** The frontend application (e.g., React, Vue) should globally intercept all `401` responses from your consumer APIs.
4.  **The Refresh Attempt:** Upon receiving a `401`, the frontend automatically makes a background request to the IAM service's `POST /api/v1/refresh-token` endpoint.
    *   **Success:** The IAM service issues a new `HttpOnly` cookie. The frontend should then automatically retry the original API request that failed.
    *   **Failure:** If the refresh fails (e.g., the absolute refresh deadline has passed, or the user was banned), the frontend should save the user's current route/state and redirect them to the login page. After a successful login, it should redirect them back to where they were.

### High-Speed Session Invalidation (Redis Denylist)
While decentralized verification is extremely fast, it creates a window where a banned user's token remains mathematically valid until its `exp` claim passes.
To solve this, `grxm-iam` supports a high-speed Redis Denylist:
1. When an administrator bans a user via the Authority API, the `user_id` is immediately added to the Redis keystore.
2. The TTL (Time-To-Live) of this Redis record is automatically set to match the maximum lifetime of a standard token (e.g., 24 hours).
3. Consumer APIs can query this Redis instance on every request. This is vastly faster than querying MongoDB. If the `user_id` is present in Redis, the API instantly rejects the token, overriding its mathematical validity.
4. Once the token naturally expires, the Redis record is automatically deleted, keeping the memory footprint minimal.

### Object-Oriented Auth Methods
Authentication and registration are handled via dynamic "methods" requested in the JSON payload. Methods are built like blocks (e.g., combining an `EmailField` and `PasswordField` creates the `"email-password"` method).

---

## 2. Configuration

The IAM service is entirely driven by a `config.json` file. 

**Environment Variable Override:**
By default, the service looks for `./config.json` in the current directory. You can specify a different location by setting the `IAM_CONFIG_LOCATION` environment variable (e.g., `IAM_CONFIG_LOCATION=/etc/iam/config.json`).

### `config.json` Structure
This documentation is crucial for orchestration (e.g., creating `docker-compose.yml` files).

```json
{
    "server": {
        "host": "0.0.0.0",          // The interface to bind the HTTP server to. Use "0.0.0.0" for Docker.
        "port": 8080                // The port the API server listens on.
    },
    "database": {
        "uri": "mongodb://localhost:27017", // The MongoDB connection string. In Docker Compose, this would be e.g., "mongodb://mongo:27017"
        "database": "grxm_iam"      // The specific MongoDB database to use.
    },
    "keystore": {
        "host": "localhost",        // The Redis server host. Used for the high-speed token denylist.
        "port": 6379,               // The Redis server port.
        "password": "",             // The Redis server password (if any).
        "db": 0                     // The Redis database index to use.
    },
    "authority": {
        "password": "change-this-in-production-123", // The critical master password required to access the WebSocket API.
        "path": "/api/v1/authority" // The path the WebSocket server is mounted on.
    },
    "default_role": "user",         // The role assigned to newly created users during registration.
    "id": {
        "type": "uid",              // Strategy for ID generation.
        "length": 32,               // Length of the generated User IDs.
        "charset": "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" // Allowed characters in the User ID.
    },
    "token": {
        "type": "jwt",              // Token format (currently JWT).
        "bits": 2048,               // RSA key bit size.
        "algorithm": "RS256",       // Signing algorithm.
        "key_path": "./keys/newest" // Path to save/load the private (.pem) and public (.pub) keys. Mount this as a volume in Docker to persist keys across restarts.
    },
    // Validation rules for specific fields when used in auth methods:
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
    // Toggles and settings for the modular authentication methods:
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

---

## 3. Public REST API

The IAM service exposes standard HTTP endpoints for client-facing user onboarding and authentication.

### `GET /health`
Returns the operational status of the IAM service and its dependencies (e.g., MongoDB). This endpoint is used by load balancers and container orchestrators (like Kubernetes or Docker) for health checks.

**Success Response (200 OK):**
```json
{
  "status": "alive",
  "database": "ok",
  "time": "2026-03-07T12:00:00Z"
}
```

**Degraded Response (503 Service Unavailable):**
If the database is unreachable:
```json
{
  "status": "alive",
  "database": "error: connection refused",
  "time": "2026-03-07T12:00:00Z"
}
```

### `POST /api/v1/register`
Creates a new user account in the MongoDB database. The submitted password will be automatically hashed using `bcrypt`.

**Request Body:**
```json
{
  "type": "string", // The ID of the registration method (e.g., "email-password", "sms-password", "username-password")
  "fields": {
    // Dynamic fields required by the chosen method.
    // Example for "email-password":
    "email": "user@example.com",
    "password": "securepassword123!"
  }
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Authentication successful" // The token is set securely via an HttpOnly cookie.
}
```

**Error Response (400 Bad Request):**
```json
{
  "success": false,
  "message": "email already in use" // Indicates validation failures, missing fields, or duplicate users.
}
```

### `POST /api/v1/login`
Authenticates an existing user and issues a bearer token. This endpoint queries MongoDB to verify the password hash and checks the user's `is_banned` status before issuing a token.

**Request Body:**
```json
{
  "type": "string", // The ID of the login method (e.g., "email-password")
  "fields": {
    "email": "user@example.com",
    "password": "securepassword123!"
  }
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Authentication successful" // The token is set securely via an HttpOnly cookie.
}
```

**Error Response (401 Unauthorized):**
```json
{
  "success": false,
  "message": "invalid email or password" // Or "user is banned: <reason>"
}
```

---

## 4. JWT Token Structure

The tokens issued by `grxm-iam` are standard JWTs (signed with RSA/RS256). Consumer applications should decode the payload (using the IAM service's Public Key) to identify the user making the request.

**Standard Claims Included:**
*   `uid` (String): The cryptographically secure User ID. This is the primary key you should use to link resources in your consumer APIs.
*   `roles` (Array of Strings): The roles currently assigned to the user (e.g., `["user", "admin"]`). This allows your application to handle role-based access control instantly.
*   `exp` (NumericDate): The expiration time of the token (Unix timestamp).

*(Note: In upcoming iterations, verification statuses will also be embedded into these claims).*

---

## 5. Authority WebSocket API

The Authority API is a persistent, secure WebSocket connection intended **only** for trusted backend administrative services to mutate user state (banning, role management) in real-time and retrieve cryptographic materials.

**Endpoint:** `ws://<iam-host>:<port>/api/v1/authority` (The path is configurable in `config.json`)

### Authentication
Connections are immediately terminated if not authenticated. Provide the authority password (from `config.json`) via one of two methods when establishing the connection:
1.  **HTTP Header:** `Authorization: Bearer <authority_password>`
2.  **Query Parameter:** `ws://.../authority?auth=<authority_password>`

### Real-Time Commands

Commands are sent as JSON messages over the open WebSocket connection. The IAM service executes these directly against the MongoDB layer.

**1. Fetch Public Key**
Retrieves the RSA Public Key needed by your API servers to validate incoming user tokens.
```json
// Request
{ "action": "public_key" }

// Response
{
  "success": true,
  "message": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvp2E... \n-----END PUBLIC KEY-----"
}
```

**2. Ban User**
Instantly sets the user's `is_banned` flag in MongoDB to `true`, blocking all future login attempts.
```json
// Request
{
  "action": "ban",
  "payload": {
    "user_id": "UID_STRING_HERE",
    "reason": "Violated terms of service."
  }
}

// Response
{ "success": true, "message": "User banned successfully" }
```

**3. Unban User**
Restores access to a banned user.
```json
// Request
{
  "action": "unban",
  "payload": {
    "user_id": "UID_STRING_HERE"
  }
}

// Response
{ "success": true, "message": "User unbanned successfully" }
```

**4. Update All Roles**
Modifies all roles assigned to a user in the database (replaces the array).
```json
// Request
{
  "action": "role",
  "payload": {
    "user_id": "UID_STRING_HERE",
    "roles": ["user", "admin", "moderator"]
  }
}

// Response
{ "success": true, "message": "Roles updated successfully" }
```

**5. Add a Single Role**
Appends a single role to the user's existing roles.
```json
// Request
{
  "action": "role_add",
  "payload": {
    "user_id": "UID_STRING_HERE",
    "role": "premium"
  }
}

// Response
{ "success": true, "message": "Role added successfully" }
```

**6. Remove a Single Role**
Removes a specific role from the user's roles.
```json
// Request
{
  "action": "role_delete",
  "payload": {
    "user_id": "UID_STRING_HERE",
    "role": "premium"
  }
}

// Response
{ "success": true, "message": "Role removed successfully" }
```

---

## 6. Setup & Deployment Guide

To effectively run and orchestrate `grxm-iam` locally or within a Docker environment, follow these steps:

### Prerequisites
*   **Go 1.25+** (if compiling from source).
*   **MongoDB Instance** (running locally or within a Docker network).

### Building and Running
1.  **Compile the Application:**
    ```bash
    go build -o iam .
    ```
2.  **Ensure Keys Directory Exists:**
    The application will automatically generate and save RSA keys if they don't exist, but the parent directory defined in `config.json` (`./keys` by default) must exist:
    ```bash
    mkdir -p keys
    ```
3.  **Start the Service:**
    ```bash
    ./iam
    ```
    *Alternatively, set the config location explicitly:*
    ```bash
    IAM_CONFIG_LOCATION=/path/to/config.json ./iam
    ```

### Docker Orchestration Considerations
When creating a `docker-compose.yml` for this service:
*   **Networking:** Ensure the `database.uri` in `config.json` uses the Docker service name for MongoDB (e.g., `mongodb://mongo:27017`).
*   **Volume Mounts:** Mount the `./keys` directory as a persistent volume. If the container restarts and the keys are lost, all previously issued JWTs will immediately become invalid because the service will generate a new keypair and fail to verify old signatures.
*   **Port Forwarding:** The service listens on `8080` by default. Expose this port so your API gateway or frontend can communicate with it.
