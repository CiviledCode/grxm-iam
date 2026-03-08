# grxm-iam: MVP Roadmap

To reach a Minimum Viable Product (MVP) suitable for a production environment with basic auth, SMS/email verification, and a zero-trust architecture, the following features and integrations must be completed:

## 1. Database Layer (`db` package)
*   **Define Interfaces:** Create core interfaces (`UserRepository`, `SessionRepository`) to ensure the data layer remains modular and DB-agnostic.
*   **MongoDB Implementation:** Implement these interfaces using the official Go MongoDB driver (`go.mongodb.org/mongo-driver`).
*   **User Model:** Define the core `User` struct containing fields for ID, email, phone, hashed password, roles, ban status, and verification status (ensuring PII stays in this layer).
*   **Connection Management:** Initialize the DB connection on server startup using a connection URI defined in `config.json`.

## 2. Authentication Logic & Cryptography
*   **Password Hashing:** Integrate `golang.org/x/crypto/bcrypt` or `argon2` for secure password hashing before storing them in the database.
*   **Wire Up Methods:** Update the currently mocked `TryAuth` and `TryRegister` functions in `auth/methods.go` to execute actual database queries, verify password hashes, and create new user documents.

## 3. Token Issuance & Verification (`token` package)
*   **Issue on Success:** Upon successful authentication in `TryAuth`, generate a real JWT containing the `UserID`, expiration time, and authorization roles. Return this token to the client.
*   **Verification Endpoint:** Create a public API endpoint (e.g., `POST /api/v1/verify-token`) or provide a lightweight Go library that consumer applications can use to validate the bearer token's signature and expiration without needing database access.

## 4. Verification Services (Email & SMS Delivery)
*   **Email Provider Integration:** Implement an interface for sending emails (e.g., SMTP, AWS SES, SendGrid). Add relevant credentials to `config.json`.
*   **SMS Provider Integration:** Implement an interface for sending SMS OTPs (e.g., Twilio, AWS SNS). Add relevant credentials to `config.json`.
*   **Temporary Code Storage:** Implement a fast, temporary storage solution for OTPs/verification codes (e.g., an in-memory cache, Redis, or a MongoDB collection with a TTL index) with short expiration times (e.g., 5-10 minutes).

## 5. Verification Flow (The `VerificationField`)
*   **Registration Verification:** Create a flow where a newly registered user is marked as `unverified` in the database. Provide an endpoint (e.g., `POST /api/v1/verify-registration`) where they submit the code sent to their email/phone to become active.
*   **2FA / Login Verification:** Utilize the `VerificationField` abstraction we created in `BaseAuthMethod`. If an auth method requires verification, `TryAuth` should return a "pending verification" state instead of a token, requiring the client to submit the OTP in a follow-up request to receive the final JWT.

## 6. Authority Actions Integration
*   **Execute Commands:** Connect the `authority/server.go` WebSocket handlers to the `db` layer so that incoming `ban` and `role` commands actively mutate the user records in MongoDB.
*   **Session Invalidation (Optional but recommended for Zero-Trust):** Implement a strategy to instantly invalidate active tokens when a user is banned (e.g., checking a "token issued after" timestamp in the DB against the JWT issue time, or maintaining a token blacklist).

## 7. Production Readiness & Security
*   **Rate Limiting:** Add HTTP middleware to rate-limit the login, registration, and OTP verification endpoints to prevent brute-force and credential stuffing attacks.
*   **Graceful Shutdown:** Implement proper OS signal handling (`SIGINT`, `SIGTERM`) in `main.go` to gracefully close the HTTP server, WebSocket connections, and Database pools before exiting.
*   **Dockerization:** Create a lean `Dockerfile` and a `docker-compose.yml` (including MongoDB) for reproducible deployments.
*   **Health Checks:** Add a `GET /health` endpoint for load balancers and container orchestrators to monitor the service.
