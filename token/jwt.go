package token

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWTSource implements the TokenSource interface using the golang-jwt/jwt library.
// It holds the configuration for signing/validating tokens and the claims for a
// single token instance.
type JWTSource struct {
	// signingMethod is the algorithm to use, e.g., jwt.SigningMethodHS256.
	signingMethod jwt.SigningMethod
	// signingKey is the key used for signing tokens (e.g., []byte or *rsa.PrivateKey).
	signingKey any
	// validationKey is the key used for parsing and validating tokens (e.g., []byte or *rsa.PublicKey).
	validationKey any
	// claims holds the key-value pairs that make up the JWT payload.
	claims jwt.MapClaims
}

// NewJWTSource creates a new JWTSource configured for a specific signing method and keys.
//
// For symmetric algorithms (e.g., HS256), signingKey and validationKey will be the same []byte slice.
// For asymmetric algorithms (e.g., RS256), signingKey should be the private key (*rsa.PrivateKey)
// and validationKey should be the corresponding public key (*rsa.PublicKey).
func NewJWTSource(method jwt.SigningMethod, signingKey, validationKey any) *JWTSource {
	return &JWTSource{
		signingMethod: method,
		signingKey:    signingKey,
		validationKey: validationKey,
	}
}

// New creates a new, empty JWTSource that inherits the key and method configuration.
// This allows a configured instance to be used as a factory for building or parsing tokens.
func (j *JWTSource) New() TokenSource {
	return &JWTSource{
		signingMethod: j.signingMethod,
		signingKey:    j.signingKey,
		validationKey: j.validationKey,
		claims:        make(jwt.MapClaims),
	}
}

// Set adds or updates a claim for the token.
func (j *JWTSource) Set(name string, value any) error {
	if j.claims == nil {
		j.claims = make(jwt.MapClaims)
	}
	j.claims[name] = value
	return nil
}

// Remove deletes a claim from the token.
func (j *JWTSource) Remove(name string) error {
	delete(j.claims, name)
	return nil
}

// Get retrieves a claim from a parsed token.
//
// NOTE: The underlying JWT library decodes all JSON numbers as float64.
// Your application code is responsible for converting this to the expected
// numeric type (e.g., int, uint64). Failure to do so may result in a runtime panic.
func (j *JWTSource) Get(name string) (any, error) {
	value, ok := j.claims[name]
	if !ok {
		return nil, fmt.Errorf("claim not found: %s", name)
	}
	return value, nil
}

// Build creates and signs a JWT string from the current set of claims.
func (j *JWTSource) Build() (string, error) {
	if j.signingKey == nil {
		return "", fmt.Errorf("jwt source is not configured with a signing key")
	}

	// Create a new token, specifying the signing method and claims.
	token := jwt.NewWithClaims(j.signingMethod, j.claims)

	// Sign the token with the configured key to get the complete, encoded token string.
	return token.SignedString(j.signingKey)
}

// Parse takes a token string, validates its signature and claims,
// and loads the claims into the JWTSource instance.
func (j *JWTSource) Parse(tokenString string) error {
	if j.validationKey == nil {
		return fmt.Errorf("jwt source is not configured with a validation key")
	}

	// The keyFunc provides the key for validation. It's critical to check the
	// token's signing method to prevent algorithm downgrade attacks.
	keyFunc := func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != j.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.validationKey, nil
	}

	// Parse the token string.
	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if the token is valid after parsing.
	if !token.Valid {
		return fmt.Errorf("token is invalid")
	}

	// Extract the claims.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("could not extract map claims from token")
	}

	j.claims = claims
	return nil
}
