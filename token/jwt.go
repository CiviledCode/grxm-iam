package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/civiledcode/grxm-iam/config"
	"github.com/golang-jwt/jwt/v5"
)

// JWTSource implements the TokenSource interface using the golang-jwt/jwt library.
// It holds the configuration for signing/validating tokens and the claims for a
// single token instance.
type JWTSource struct {
	// signingMethod is the algorithm to use, e.g., jwt.SigningMethodHS256.
	signingMethod jwt.SigningMethod
	// signingKey is the key used for signing tokens.
	signingKey *rsa.PrivateKey
	// validationKey is the key used for parsing and validating tokens.
	validationKey *rsa.PublicKey
	// claims holds the key-value pairs that make up the JWT payload.
	claims jwt.MapClaims
	// bitSize is the amount of bits each key is.
	bitSize int
}

// New creates a new, empty JWTSource that inherits the key and method configuration.
// This allows a configured instance to be used as a factory for building or parsing tokens.
func (j *JWTSource) New(c *config.IAMConfig) TokenSource {
	if c != nil {
		j.bitSize = c.Token.Bits
		var signingMethod jwt.SigningMethod
		switch strings.ToUpper(c.Token.Algorithm) {
		// TODO: Add more
		case "RS256":
			signingMethod = jwt.SigningMethodRS256
		case "RS384":
			signingMethod = jwt.SigningMethodRS384
		case "RS512":
			signingMethod = jwt.SigningMethodRS512
		default:
			panic("invalid signing method for JWT token source")
		}
		j.signingMethod = signingMethod
		return j
	}

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

// Save marshals the RSA private key to the PEM format and writes it to a file.
// It ensures the key file is saved with restricted permissions (read/write for owner only).
func (j *JWTSource) Save(filePath string) error {
	if j.signingKey == nil {
		return fmt.Errorf("signing key is not available to save")
	}

	// Marshal the RSA private key into PKCS#1, ASN.1 DER format.
	derBytes := x509.MarshalPKCS1PrivateKey(j.signingKey)

	// Create a PEM block to hold the DER-encoded key.
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	// Write the PEM-encoded data to the specified file.
	// The file permission 0600 restricts access to the file owner.
	err := os.WriteFile(filePath, pem.EncodeToMemory(pemBlock), 0600)
	if err != nil {
		return fmt.Errorf("failed to write key to file %s: %w", filePath, err)
	}

	if j.signingKey == nil {
		return fmt.Errorf("signing key is not available to save")
	}

	// Marshal the RSA private key into PKCS#1, ASN.1 DER format.
	derBytes = x509.MarshalPKCS1PublicKey(j.validationKey)

	// Create a PEM block to hold the DER-encoded key.
	pemBlock = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	}

	// Write the PEM-encoded data to the specified file.
	// The file permission 0600 restricts access to the file owner.
	err = os.WriteFile(filePath+".pub", pem.EncodeToMemory(pemBlock), 0600)
	if err != nil {
		return fmt.Errorf("failed to write key to file %s: %w", filePath, err)
	}

	return nil
}

// Load reads a PEM-encoded RSA private key from a file, parses it,
// and sets the signing and validation keys for the JWTSource.
func (j *JWTSource) Load(filePath string) error {
	// Read the entire PEM-encoded file.
	pemBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read key from file %s: %w", filePath, err)
	}

	// Decode the PEM block from the file content.
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from %s", filePath)
	}

	// Parse the DER-encoded private key from the PEM block.
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse DER encoded private key: %w", err)
	}

	// Set the signing and validation keys on the JWTSource instance.
	j.signingKey = privateKey
	j.validationKey = &privateKey.PublicKey

	return nil
}

// Random generates a new RSA private/public key pair.
// This function is included from your original prompt for context.
func (j *JWTSource) Random(randSrc io.Reader) error {
	privateKey, err := rsa.GenerateKey(randSrc, j.bitSize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	j.signingKey = privateKey
	j.validationKey = &privateKey.PublicKey
	return nil
}

func (j *JWTSource) NameMatches(name string) bool {
	if name == "jwt" || name == "json" {
		return true
	}

	return false
}

func (j *JWTSource) PublicKeyPEM() (string, error) {
	if j.validationKey == nil {
		return "", fmt.Errorf("public key not loaded")
	}

	derBytes, err := x509.MarshalPKIXPublicKey(j.validationKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
