package token

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestHappyPath_Symmetric tests the full token lifecycle (create -> parse) with a symmetric key (HS256).
func TestHappyPath_Symmetric(t *testing.T) {
	// 1. Setup
	secretKey := []byte("a-very-secret-key-that-is-long-enough")
	jwtSource := NewJWTSource(jwt.SigningMethodHS256, secretKey, secretKey)

	originalUserToken := &UserToken{
		UserID:         "user-123",
		ExpirationUnix: time.Now().Add(time.Hour * 1).Unix(),
	}

	// 2. Execution - Build
	tokenString, err := ToToken(jwtSource, originalUserToken)
	if err != nil {
		t.Fatalf("Building token should not fail, but got: %v", err)
	}
	if tokenString == "" {
		t.Fatal("Token string should not be empty")
	}

	// 3. Execution - Parse
	parsedUserToken, err := FromToken(jwtSource, tokenString)
	if err != nil {
		t.Fatalf("Parsing token should not fail, but got: %v", err)
	}

	// 4. Assertions
	if originalUserToken.UserID != parsedUserToken.UserID {
		t.Errorf("expected UserID %q, but got %q", originalUserToken.UserID, parsedUserToken.UserID)
	}
	if originalUserToken.ExpirationUnix != parsedUserToken.ExpirationUnix {
		t.Errorf("expected ExpirationUnix %d, but got %d", originalUserToken.ExpirationUnix, parsedUserToken.ExpirationUnix)
	}
}

// TestHappyPath_Asymmetric tests the full token lifecycle with an asymmetric key pair (RS256).
func TestHappyPath_Asymmetric(t *testing.T) {
	// 1. Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	jwtSource := NewJWTSource(jwt.SigningMethodRS256, privateKey, publicKey)

	originalUserToken := &UserToken{
		UserID:         "user-456",
		ExpirationUnix: time.Now().Add(time.Hour * 24).Unix(),
	}

	// 2. Execution - Build
	tokenString, err := ToToken(jwtSource, originalUserToken)
	if err != nil {
		t.Fatalf("Building token failed: %v", err)
	}
	if tokenString == "" {
		t.Fatal("Token string should not be empty after building")
	}

	// 3. Execution - Parse
	parsedUserToken, err := FromToken(jwtSource, tokenString)
	if err != nil {
		t.Fatalf("Parsing token failed: %v", err)
	}

	// 4. Assertions
	if originalUserToken.UserID != parsedUserToken.UserID {
		t.Errorf("expected UserID %q, but got %q", originalUserToken.UserID, parsedUserToken.UserID)
	}
	if originalUserToken.ExpirationUnix != parsedUserToken.ExpirationUnix {
		t.Errorf("expected ExpirationUnix %d, but got %d", originalUserToken.ExpirationUnix, parsedUserToken.ExpirationUnix)
	}
}

// TestParse_InvalidSignature ensures parsing fails when the token is signed with a different key.
func TestParse_InvalidSignature(t *testing.T) {
	// 1. Setup
	signingKey := []byte("first-secret-key")
	validationKey := []byte("second-different-secret-key")

	signerSource := NewJWTSource(jwt.SigningMethodHS256, signingKey, signingKey)
	parserSource := NewJWTSource(jwt.SigningMethodHS256, validationKey, validationKey)

	userToken := &UserToken{UserID: "test-user", ExpirationUnix: time.Now().Add(time.Minute).Unix()}

	// 2. Execution - Build with the first key
	tokenString, err := ToToken(signerSource, userToken)
	if err != nil {
		t.Fatalf("Building token failed: %v", err)
	}

	// 3. Execution & Assertion - Parse with the second key
	_, err = FromToken(parserSource, tokenString)
	if err == nil {
		t.Fatal("Parsing with the wrong key should fail, but it did not")
	}
	expectedError := "signature is invalid"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("expected error to contain %q, but got %q", expectedError, err.Error())
	}
}

// TestParse_ExpiredToken ensures parsing fails if the token's 'exp' claim is in the past.
func TestParse_ExpiredToken(t *testing.T) {
	// 1. Setup
	secretKey := []byte("my-secret")
	jwtSource := NewJWTSource(jwt.SigningMethodHS256, secretKey, secretKey)
	expiredUserToken := &UserToken{
		UserID:         "expired-user",
		ExpirationUnix: time.Now().Add(-time.Minute * 5).Unix(), // 5 minutes in the past
	}

	// 2. Execution - Build
	tokenString, err := ToToken(jwtSource, expiredUserToken)
	if err != nil {
		t.Fatalf("Building token failed: %v", err)
	}

	// 3. Execution & Assertion - Parse
	_, err = FromToken(jwtSource, tokenString)
	if err == nil {
		t.Fatal("Parsing an expired token should fail, but it did not")
	}
	expectedError := "token is expired"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("expected error to contain %q, but got %q", expectedError, err.Error())
	}
}

// TestParse_MismatchedAlgorithm ensures the parser rejects a token signed with an unexpected algorithm.
func TestParse_MismatchedAlgorithm(t *testing.T) {
	// 1. Setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Signer uses RS256
	signerSource := NewJWTSource(jwt.SigningMethodRS256, privateKey, publicKey)

	// Parser expects HS256 (a common attack vector attempt)
	parserSource := NewJWTSource(jwt.SigningMethodHS256, publicKey, publicKey) // Incorrectly configured with a public key for HS256

	userToken := &UserToken{UserID: "alg-test", ExpirationUnix: time.Now().Add(time.Minute).Unix()}

	// 2. Execution - Build
	tokenString, err := ToToken(signerSource, userToken)
	if err != nil {
		t.Fatalf("Building token failed: %v", err)
	}

	// 3. Execution & Assertion - Parse
	_, err = FromToken(parserSource, tokenString)
	if err == nil {
		t.Fatal("Parsing with mismatched algorithm should fail, but it did not")
	}
	expectedError := "unexpected signing method"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("expected error to contain %q, but got %q", expectedError, err.Error())
	}
}
