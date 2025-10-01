package token

import (
	"fmt"
)

const (
	USER_ID         = "uid"
	EXPIRATION_TIME = "exp"
)

// UserToken is the application-specific data model for a user's token.
type UserToken struct {
	UserID         string
	ExpirationUnix int64
}

// ToToken populates a TokenSource with claims from a UserToken struct and builds the token string.
func ToToken(src TokenSource, u *UserToken) (string, error) {
	builder := src.New()
	if err := builder.Set(USER_ID, u.UserID); err != nil {
		return "", err
	}
	if err := builder.Set(EXPIRATION_TIME, u.ExpirationUnix); err != nil {
		return "", err
	}
	return builder.Build()
}

// FromToken parses a token string using a TokenSource and populates a UserToken struct.
// It correctly handles the conversion of numeric claims from the token.
func FromToken(src TokenSource, token string) (*UserToken, error) {
	parser := src.New()
	err := parser.Parse(token)
	if err != nil {
		return nil, err
	}

	uid, err := parser.Get(USER_ID)
	if err != nil {
		return nil, fmt.Errorf("error getting user id: %w", err)
	}
	uidStr, ok := uid.(string)
	if !ok {
		return nil, fmt.Errorf("user id claim is not a string")
	}

	exp, err := parser.Get(EXPIRATION_TIME)
	if err != nil {
		return nil, fmt.Errorf("error getting expiration time: %w", err)
	}

	// JWT libraries decode JSON numbers into float64, so we must convert it.
	expFloat, ok := exp.(float64)
	if !ok {
		return nil, fmt.Errorf("expiration time claim is not a number")
	}

	return &UserToken{
		UserID:         uidStr,
		ExpirationUnix: int64(expFloat),
	}, nil
}
