package user

import (
	"fmt"

	"github.com/civiledcode/grxm-iam/token"
)

const (
	USER_ID          = "uid"
	EXPIRATION_TIME  = "exp"
	ROLES            = "roles"
	REFRESH_DEADLINE = "refresh_deadline"
)

// UserToken is the application-specific data model for a user's token.
type UserToken struct {
	UserID              string
	Roles               []string
	ExpirationUnix      int64
	RefreshDeadlineUnix int64
}

// ToToken populates a TokenSource with claims from a UserToken struct and builds the token string.
func ToToken(src token.TokenSource, u *UserToken) (string, error) {
	builder := src.New(nil)
	if err := builder.Set(USER_ID, u.UserID); err != nil {
		return "", err
	}
	if err := builder.Set(EXPIRATION_TIME, u.ExpirationUnix); err != nil {
		return "", err
	}
	if err := builder.Set(REFRESH_DEADLINE, u.RefreshDeadlineUnix); err != nil {
		return "", err
	}
	if err := builder.Set(ROLES, u.Roles); err != nil {
		return "", err
	}
	return builder.Build()
}

// FromToken parses a token string using a TokenSource and populates a UserToken struct.
// It correctly handles the conversion of numeric claims from the token.
func FromToken(src token.TokenSource, token string) (*UserToken, error) {
	parser := src.New(nil)
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

	refClaim, err := parser.Get(REFRESH_DEADLINE)
	if err != nil {
		return nil, fmt.Errorf("error getting refresh deadline: %w", err)
	}
	refFloat, ok := refClaim.(float64)
	if !ok {
		return nil, fmt.Errorf("refresh deadline claim is not a number")
	}

	rolesClaim, err := parser.Get(ROLES)
	var roleList []string
	if err == nil {
		if rolesArr, ok := rolesClaim.([]any); ok {
			for _, r := range rolesArr {
				if rStr, ok := r.(string); ok {
					roleList = append(roleList, rStr)
				}
			}
		}
	}

	return &UserToken{
		UserID:              uidStr,
		Roles:               roleList,
		ExpirationUnix:      int64(expFloat),
		RefreshDeadlineUnix: int64(refFloat),
	}, nil
}
