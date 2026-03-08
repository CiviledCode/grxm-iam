package db

import (
	"context"
	"time"
)

// User represents the core user document.
// PII is kept strictly in this model and is not exposed in standard tokens.
type User struct {
	ID                 string    `bson:"_id" json:"id"`
	Email              string    `bson:"email,omitempty" json:"email,omitempty"`
	Phone              string    `bson:"phone,omitempty" json:"phone,omitempty"`
	Username           string    `bson:"username,omitempty" json:"username,omitempty"`
	PasswordHash       string    `bson:"password_hash,omitempty" json:"-"`
	Roles              []string  `bson:"roles" json:"roles"`
	IsBanned           bool      `bson:"is_banned" json:"is_banned"`
	BanReason          string    `bson:"ban_reason,omitempty" json:"ban_reason,omitempty"`
	IsEmailVerified    bool      `bson:"is_email_verified" json:"is_email_verified"`
	IsPhoneVerified    bool      `bson:"is_phone_verified" json:"is_phone_verified"`
	CreatedAt          time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt          time.Time `bson:"updated_at" json:"updated_at"`
}

// UserRepository defines the required operations for the database layer.
type UserRepository interface {
	// Create inserts a new user into the database.
	Create(ctx context.Context, user *User) error
	// GetByID retrieves a user by their unique ID.
	GetByID(ctx context.Context, id string) (*User, error)
	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (*User, error)
	// GetByPhone retrieves a user by their phone number.
	GetByPhone(ctx context.Context, phone string) (*User, error)
	// GetByUsername retrieves a user by their username.
	GetByUsername(ctx context.Context, username string) (*User, error)
	// UpdateRoles modifies a user's roles.
	UpdateRoles(ctx context.Context, id string, roles []string) error
	// AddRole adds a role to a user.
	AddRole(ctx context.Context, id string, role string) error
	// RemoveRole removes a role from a user.
	RemoveRole(ctx context.Context, id string, role string) error
	// SetBanStatus updates a user's ban status and reason.
	SetBanStatus(ctx context.Context, id string, isBanned bool, reason string) error
	// Ping checks if the database is reachable.
	Ping(ctx context.Context) error
}
