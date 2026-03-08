package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/field"
	"github.com/civiledcode/grxm-iam/util"
	"golang.org/x/crypto/bcrypt"
)

// DefaultLoginMethods defines the standard object-oriented login methods.
var DefaultLoginMethods = []LoginMethod{
	&EmailPasswordLogin{
		BaseAuthMethod: BaseAuthMethod{
			MethodID: "email-password",
			InputFields: []field.InputField{
				&field.EmailInputField{Name: "email", Required: true},
				&field.PasswordInputField{Name: "password", Required: true},
			},
		},
	},
	&SMSPasswordLogin{
		BaseAuthMethod: BaseAuthMethod{
			MethodID: "sms-password",
			InputFields: []field.InputField{
				&field.SMSInputField{Name: "phone", Required: true},
				&field.PasswordInputField{Name: "password", Required: true},
			},
		},
	},
	&UsernamePasswordLogin{
		BaseAuthMethod: BaseAuthMethod{
			MethodID: "username-password",
			InputFields: []field.InputField{
				&field.UsernameInputField{Name: "username", Required: true},
				&field.PasswordInputField{Name: "password", Required: true},
			},
		},
	},
}

// DefaultRegistrationMethods defines the standard registration methods.
var DefaultRegistrationMethods = []RegisterMethod{
	&EmailPasswordRegister{
		BaseAuthMethod: BaseAuthMethod{
			MethodID: "email-password",
			InputFields: []field.InputField{
				&field.EmailInputField{Name: "email", Required: true},
				&field.PasswordInputField{Name: "password", Required: true, MinLength: 8},
			},
		},
	},
	&SMSPasswordRegister{
		BaseAuthMethod: BaseAuthMethod{
			MethodID: "sms-password",
			InputFields: []field.InputField{
				&field.SMSInputField{Name: "phone", Required: true},
				&field.PasswordInputField{Name: "password", Required: true, MinLength: 8},
			},
		},
	},
	&UsernamePasswordRegister{
		BaseAuthMethod: BaseAuthMethod{
			MethodID: "username-password",
			InputFields: []field.InputField{
				&field.UsernameInputField{Name: "username", Required: true, MinLength: 3},
				&field.PasswordInputField{Name: "password", Required: true, MinLength: 8},
			},
		},
	},
}

func checkPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

type EmailPasswordLogin struct{ BaseAuthMethod }

func (e *EmailPasswordLogin) TryAuth(fields map[string]any) (*db.User, string) {
	if ok, msg := e.ValidateInputs(fields); !ok {
		return nil, msg
	}

	email := fields["email"].(string)
	password := fields["password"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := e.Repo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, "invalid email or password"
		}
		slog.Error("Database error during login", "error", err)
		return nil, "internal error"
	}

	if !checkPassword(user.PasswordHash, password) {
		return nil, "invalid email or password"
	}

	if user.IsBanned {
		return nil, "user is banned: " + user.BanReason
	}

	return user, ""
}

type SMSPasswordLogin struct{ BaseAuthMethod }

func (s *SMSPasswordLogin) TryAuth(fields map[string]any) (*db.User, string) {
	if ok, msg := s.ValidateInputs(fields); !ok {
		return nil, msg
	}

	phone := fields["phone"].(string)
	password := fields["password"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := s.Repo.GetByPhone(ctx, phone)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, "invalid phone or password"
		}
		slog.Error("Database error during login", "error", err)
		return nil, "internal error"
	}

	if !checkPassword(user.PasswordHash, password) {
		return nil, "invalid phone or password"
	}

	if user.IsBanned {
		return nil, "user is banned: " + user.BanReason
	}

	return user, ""
}

type UsernamePasswordLogin struct{ BaseAuthMethod }

func (u *UsernamePasswordLogin) TryAuth(fields map[string]any) (*db.User, string) {
	if ok, msg := u.ValidateInputs(fields); !ok {
		return nil, msg
	}

	username := fields["username"].(string)
	password := fields["password"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := u.Repo.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, "invalid username or password"
		}
		slog.Error("Database error during login", "error", err)
		return nil, "internal error"
	}

	if !checkPassword(user.PasswordHash, password) {
		return nil, "invalid username or password"
	}

	if user.IsBanned {
		return nil, "user is banned: " + user.BanReason
	}

	return user, ""
}

type EmailPasswordRegister struct{ BaseAuthMethod }

func (e *EmailPasswordRegister) TryRegister(fields map[string]any) (*db.User, string) {
	if ok, msg := e.ValidateInputs(fields); !ok {
		return nil, msg
	}

	email := fields["email"].(string)
	password := fields["password"].(string)

	hash, err := hashPassword(password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return nil, "internal error"
	}

	user := &db.User{
		ID:              util.GenerateID(e.Config.ID),
		Email:           email,
		PasswordHash:    hash,
		Roles:           []string{e.Config.DefaultRole},
		IsEmailVerified: false,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := e.Repo.Create(ctx, user); err != nil {
		if errors.Is(err, db.ErrDuplicateUser) {
			return nil, "email already in use"
		}
		slog.Error("Failed to create user", "error", err)
		return nil, "internal error"
	}

	return user, ""
}

type SMSPasswordRegister struct{ BaseAuthMethod }

func (s *SMSPasswordRegister) TryRegister(fields map[string]any) (*db.User, string) {
	if ok, msg := s.ValidateInputs(fields); !ok {
		return nil, msg
	}

	phone := fields["phone"].(string)
	password := fields["password"].(string)

	hash, err := hashPassword(password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return nil, "internal error"
	}

	user := &db.User{
		ID:              util.GenerateID(s.Config.ID),
		Phone:           phone,
		PasswordHash:    hash,
		Roles:           []string{s.Config.DefaultRole},
		IsPhoneVerified: false,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Repo.Create(ctx, user); err != nil {
		if errors.Is(err, db.ErrDuplicateUser) {
			return nil, "phone already in use"
		}
		slog.Error("Failed to create user", "error", err)
		return nil, "internal error"
	}

	return user, ""
}

type UsernamePasswordRegister struct{ BaseAuthMethod }

func (u *UsernamePasswordRegister) TryRegister(fields map[string]any) (*db.User, string) {
	if ok, msg := u.ValidateInputs(fields); !ok {
		return nil, msg
	}

	username := fields["username"].(string)
	password := fields["password"].(string)

	hash, err := hashPassword(password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return nil, "internal error"
	}

	user := &db.User{
		ID:           util.GenerateID(u.Config.ID),
		Username:     username,
		PasswordHash: hash,
		Roles:        []string{u.Config.DefaultRole},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := u.Repo.Create(ctx, user); err != nil {
		if errors.Is(err, db.ErrDuplicateUser) {
			return nil, "username already in use"
		}
		slog.Error("Failed to create user", "error", err)
		return nil, "internal error"
	}

	return user, ""
}
