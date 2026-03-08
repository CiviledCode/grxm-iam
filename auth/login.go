package auth

import (
	"github.com/civiledcode/grxm-iam/config"
	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/field"
)

type LoginMethod interface {
	Construct(*config.IAMConfig, db.UserRepository)
	ID() string
	Fields() []field.InputField
	Verification() field.InputField
	TryAuth(map[string]any) (*db.User, string)
}
