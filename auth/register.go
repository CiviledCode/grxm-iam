package auth

import (
	"github.com/civiledcode/grxm-iam/config"
	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/field"
)

type RegisterMethod interface {
	Construct(*config.IAMConfig, db.UserRepository)
	ID() string
	Fields() []field.InputField
	Verification() field.InputField
	TryRegister(map[string]any) (*db.User, string)
}
