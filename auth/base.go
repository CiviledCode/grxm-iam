package auth

import (
	"github.com/civiledcode/grxm-iam/config"
	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/field"
)

// BaseAuthMethod provides the object-oriented building block for auth methods.
type BaseAuthMethod struct {
	MethodID          string
	InputFields       []field.InputField
	VerificationField field.InputField // Optional 2FA validation field
	Config            *config.IAMConfig
	Repo              db.UserRepository
}

func (b *BaseAuthMethod) Construct(cfg *config.IAMConfig, repo db.UserRepository) {
	b.Config = cfg
	b.Repo = repo
}

func (b *BaseAuthMethod) ID() string {
	return b.MethodID
}

func (b *BaseAuthMethod) Fields() []field.InputField {
	return b.InputFields
}

func (b *BaseAuthMethod) Verification() field.InputField {
	return b.VerificationField
}

// ValidateInputs runs the generic validation across all building-block fields.
func (b *BaseAuthMethod) ValidateInputs(payload map[string]any) (bool, string) {
	// Check standard input fields
	for _, f := range b.InputFields {
		val, ok := payload[f.FieldName()]
		if f.IsRequired() && !ok {
			return false, "missing required field: " + f.FieldName()
		}
		if ok && !f.Validate(val) {
			return false, "invalid field format: " + f.FieldName()
		}
	}

	// Check optional verification field (2FA) if it exists in the payload or is required
	if b.VerificationField != nil {
		val, ok := payload[b.VerificationField.FieldName()]
		if b.VerificationField.IsRequired() && !ok {
			return false, "missing required verification field: " + b.VerificationField.FieldName()
		}
		if ok && !b.VerificationField.Validate(val) {
			return false, "invalid verification field format: " + b.VerificationField.FieldName()
		}
	}

	return true, ""
}
