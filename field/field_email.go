package field

import "strings"

type EmailInputField struct {
	Name     string
	Required bool
}

func (e *EmailInputField) FieldName() string {
	return e.Name
}

func (e *EmailInputField) IsRequired() bool {
	return e.Required
}

func (e *EmailInputField) Validate(val any) bool {
	v, ok := val.(string)
	if !ok || v == "" {
		return false
	}
	// Basic format validation
	return strings.Contains(v, "@") && strings.Contains(v, ".")
}
