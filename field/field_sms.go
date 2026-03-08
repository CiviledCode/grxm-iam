package field

import "regexp"

type SMSInputField struct {
	Name     string
	Required bool
}

var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)

func (s *SMSInputField) FieldName() string {
	return s.Name
}

func (s *SMSInputField) IsRequired() bool {
	return s.Required
}

func (s *SMSInputField) Validate(val any) bool {
	v, ok := val.(string)
	if !ok || v == "" {
		return false
	}
	return phoneRegex.MatchString(v)
}
