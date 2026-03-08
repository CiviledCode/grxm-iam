package field

import "strings"

type StringInputField struct {
	Name      string
	Required  bool
	MinLength int
	MaxLength int
	Whitelist string
	Blacklist string
}

func (s *StringInputField) FieldName() string {
	return s.Name
}

func (s *StringInputField) IsRequired() bool {
	return s.Required
}

func (s *StringInputField) Validate(val any) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}

	if len(v) < s.MinLength || len(v) > s.MaxLength {
		return false
	}

	if s.Whitelist != "" {
		for _, char := range v {
			if !strings.ContainsRune(s.Whitelist, char) {
				return false
			}
		}
	}

	if s.Blacklist != "" {
		if strings.ContainsAny(v, s.Blacklist) {
			return false
		}
	}

	return true
}
