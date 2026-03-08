package field

import (
	"strings"
	"unicode"
)

type PasswordInputField struct {
	Name             string
	Required         bool
	MinLength        int
	MaxLength        int
	RequireSymbols   bool
	RequireUppercase bool
	SymbolList       string
}

func (p *PasswordInputField) FieldName() string {
	return p.Name
}

func (p *PasswordInputField) IsRequired() bool {
	return p.Required
}

func (p *PasswordInputField) Validate(val any) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}

	if len(v) < p.MinLength || (p.MaxLength > 0 && len(v) > p.MaxLength) {
		return false
	}

	if p.RequireSymbols && p.SymbolList != "" {
		if !strings.ContainsAny(v, p.SymbolList) {
			return false
		}
	}

	if p.RequireUppercase {
		hasUppercase := false
		for _, char := range v {
			if unicode.IsUpper(char) {
				hasUppercase = true
				break
			}
		}
		if !hasUppercase {
			return false
		}
	}

	return true
}
