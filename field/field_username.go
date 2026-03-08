package field

type UsernameInputField struct {
	Name      string
	Required  bool
	MinLength int
	MaxLength int
}

func (u *UsernameInputField) FieldName() string {
	return u.Name
}

func (u *UsernameInputField) IsRequired() bool {
	return u.Required
}

func (u *UsernameInputField) Validate(val any) bool {
	v, ok := val.(string)
	if !ok {
		return false
	}
	
	l := len(v)
	if u.MinLength > 0 && l < u.MinLength {
		return false
	}
	if u.MaxLength > 0 && l > u.MaxLength {
		return false
	}
	return true
}
