package field

type BooleanInputField struct {
	Name     string
	Required bool
}

func (s *BooleanInputField) FieldName() string {
	return s.Name
}

func (s *BooleanInputField) IsRequired() bool {
	return s.Required
}

func (s *BooleanInputField) Validate(val any) bool {
	_, ok := val.(bool)
	if !ok {
		return false
	}

	return true
}
