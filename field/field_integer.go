package field

type IntegerInputField struct {
	Name     string
	Required bool
	MinValue int64
	MaxValue int64
}

func (s *IntegerInputField) FieldName() string {
	return s.Name
}

func (s *IntegerInputField) IsRequired() bool {
	return s.Required
}

func (s *IntegerInputField) Validate(val any) bool {
	i, ok := val.(int64)
	if ok {
		return i < s.MaxValue && i > s.MinValue
	}

	f, ok := val.(float64)
	if ok {
		return f < float64(s.MaxValue) && f > float64(s.MinValue)
	}

	return false
}
