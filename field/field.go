package field

type InputField interface {
	FieldName() string
	IsRequired() bool
	Validate(any) bool
}
