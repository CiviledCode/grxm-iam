package token

// TokenSource defines the interface for a stateful token builder and parser.
type TokenSource interface {
	// New creates a fresh instance, inheriting configuration but with empty claims.
	New() TokenSource
	// Set adds or updates a claim.
	Set(name string, value any) error
	// Remove deletes a claim.
	Remove(name string) error
	// Get retrieves a claim by name.
	Get(name string) (any, error)
	// Build signs and serializes the claims into a token string.
	Build() (string, error)
	// Parse validates a token string and loads its claims.
	Parse(tokenString string) error
}
