package token

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/civiledcode/grxm-iam/config"
)

// TokenSource defines the interface for a stateful token builder and parser.
type TokenSource interface {
	// New creates a fresh instance, inheriting configuration but with empty claims.
	New(*config.IAMConfig) TokenSource
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
	// Save the keys used by this source to the file at filePath.
	Save(filePath string) error
	// Load the keys from the file at filePath into this source.
	Load(filePath string) error
	// Generate random keys from the supplied random source.
	Random(io.Reader) error
	// Determines if a given name matches that used by this token source. The inputted name will be lowercase.
	NameMatches(string) bool
}

func GetTokenSource(conf *config.IAMConfig) TokenSource {
	var src TokenSource

	for _, s := range RegisteredSources {
		if s.NameMatches(conf.Token["type"].(string)) {
			src = s
		}
	}

	src.New(conf)

	keyFilepath := conf.Token["key_path"].(string)
	if err := src.Load(keyFilepath); err != nil {
		if err := src.Random(rand.Reader); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Key Loaded!")
	}

	if err := src.Save(keyFilepath); err != nil {
		panic(err)
	}

	return src
}
