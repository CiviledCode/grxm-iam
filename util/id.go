package util

import (
	"crypto/rand"
	"math/big"

	"github.com/civiledcode/grxm-iam/config"
)

// GenerateID generates a random string ID based on the configuration.
func GenerateID(cfg config.IDConfig) string {
	length := cfg.Length
	if length <= 0 {
		length = 32
	}
	charset := cfg.Charset
	if charset == "" {
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	}

	b := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range b {
		n, _ := rand.Int(rand.Reader, charsetLen)
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
