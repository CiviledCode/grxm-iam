package config

import (
	"encoding/json"
	"os"
)

type IDConfig struct {
	Type    string `json:"type"`
	Length  int    `json:"length"`
	Charset string `json:"charset"`
}

type TokenConfig struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
	KeyPath   string `json:"key_path"`
}

type EmailConfig struct {
	UsernameMinLength int      `json:"username_min_length"`
	UsernameMaxLength int      `json:"username_max_length"`
	DomainMinLength   int      `json:"domain_min_length"`
	DomainMaxLength   int      `json:"domain_max_length"`
	DomainWhitelist   []string `json:"domain_whitelist"`
	DomainBlacklist   []string `json:"domain_blacklist"`
}

type PasswordConfig struct {
	
}

type SMSConfig struct {
}

type AuthorityConfig struct {
	Password string `json:"password"`
	Path     string `json:"path"`
}

type DatabaseConfig struct {
	URI      string `json:"uri"`
	Database string `json:"database"`
}

type ServerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type IAMConfig struct {
	Server      ServerConfig    `json:"server"`
	Database    DatabaseConfig  `json:"database"`
	Authority   AuthorityConfig `json:"authority"`
	DefaultRole string          `json:"default_role"`
	ID          IDConfig        `json:"id"`
	Token       TokenConfig     `json:"token"`
	Email       EmailConfig     `json:"email"`
	SMS         SMSConfig       `json:"sms"`
	Password    PasswordConfig  `json:"password"`
	AuthMethods map[string]any  `json:"auth_methods"`
}

func LoadConfig(filepath string) (*IAMConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var config IAMConfig

	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
