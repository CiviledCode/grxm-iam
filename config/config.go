package config

import (
	"encoding/json"
	"os"
)

type IAMConfig struct {
	ID          map[string]any `json:"id"`
	Token       map[string]any `json:"token"`
	AuthMethods map[string]any `json:"auth_methods"`
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
