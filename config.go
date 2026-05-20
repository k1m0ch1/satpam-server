package main

import (
	"encoding/json"
	"errors"
	"os"
)

const serverConfigFile = "satpam-server.json"

type serverConfig struct {
	Driver string `json:"driver"` // "sqlite" | "postgres"
	DSN    string `json:"dsn"`
}

func loadServerConfig() (*serverConfig, error) {
	data, err := os.ReadFile(serverConfigFile)
	if err != nil {
		return nil, err
	}
	var cfg serverConfig
	return &cfg, json.Unmarshal(data, &cfg)
}

func saveServerConfig(cfg serverConfig) error {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(serverConfigFile, data, 0600)
}

func serverConfigExists() bool {
	_, err := os.Stat(serverConfigFile)
	return !errors.Is(err, os.ErrNotExist)
}
