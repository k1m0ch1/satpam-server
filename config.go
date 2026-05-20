package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

const serverConfigFile = "satpam-server.json"

type serverConfig struct {
	AuthToken string `json:"auth_token"`
}

// DeriveToken returns hex(SHA-256(username + ":" + password)).
func DeriveToken(username, password string) string {
	h := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(h[:])
}

// LoadOrSetupConfig resolves the auth token in priority order:
//  1. SATPAM_AUTH_TOKEN environment variable
//  2. satpam-server.json config file
//  3. Interactive first-run wizard (only when stdin is a TTY)
func LoadOrSetupConfig() (string, error) {
	if t := os.Getenv("SATPAM_AUTH_TOKEN"); t != "" {
		return t, nil
	}
	cfg, err := loadServerConfig()
	if err == nil && cfg.AuthToken != "" {
		return cfg.AuthToken, nil
	}
	if !stdinIsTTY() {
		return "", fmt.Errorf(
			"no auth token configured — set SATPAM_AUTH_TOKEN or run the server interactively once to generate %s",
			serverConfigFile,
		)
	}
	return runConfigWizard()
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & fs.ModeCharDevice) != 0
}

func runConfigWizard() (string, error) {
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║   satpam-server  first-run  setup    ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("  Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username cannot be empty")
	}

	fmt.Print("  Password (visible): ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	token := DeriveToken(username, password)

	cfg := serverConfig{AuthToken: token}
	if err := saveServerConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "  [!] Could not save config: %v\n", err)
	} else {
		fmt.Printf("  [+] Config saved to %s\n", serverConfigFile)
	}

	fmt.Println()
	fmt.Println("  Bear token (add to each agent's server_token field):")
	fmt.Printf("  %s\n\n", token)

	return token, nil
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
	return os.WriteFile(serverConfigFile, data, 0o600)
}

func serverConfigExists() bool {
	_, err := os.Stat(serverConfigFile)
	return !errors.Is(err, os.ErrNotExist)
}
