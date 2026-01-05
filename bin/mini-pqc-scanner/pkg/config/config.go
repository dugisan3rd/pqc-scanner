package config

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// Config holds the application configuration
type Config struct {
	Debug        bool   `json:"debug"`
	Organization string `json:"organization"`
	LicenseKey   string `json:"license_key"`
	CacheEnabled bool   `json:"cache_enabled"`
	ClientIP     string `json:"client_ip,omitempty"`
}

var (
	instance *Config
	once     sync.Once
	mu       sync.RWMutex
)

// GetConfig returns the singleton config instance
func GetConfig() *Config {
	once.Do(func() {
		instance = &Config{
			Debug:        false, // Default to debug off
			Organization: "",   // Default to empty organization
			LicenseKey:   "",   // Default to empty license key
			CacheEnabled: true,  // Default to cache enabled
		}
		loadConfig()
	})
	return instance
}

// findConfigFile tries to find the config file in multiple locations
func findConfigFile() (string, bool) {
	// Possible config file locations in order of preference
	possibleLocations := []string{
		"./config/pqc.json",                    // Current directory
		"../config/pqc.json",                   // Parent directory
		"/etc/pqc/config/pqc.json",             // System-wide config
		filepath.Join(os.Getenv("HOME"), ".pqc/config/pqc.json"), // User's home directory
	}

	// Try to get the executable path and check relative to it
	if exePath, err := exec.LookPath(os.Args[0]); err == nil {
		exeDir := filepath.Dir(exePath)
		possibleLocations = append([]string{
			filepath.Join(exeDir, "config/pqc.json"),      // Relative to executable
			filepath.Join(exeDir, "../config/pqc.json"),   // One level up from executable
		}, possibleLocations...)
	}

	// Check each location
	for _, location := range possibleLocations {
		if _, err := os.Stat(location); err == nil {
			return location, true
		}
	}

	// If not found, return the default location to create a new config
	return "./config/pqc.json", false
}

// getConfigDir returns the directory of the config file
func getConfigDir(configFile string) string {
	return filepath.Dir(configFile)
}

// loadConfig loads configuration from file
func loadConfig() {
	configFile, found := findConfigFile()
	configDir := getConfigDir(configFile)

	// Create config directory if it doesn't exist
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Printf("Failed to create config directory: %v", err)
			return
		}
	}

	// Check if config file exists
	if !found {
		// Create default config file
		defaultConfig := &Config{
			Debug:        true, // Default to debug on for initial setup
			Organization: "",  // Default to empty organization
			LicenseKey:   "",  // Default to empty license key
			CacheEnabled: true,  // Default to cache enabled
		}
		writeConfig(configFile, defaultConfig)
		instance = defaultConfig
		return
	}

	// Read config file
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Printf("Failed to read config file: %v", err)
		return
	}

	// Parse config file
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Failed to parse config file: %v", err)
		return
	}

	instance = &config
}

// writeConfig writes configuration to file
func writeConfig(configFile string, config *Config) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal config: %v", err)
		return
	}

	if err := ioutil.WriteFile(configFile, data, 0644); err != nil {
		log.Printf("Failed to write config file: %v", err)
	}
}

// IsDebug returns true if debug mode is enabled
func IsDebug() bool {
	mu.RLock()
	defer mu.RUnlock()
	return GetConfig().Debug
}

// IsConfigValid returns true if the config has all required fields
func IsConfigValid() bool {
	mu.RLock()
	defer mu.RUnlock()
	config := GetConfig()
	return config.Organization != "" && config.LicenseKey != ""
}

// ConfigFileExists returns true if the config file exists
func ConfigFileExists() bool {
	_, found := findConfigFile()
	return found
}

// SetDebug sets the debug mode
func SetDebug(debug bool) {
	mu.Lock()
	defer mu.Unlock()
	
	config := GetConfig()
	config.Debug = debug
	
	// Update config file
	configFile, _ := findConfigFile()
	writeConfig(configFile, config)
}

// GetOrganization returns the organization name
func GetOrganization() string {
	mu.RLock()
	defer mu.RUnlock()
	return GetConfig().Organization
}

// SetOrganization sets the organization name
func SetOrganization(org string) {
	mu.Lock()
	defer mu.Unlock()
	
	config := GetConfig()
	config.Organization = org
	
	// Update config file
	configFile, _ := findConfigFile()
	writeConfig(configFile, config)
}

// GetLicenseKey returns the license key
func GetLicenseKey() string {
	mu.RLock()
	defer mu.RUnlock()
	return GetConfig().LicenseKey
}

// SetLicenseKey sets the license key
func SetLicenseKey(key string) {
	mu.Lock()
	defer mu.Unlock()
	
	config := GetConfig()
	config.LicenseKey = key
	
	// Update config file
	configFile, _ := findConfigFile()
	writeConfig(configFile, config)
}

// GetCacheDir returns the directory for caching scan results
func GetCacheDir() string {
	configFile, _ := findConfigFile()
	configDir := getConfigDir(configFile)
	return filepath.Join(configDir, "cache")
}

// IsCacheEnabled returns true if caching is enabled
func IsCacheEnabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return GetConfig().CacheEnabled
}

// SetCacheEnabled sets the cache enabled flag
func SetCacheEnabled(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	
	config := GetConfig()
	config.CacheEnabled = enabled
	
	// Update config file
	configFile, _ := findConfigFile()
	writeConfig(configFile, config)
}

// GetClientIP returns the client IP override from config
func GetClientIP() string {
	mu.RLock()
	defer mu.RUnlock()
	return GetConfig().ClientIP
}
