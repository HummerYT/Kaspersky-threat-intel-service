package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr     string
	DatabaseURL  string
	APIKey       string
	RateLimit    int
	RateWindow   time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	TLSCertFile  string
	TLSKeyFile   string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:     env("HTTP_ADDR", ":8080"),
		DatabaseURL:  env("DATABASE_URL", "postgres://threats:threats@localhost:5433/threats?sslmode=disable"),
		APIKey:       os.Getenv("API_KEY"),
		TLSCertFile:  os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:   os.Getenv("TLS_KEY_FILE"),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		RateWindow:   time.Minute,
	}

	limit, err := strconv.Atoi(env("RATE_LIMIT", "120"))
	if err != nil || limit < 0 {
		return Config{}, fmt.Errorf("RATE_LIMIT must be a non-negative integer")
	}
	cfg.RateLimit = limit

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}

	return cfg, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
