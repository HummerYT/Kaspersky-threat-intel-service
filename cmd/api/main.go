package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"threat-intel-service/internal/config"
	"threat-intel-service/internal/httpapi"
	"threat-intel-service/internal/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("create PostgreSQL connection pool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := pool.Ping(pingCtx); err != nil {
		logger.Error("connect to PostgreSQL", "error", err)
		os.Exit(1)
	}
	if err := postgres.ApplyMigrations(ctx, pool); err != nil {
		logger.Error("apply database migrations", "error", err)
		os.Exit(1)
	}

	threatRepo := postgres.NewPostgresRepository(pool)
	handler := httpapi.NewHandler(threatRepo, logger)
	var routes http.Handler = handler.Routes()
	routes = httpapi.APIKeyMiddleware(cfg.APIKey, routes)
	routes = httpapi.RateLimitMiddleware(cfg.RateLimit, cfg.RateWindow, routes)

	server := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      routes,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("HTTP server is starting", "address", cfg.HTTPAddr, "tls", cfg.TLSCertFile != "")
		if cfg.TLSCertFile != "" {
			serverErrors <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			_ = server.Close()
		}
		logger.Info("HTTP server stopped")
	}
}
