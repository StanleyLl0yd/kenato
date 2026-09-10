package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
	"github.com/StanleyLl0yd/kenato/server/internal/httpapi"
)

const (
	defaultListenAddress  = "127.0.0.1:8080"
	defaultDatabasePath   = "kenato.db"
	inviteCleanupInterval = time.Hour
	maintenanceTimeout    = 10 * time.Second
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	startupCtx, startupCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	store, err := contact.OpenSQLiteStore(startupCtx, databasePath())
	startupCancel()
	if err != nil {
		logger.Fatalf("contact store initialization failed")
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	_, err = store.PruneExpiredInvites(cleanupCtx, time.Now().UTC())
	cleanupCancel()
	if err != nil {
		_ = store.Close()
		logger.Fatalf("contact store initialization failed")
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Printf("contact store close failed")
		}
	}()

	server := &http.Server{
		Addr:              listenAddress(),
		Handler:           httpapi.NewHandler(contact.NewService(store)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("kenato-server listening on %s", server.Addr)
		errCh <- server.ListenAndServe()
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	cleanupTicker := time.NewTicker(inviteCleanupInterval)
	defer cleanupTicker.Stop()

running:
	for {
		select {
		case now := <-cleanupTicker.C:
			ctx, cancel := context.WithTimeout(context.Background(), maintenanceTimeout)
			_, cleanupErr := store.PruneExpiredInvites(ctx, now.UTC())
			cancel()
			if cleanupErr != nil {
				logger.Printf("contact retention cleanup failed")
			}
		case sig := <-signalCh:
			logger.Printf("shutdown requested: %s", sig)
			break running
		case err := <-errCh:
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("server failed")
			}
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Printf("graceful shutdown failed")
		if closeErr := server.Close(); closeErr != nil {
			logger.Printf("forced shutdown failed")
		}
	}
}

func listenAddress() string {
	if address := strings.TrimSpace(os.Getenv("KENATO_LISTEN_ADDR")); address != "" {
		return address
	}
	return defaultListenAddress
}

func databasePath() string {
	if path := strings.TrimSpace(os.Getenv("KENATO_DB_PATH")); path != "" {
		return path
	}
	return defaultDatabasePath
}
