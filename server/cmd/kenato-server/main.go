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
	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

const (
	defaultListenAddress       = "127.0.0.1:8080"
	defaultDatabasePath        = "kenato.db"
	defaultMailboxDatabasePath = "kenato-mailbox.db"
	retentionCleanupInterval   = time.Hour
	maintenanceTimeout         = 10 * time.Second
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

	mailboxCtx, mailboxCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	mailboxStore, err := messaging.OpenSQLiteMailboxStore(mailboxCtx, mailboxDatabasePath())
	mailboxCancel()
	if err != nil {
		logger.Fatalf("mailbox store initialization failed")
	}
	defer func() {
		if err := mailboxStore.Close(); err != nil {
			logger.Printf("mailbox store close failed")
		}
	}()

	contactService := contact.NewService(store)
	sessionService := contact.NewSessionService(store, store)
	mailboxService := messaging.NewMailboxService(mailboxStore, store)
	messagingWS := httpapi.NewMessagingWebSocketServer(contactService, mailboxService)
	server := &http.Server{
		Addr:              listenAddress(),
		Handler:           httpapi.NewHandlerWithMessaging(contactService, sessionService, messagingWS),
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

	cleanupTicker := time.NewTicker(retentionCleanupInterval)
	defer cleanupTicker.Stop()

running:
	for {
		select {
		case now := <-cleanupTicker.C:
			inviteCleanupCtx, inviteCleanupCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
			_, inviteCleanupErr := store.PruneExpiredInvites(inviteCleanupCtx, now.UTC())
			inviteCleanupCancel()

			mailboxCleanupCtx, mailboxCleanupCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
			_, mailboxCleanupErr := mailboxStore.PruneExpired(mailboxCleanupCtx, now.UTC())
			mailboxCleanupCancel()

			if inviteCleanupErr != nil {
				logger.Printf("contact retention cleanup failed")
			}
			if mailboxCleanupErr != nil {
				logger.Printf("mailbox retention cleanup failed")
			}
		case sig := <-signalCh:
			logger.Printf("shutdown requested: %s", sig)
			break running
		case err := <-errCh:
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("server failed")
			}
			// Use the same ordered shutdown path as signal handling. Upgraded
			// WebSocket connections are not owned by net/http after hijack, so
			// returning here could close SQLite stores while M4 workers still run.
			break running
		}
	}

	// Stop upgraded WSS work first so its bounded send/drain workers finish
	// before the mailbox/contact stores are closed by the deferred cleanup.
	// Give the WebSocket and HTTP shutdown phases independent bounded budgets so
	// a slow WSS close cannot consume the HTTP server's entire graceful deadline.
	messagingShutdownCtx, messagingShutdownCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	if err := messagingWS.Shutdown(messagingShutdownCtx); err != nil {
		logger.Printf("messaging shutdown failed")
	}
	messagingShutdownCancel()

	httpShutdownCtx, httpShutdownCancel := context.WithTimeout(context.Background(), maintenanceTimeout)
	if err := server.Shutdown(httpShutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed")
		if closeErr := server.Close(); closeErr != nil {
			logger.Printf("forced shutdown failed")
		}
	}
	httpShutdownCancel()
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

func mailboxDatabasePath() string {
	if path := strings.TrimSpace(os.Getenv("KENATO_MAILBOX_DB_PATH")); path != "" {
		return path
	}
	return defaultMailboxDatabasePath
}
