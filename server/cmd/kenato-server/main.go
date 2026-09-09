package main

import (
    "context"
    "errors"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/StanleyLl0yd/kenato/server/internal/httpapi"
)

func main() {
    logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

    server := &http.Server{
        Addr:              ":8080",
        Handler:           httpapi.NewHandler(),
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

    select {
    case sig := <-signalCh:
        logger.Printf("shutdown requested: %s", sig)
    case err := <-errCh:
        if !errors.Is(err, http.ErrServerClosed) {
            logger.Fatalf("server failed: %v", err)
        }
        return
    }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        logger.Printf("graceful shutdown failed: %v", err)
        if closeErr := server.Close(); closeErr != nil {
            logger.Printf("forced shutdown failed: %v", closeErr)
        }
    }
}
