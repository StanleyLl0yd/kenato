package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
)

const maxRequestBodyBytes int64 = contact.MaxSessionWireMessageBytes

type healthResponse struct {
	Status string `json:"status"`
}

func NewHandler(service contactService) http.Handler {
	return newHandler(service, nil)
}

func NewHandlerWithSession(service contactService, sessions sessionService) http.Handler {
	return newHandler(service, sessions)
}

func newHandler(service contactService, sessions sessionService) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	gate := newCryptoGate(time.Now)
	if service != nil {
		api := newContactAPI(service)
		api.gate = gate
		api.register(mux)
	}
	if sessions != nil {
		newSessionAPI(sessions, gate).register(mux)
	}
	return withSecurityHeaders(withRequestLimit(mux))
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(healthResponse{Status: "ok"})
}

func withRequestLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
