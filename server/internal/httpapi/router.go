package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
)

const maxRequestBodyBytes int64 = contact.MaxWireMessageBytes

type healthResponse struct {
	Status string `json:"status"`
}

func NewHandler(service contactService) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	if service != nil {
		newContactAPI(service).register(mux)
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
