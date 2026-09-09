package httpapi

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestHealth(t *testing.T) {
    request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
    response := httptest.NewRecorder()

    NewHandler().ServeHTTP(response, request)

    if response.Code != http.StatusOK {
        t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
    }
    if got := response.Body.String(); got != "{\"status\":\"ok\"}\n" {
        t.Fatalf("body = %q", got)
    }
}

func TestHealthRejectsUnsupportedMethod(t *testing.T) {
    request := httptest.NewRequest(http.MethodPost, "/healthz", nil)
    response := httptest.NewRecorder()

    NewHandler().ServeHTTP(response, request)

    if response.Code != http.StatusMethodNotAllowed {
        t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
    }
}
