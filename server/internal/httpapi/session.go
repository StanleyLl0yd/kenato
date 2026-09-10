package httpapi

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
)

type sessionService interface {
	PublishSessionBootstrap(context.Context, contact.PublishSessionBootstrapRequest) (uint64, uint64, error)
	ReserveSessionBootstrap(context.Context, contact.ReserveSessionBootstrapRequest) (contact.ReserveSessionBootstrapResult, error)
	SubmitSessionInit(context.Context, contact.SubmitSessionInitRequest) error
	ClaimSessionInit(context.Context, contact.ClaimSessionInitRequest) (contact.ClaimSessionInitResult, error)
}

type sessionAPI struct {
	service sessionService
	gate    *cryptoGate
}

func newSessionAPI(service sessionService, gate *cryptoGate) *sessionAPI {
	return &sessionAPI{service: service, gate: gate}
}

func (api *sessionAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/session/bootstrap/publish", api.publishBootstrap)
	mux.HandleFunc("POST /v1/session/bootstrap/reserve", api.reserveBootstrap)
	mux.HandleFunc("POST /v1/session/init", api.submitInit)
	mux.HandleFunc("POST /v1/session/init/claim", api.claimInit)
}

func (api *sessionAPI) publishBootstrap(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readSessionProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodePublishSessionBootstrapRequest(requestBody)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	release, ok := api.gate.acquire()
	if !ok {
		writeRateLimited(w)
		return
	}
	defer release()

	ctx, cancel := contactContext(r.Context())
	defer cancel()
	generation, revision, err := api.service.PublishSessionBootstrap(ctx, request)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeSessionProtobuf(w, http.StatusOK, contact.EncodePublishSessionBootstrapResponse(generation, revision))
}

func (api *sessionAPI) reserveBootstrap(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readSessionProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodeReserveSessionBootstrapRequest(requestBody)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	release, ok := api.gate.acquire()
	if !ok {
		writeRateLimited(w)
		return
	}
	defer release()

	ctx, cancel := contactContext(r.Context())
	defer cancel()
	result, err := api.service.ReserveSessionBootstrap(ctx, request)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	response, err := contact.EncodeReserveSessionBootstrapResponse(result.CreatorBundle, result.CreatorOneTimeKey)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeSessionProtobuf(w, http.StatusOK, response)
}

func (api *sessionAPI) submitInit(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readSessionProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodeSubmitSessionInitRequest(requestBody)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	release, ok := api.gate.acquire()
	if !ok {
		writeRateLimited(w)
		return
	}
	defer release()

	ctx, cancel := contactContext(r.Context())
	defer cancel()
	if err := api.service.SubmitSessionInit(ctx, request); err != nil {
		writeSessionError(w, err)
		return
	}
	writeSessionProtobuf(w, http.StatusOK, contact.EncodeSubmitSessionInitResponse())
}

func (api *sessionAPI) claimInit(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readSessionProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodeClaimSessionInitRequest(requestBody)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	release, ok := api.gate.acquire()
	if !ok {
		writeRateLimited(w)
		return
	}
	defer release()

	ctx, cancel := contactContext(r.Context())
	defer cancel()
	result, err := api.service.ClaimSessionInit(ctx, request)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	response, err := contact.EncodeClaimSessionInitResponse(result)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	writeSessionProtobuf(w, http.StatusOK, response)
}

func readSessionProtobufBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (contentType != protobufContentType && contentType != "application/protobuf") {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return nil, false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid request body", http.StatusBadRequest)
		}
		return nil, false
	}
	if len(body) == 0 || len(body) > contact.MaxSessionWireMessageBytes {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func writeSessionProtobuf(w http.ResponseWriter, status int, payload []byte) {
	if len(payload) == 0 || len(payload) > contact.MaxSessionWireMessageBytes {
		http.Error(w, "session response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", protobufContentType)
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeSessionError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "session service unavailable"
	switch {
	case errors.Is(err, contact.ErrMalformedWire),
		errors.Is(err, contact.ErrInvalidSessionBootstrap),
		errors.Is(err, contact.ErrUnsupportedVersion),
		errors.Is(err, contact.ErrIdentityNotFound):
		status = http.StatusBadRequest
		message = "invalid session request"
	case errors.Is(err, contact.ErrInviteNotFound):
		status = http.StatusNotFound
		message = "session resource not found"
	case errors.Is(err, contact.ErrInviteExpired):
		status = http.StatusGone
		message = "invite expired"
	case errors.Is(err, contact.ErrSessionConflict),
		errors.Is(err, contact.ErrSessionKeyUnavailable),
		errors.Is(err, contact.ErrSessionInitMissing),
		errors.Is(err, contact.ErrSessionInitConflict),
		errors.Is(err, contact.ErrInviteNotRedeemed):
		status = http.StatusConflict
		message = "session state conflict"
	case errors.Is(err, contact.ErrCapacity):
		status = http.StatusTooManyRequests
		message = "session capacity limit reached"
	case errors.Is(err, context.Canceled):
		return
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
		message = "session request timed out"
	}
	http.Error(w, message, status)
}
