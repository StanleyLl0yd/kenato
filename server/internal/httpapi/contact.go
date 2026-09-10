package httpapi

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
)

const (
	protobufContentType      = "application/x-protobuf"
	maxCryptoConcurrent      = 4
	maxCryptoOperations      = 600
	cryptoRateWindowDuration = time.Minute
	contactOperationTimeout  = 8 * time.Second
)

type contactService interface {
	PublishIdentity(context.Context, contact.PublishIdentityRequest) (uint64, error)
	CreateInvite(context.Context, contact.CreateInviteRequest) (int64, error)
	RedeemInvite(context.Context, contact.RedeemInviteRequest) (contact.PublicIdentityBundle, int64, error)
	ClaimInvite(context.Context, contact.ClaimInviteRequest) (contact.PublicIdentityBundle, []byte, int64, error)
}

type contactAPI struct {
	service contactService
	gate    *cryptoGate
}

func newContactAPI(service contactService) *contactAPI {
	return &contactAPI{
		service: service,
		gate:    newCryptoGate(time.Now),
	}
}

func (api *contactAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/identity/publish", api.publishIdentity)
	mux.HandleFunc("POST /v1/invites", api.createInvite)
	mux.HandleFunc("POST /v1/invites/redeem", api.redeemInvite)
	mux.HandleFunc("POST /v1/invites/claim", api.claimInvite)
}

func (api *contactAPI) publishIdentity(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodePublishIdentityRequest(requestBody)
	if err != nil {
		writeContactError(w, err)
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
	revision, err := api.service.PublishIdentity(ctx, request)
	if err != nil {
		writeContactError(w, err)
		return
	}
	writeProtobuf(w, http.StatusOK, contact.EncodePublishIdentityResponse(revision))
}

func (api *contactAPI) createInvite(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodeCreateInviteRequest(requestBody)
	if err != nil {
		writeContactError(w, err)
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
	expiresAt, err := api.service.CreateInvite(ctx, request)
	if err != nil {
		writeContactError(w, err)
		return
	}
	writeProtobuf(w, http.StatusCreated, contact.EncodeCreateInviteResponse(expiresAt))
}

func (api *contactAPI) redeemInvite(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodeRedeemInviteRequest(requestBody)
	if err != nil {
		writeContactError(w, err)
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
	creatorBundle, redeemedAt, err := api.service.RedeemInvite(ctx, request)
	if err != nil {
		writeContactError(w, err)
		return
	}
	response, err := contact.EncodeRedeemInviteResponse(creatorBundle, redeemedAt)
	if err != nil {
		writeContactError(w, err)
		return
	}
	writeProtobuf(w, http.StatusOK, response)
}

func (api *contactAPI) claimInvite(w http.ResponseWriter, r *http.Request) {
	requestBody, ok := readProtobufBody(w, r)
	if !ok {
		return
	}
	request, err := contact.DecodeClaimInviteRequest(requestBody)
	if err != nil {
		writeContactError(w, err)
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
	redeemerBundle, redemptionSignature, redeemedAt, err := api.service.ClaimInvite(ctx, request)
	if err != nil {
		writeContactError(w, err)
		return
	}
	response, err := contact.EncodeClaimInviteResponse(redeemerBundle, redemptionSignature, redeemedAt)
	if err != nil {
		writeContactError(w, err)
		return
	}
	writeProtobuf(w, http.StatusOK, response)
}

func contactContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, contactOperationTimeout)
}

func readProtobufBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
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
	if len(body) == 0 || len(body) > contact.MaxWireMessageBytes {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func writeProtobuf(w http.ResponseWriter, status int, payload []byte) {
	if len(payload) == 0 || len(payload) > contact.MaxWireMessageBytes {
		http.Error(w, "contact response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", protobufContentType)
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(int(cryptoRateWindowDuration/time.Second)))
	http.Error(w, "request rate limit exceeded", http.StatusTooManyRequests)
}

func writeContactError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "contact service unavailable"
	switch {
	case errors.Is(err, contact.ErrMalformedWire),
		errors.Is(err, contact.ErrInvalidBundle),
		errors.Is(err, contact.ErrInvalidInvite),
		errors.Is(err, contact.ErrUnsupportedVersion),
		errors.Is(err, contact.ErrSelfInvite):
		status = http.StatusBadRequest
		message = "invalid contact request"
	case errors.Is(err, contact.ErrIdentityNotFound), errors.Is(err, contact.ErrInviteNotFound):
		status = http.StatusNotFound
		message = "contact resource not found"
	case errors.Is(err, contact.ErrInviteExpired):
		status = http.StatusGone
		message = "invite expired"
	case errors.Is(err, contact.ErrPublicationConflict),
		errors.Is(err, contact.ErrInviteAlreadyUsed),
		errors.Is(err, contact.ErrInviteNotRedeemed):
		status = http.StatusConflict
		message = "contact state conflict"
	case errors.Is(err, contact.ErrCapacity):
		status = http.StatusTooManyRequests
		message = "contact capacity limit reached"
	case errors.Is(err, context.Canceled):
		return
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
		message = "contact request timed out"
	}
	http.Error(w, message, status)
}

type cryptoGate struct {
	mu          sync.Mutex
	windowStart time.Time
	operations  int
	inFlight    chan struct{}
	clock       func() time.Time
}

func newCryptoGate(clock func() time.Time) *cryptoGate {
	return &cryptoGate{
		windowStart: clock(),
		inFlight:    make(chan struct{}, maxCryptoConcurrent),
		clock:       clock,
	}
}

func (g *cryptoGate) acquire() (func(), bool) {
	now := g.clock()
	g.mu.Lock()
	if now.Sub(g.windowStart) >= cryptoRateWindowDuration || now.Before(g.windowStart) {
		g.windowStart = now
		g.operations = 0
	}
	if g.operations >= maxCryptoOperations {
		g.mu.Unlock()
		return nil, false
	}
	select {
	case g.inFlight <- struct{}{}:
		g.operations++
		g.mu.Unlock()
		return func() { <-g.inFlight }, true
	default:
		g.mu.Unlock()
		return nil, false
	}
}
