package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
	"google.golang.org/protobuf/encoding/protowire"
)

type fakeSessionService struct {
	publishCalls       int
	publishHasDeadline bool
	publishErr         error
}

func (f *fakeSessionService) PublishSessionBootstrap(ctx context.Context, _ contact.PublishSessionBootstrapRequest) (uint64, uint64, error) {
	f.publishCalls++
	_, f.publishHasDeadline = ctx.Deadline()
	return 3, 7, f.publishErr
}

func (*fakeSessionService) ReserveSessionBootstrap(context.Context, contact.ReserveSessionBootstrapRequest) (contact.ReserveSessionBootstrapResult, error) {
	return contact.ReserveSessionBootstrapResult{}, errors.New("unexpected ReserveSessionBootstrap call")
}

func (*fakeSessionService) SubmitSessionInit(context.Context, contact.SubmitSessionInitRequest) error {
	return errors.New("unexpected SubmitSessionInit call")
}

func (*fakeSessionService) ClaimSessionInit(context.Context, contact.ClaimSessionInitRequest) (contact.ClaimSessionInitResult, error) {
	return contact.ClaimSessionInitResult{}, errors.New("unexpected ClaimSessionInit call")
}

func TestSessionPublishEndpointUsesBoundedProtobufAndDeadline(t *testing.T) {
	service := &fakeSessionService{}
	body := minimalSessionPublishRequest(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/session/bootstrap/publish", bytes.NewReader(body))
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()

	NewHandlerWithSession(&fakeContactService{}, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if service.publishCalls != 1 {
		t.Fatalf("publish calls=%d", service.publishCalls)
	}
	if !service.publishHasDeadline {
		t.Fatal("session service call did not receive a deadline")
	}
	if got := response.Header().Get("Content-Type"); got != protobufContentType {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
}

func TestSessionRoutesAreAbsentWithoutSessionService(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/session/bootstrap/publish", strings.NewReader("x"))
	request.Header.Set("Content-Type", protobufContentType)

	NewHandler(&fakeContactService{}).ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", response.Code)
	}
}

func TestSessionEndpointRejectsMalformedAndWrongContentTypeBeforeService(t *testing.T) {
	tests := map[string]struct {
		contentType string
		body        string
		want        int
	}{
		"wrong content type": {contentType: "application/json", body: "x", want: http.StatusUnsupportedMediaType},
		"malformed wire":     {contentType: protobufContentType, body: "\x80", want: http.StatusBadRequest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			service := &fakeSessionService{}
			request := httptest.NewRequest(http.MethodPost, "/v1/session/bootstrap/publish", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()

			NewHandlerWithSession(&fakeContactService{}, service).ServeHTTP(response, request)

			if response.Code != tc.want {
				t.Fatalf("status=%d, want %d", response.Code, tc.want)
			}
			if service.publishCalls != 0 {
				t.Fatalf("publish calls=%d", service.publishCalls)
			}
		})
	}
}

func TestSessionEndpointRejectsOversizedBodyBeforeService(t *testing.T) {
	service := &fakeSessionService{}
	body := bytes.Repeat([]byte{1}, contact.MaxSessionWireMessageBytes+1)
	request := httptest.NewRequest(http.MethodPost, "/v1/session/bootstrap/publish", bytes.NewReader(body))
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()

	NewHandlerWithSession(&fakeContactService{}, service).ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", response.Code)
	}
	if service.publishCalls != 0 {
		t.Fatalf("publish calls=%d", service.publishCalls)
	}
}

func TestSessionErrorsDoNotRevealIdentityExistenceOrInternals(t *testing.T) {
	invalid := httptest.NewRecorder()
	writeSessionError(invalid, contact.ErrInvalidSessionBootstrap)
	missing := httptest.NewRecorder()
	writeSessionError(missing, contact.ErrIdentityNotFound)
	if missing.Code != invalid.Code || missing.Body.String() != invalid.Body.String() {
		t.Fatal("session identity existence leaked through HTTP response")
	}

	internal := httptest.NewRecorder()
	writeSessionError(internal, errors.New("database path and private diagnostics"))
	if internal.Code != http.StatusInternalServerError {
		t.Fatalf("internal status=%d", internal.Code)
	}
	if strings.Contains(internal.Body.String(), "database") || strings.Contains(internal.Body.String(), "private") {
		t.Fatalf("internal error leaked: %q", internal.Body.String())
	}
}

func TestWriteSessionProtobufRejectsOversizedPayload(t *testing.T) {
	response := httptest.NewRecorder()
	writeSessionProtobuf(response, http.StatusOK, make([]byte, contact.MaxSessionWireMessageBytes+1))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got == protobufContentType {
		t.Fatal("oversized session payload was emitted as protobuf")
	}
}

func minimalSessionPublishRequest(t *testing.T) []byte {
	t.Helper()
	bundle := contact.SessionBootstrapBundle{
		IdentityID:               bytes.Repeat([]byte{1}, contact.IdentityIDBytes),
		AccountGeneration:        1,
		PublicationRevision:      1,
		OlmEd25519IdentityKey:    bytes.Repeat([]byte{2}, contact.OlmPublicKeyBytes),
		OlmCurve25519IdentityKey: bytes.Repeat([]byte{3}, contact.OlmPublicKeyBytes),
		OneTimePreKeys: []contact.SessionOneTimePreKey{
			{ID: 1, PublicKey: bytes.Repeat([]byte{4}, contact.OlmPublicKeyBytes)},
		},
		BindingSignature: []byte{0x30, 1, 1},
	}
	encodedBundle, err := contact.EncodeSessionBootstrapBundle(bundle)
	if err != nil {
		t.Fatalf("EncodeSessionBootstrapBundle: %v", err)
	}
	var body []byte
	body = protowire.AppendTag(body, 1, protowire.VarintType)
	body = protowire.AppendVarint(body, uint64(contact.SessionProtocolVersion))
	body = protowire.AppendTag(body, 2, protowire.BytesType)
	body = protowire.AppendBytes(body, encodedBundle)
	return body
}
