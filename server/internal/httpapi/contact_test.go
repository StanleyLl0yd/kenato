package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
	"google.golang.org/protobuf/encoding/protowire"
)

type fakeContactService struct {
	publishCalls       int
	publishErr         error
	publishHasDeadline bool
}

func (f *fakeContactService) PublishIdentity(ctx context.Context, _ contact.PublishIdentityRequest) (uint64, error) {
	f.publishCalls++
	_, f.publishHasDeadline = ctx.Deadline()
	return 7, f.publishErr
}

func (*fakeContactService) CreateInvite(context.Context, contact.CreateInviteRequest) (int64, error) {
	return 0, errors.New("unexpected CreateInvite call")
}

func (*fakeContactService) RedeemInvite(context.Context, contact.RedeemInviteRequest) (contact.PublicIdentityBundle, int64, error) {
	return contact.PublicIdentityBundle{}, 0, errors.New("unexpected RedeemInvite call")
}

func (*fakeContactService) ClaimInvite(context.Context, contact.ClaimInviteRequest) (contact.PublicIdentityBundle, []byte, int64, error) {
	return contact.PublicIdentityBundle{}, nil, 0, errors.New("unexpected ClaimInvite call")
}

func TestPublishIdentityEndpointUsesProtobuf(t *testing.T) {
	service := &fakeContactService{}
	body := minimalPublishRequest(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/identity/publish", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()

	NewHandler(service).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if service.publishCalls != 1 {
		t.Fatalf("publish calls=%d", service.publishCalls)
	}
	if !service.publishHasDeadline {
		t.Fatal("contact service call did not receive a deadline")
	}
	if got := response.Header().Get("Content-Type"); got != protobufContentType {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
}

func TestContactEndpointRejectsWrongContentTypeBeforeService(t *testing.T) {
	service := &fakeContactService{}
	request := httptest.NewRequest(http.MethodPost, "/v1/identity/publish", strings.NewReader("x"))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(service).ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d", response.Code)
	}
	if service.publishCalls != 0 {
		t.Fatalf("publish calls=%d", service.publishCalls)
	}
}

func TestContactEndpointRejectsMalformedWireBeforeService(t *testing.T) {
	service := &fakeContactService{}
	request := httptest.NewRequest(http.MethodPost, "/v1/identity/publish", strings.NewReader("\x80"))
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()

	NewHandler(service).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
	if service.publishCalls != 0 {
		t.Fatalf("publish calls=%d", service.publishCalls)
	}
}

func TestContactEndpointDoesNotExposeInternalErrors(t *testing.T) {
	service := &fakeContactService{publishErr: errors.New("database path and private diagnostics")}
	body := minimalPublishRequest(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/identity/publish", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()

	NewHandler(service).ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", response.Code)
	}
	if strings.Contains(response.Body.String(), "database") || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("internal error leaked: %q", response.Body.String())
	}
}

func TestNoPublicIdentityLookupRoute(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/identity/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil)

	NewHandler(&fakeContactService{}).ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", response.Code)
	}
}

func TestWriteProtobufRejectsOversizedPayload(t *testing.T) {
	response := httptest.NewRecorder()
	writeProtobuf(response, http.StatusOK, make([]byte, contact.MaxWireMessageBytes+1))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got == protobufContentType {
		t.Fatalf("oversized payload was emitted as protobuf")
	}
}

func TestCryptoGateBoundsConcurrencyAndWindow(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	gate := newCryptoGate(func() time.Time { return now })
	releases := make([]func(), 0, maxCryptoConcurrent)
	for i := 0; i < maxCryptoConcurrent; i++ {
		release, ok := gate.acquire()
		if !ok {
			t.Fatalf("acquire %d rejected", i)
		}
		releases = append(releases, release)
	}
	if _, ok := gate.acquire(); ok {
		t.Fatal("concurrency limit was not enforced")
	}
	for _, release := range releases {
		release()
	}

	gate.mu.Lock()
	gate.operations = maxCryptoOperations
	gate.mu.Unlock()
	if _, ok := gate.acquire(); ok {
		t.Fatal("operation-rate limit was not enforced")
	}
	now = now.Add(cryptoRateWindowDuration)
	release, ok := gate.acquire()
	if !ok {
		t.Fatal("gate did not reset after the rate window")
	}
	release()
}

func minimalPublishRequest(t *testing.T) []byte {
	t.Helper()
	bundle := contact.PublicIdentityBundle{
		IdentityID:          make([]byte, contact.IdentityIDBytes),
		IdentityPublicKey:   []byte{1},
		PublicationRevision: 1,
		SignedPreKey: contact.SignedPreKey{
			ID:                   1,
			PublicKey:            []byte{2},
			Signature:            []byte{3},
			CreatedAtUnixSeconds: 1,
		},
		PublicationSignature: []byte{4},
	}
	encodedBundle, err := contact.EncodePublicIdentityBundle(bundle)
	if err != nil {
		t.Fatalf("EncodePublicIdentityBundle: %v", err)
	}
	var body []byte
	body = protowire.AppendTag(body, 1, protowire.VarintType)
	body = protowire.AppendVarint(body, uint64(contact.ProtocolVersion))
	body = protowire.AppendTag(body, 2, protowire.BytesType)
	body = protowire.AppendBytes(body, encodedBundle)
	return body
}
