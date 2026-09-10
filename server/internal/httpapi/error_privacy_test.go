package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/StanleyLl0yd/kenato/server/internal/contact"
)

func TestContactErrorDoesNotRevealIdentityExistence(t *testing.T) {
	invalid := httptest.NewRecorder()
	writeContactError(invalid, contact.ErrInvalidInvite)

	missingIdentity := httptest.NewRecorder()
	writeContactError(missingIdentity, contact.ErrIdentityNotFound)

	if missingIdentity.Code != invalid.Code {
		t.Fatalf("identity existence leaked by status: missing=%d invalid=%d", missingIdentity.Code, invalid.Code)
	}
	if missingIdentity.Body.String() != invalid.Body.String() {
		t.Fatalf("identity existence leaked by response body")
	}
}
