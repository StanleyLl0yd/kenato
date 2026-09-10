package contact

import "testing"

func TestValidatePublicIdentityBundleRejectsReusedSignedPreKeyID(t *testing.T) {
	bundle, _ := newSignedBundle(t, 1)
	bundle.OneTimePreKeys[0].ID = bundle.SignedPreKey.ID

	if err := ValidatePublicIdentityBundle(bundle); err == nil {
		t.Fatal("signed-prekey id reused by one-time prekey was accepted")
	}
}
