package contact

import "context"

// VerifyIdentitySignature verifies a bounded protocol payload against an
// already-published Kenato identity. Callers decide the protocol-specific
// payload framing; identity-key parsing and identity-id binding stay centralized
// in the contact package.
func (s *Service) VerifyIdentitySignature(ctx context.Context, identityID, payload, signature []byte) error {
	if s == nil || s.store == nil || len(payload) == 0 || !validSignature(signature) {
		return ErrInvalidBundle
	}
	bundle, err := s.loadIdentity(ctx, identityID)
	if err != nil {
		return err
	}
	identityKey, err := signerKey(bundle.IdentityID, bundle.IdentityPublicKey)
	if err != nil {
		return ErrInvalidBundle
	}
	if !verifyP256Signature(identityKey, payload, signature) {
		return ErrInvalidBundle
	}
	return nil
}
