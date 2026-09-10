package contact

import "errors"

const (
	ProtocolVersion   uint32 = 1
	IdentityIDBytes          = 32
	InviteTokenBytes         = 32
	MaxPublicKeyBytes        = 2 << 10
	MaxSignatureBytes        = 2 << 10
	MaxOneTimePreKeys        = 100
)

var (
	ErrInvalidBundle = errors.New("invalid public identity bundle")
	ErrInvalidInvite = errors.New("invalid invite descriptor")
)

type SignedPreKey struct {
	ID                   uint32
	PublicKey            []byte
	Signature            []byte
	CreatedAtUnixSeconds int64
}

type OneTimePreKey struct {
	ID                   uint32
	PublicKey            []byte
	CreatedAtUnixSeconds int64
}

type PublicIdentityBundle struct {
	IdentityID           []byte
	IdentityPublicKey    []byte
	PublicationRevision  uint64
	SignedPreKey         SignedPreKey
	OneTimePreKeys       []OneTimePreKey
	PublicationSignature []byte
}

type InviteDescriptor struct {
	CreatorIdentityID []byte
	InviteToken       []byte
	InviteSignature   []byte
}
