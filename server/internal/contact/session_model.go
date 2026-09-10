package contact

import (
	"crypto/sha256"
	"errors"
)

const (
	SessionProtocolVersion       uint32 = 1
	OlmPublicKeyBytes                   = 32
	MaxSessionOneTimePreKeys            = 50
	TargetSessionOneTimePreKeys         = 32
	MaxSessionCiphertextBytes           = 96 << 10
	MaxSessionWireMessageBytes          = 128 << 10
	MaxStoredSessionBootstraps          = MaxStoredIdentities
)

const (
	OlmMessageTypePreKey uint32 = 0
	OlmMessageTypeNormal uint32 = 1
)

var (
	ErrInvalidSessionBootstrap = errors.New("invalid session bootstrap")
	ErrSessionConflict         = errors.New("session bootstrap conflict")
	ErrSessionKeyUnavailable   = errors.New("session one-time key unavailable")
	ErrSessionInitMissing      = errors.New("session initialization is missing")
	ErrSessionInitConflict     = errors.New("session initialization conflict")
)

type SessionOneTimePreKey struct {
	ID        uint64
	PublicKey []byte
}

type SessionBootstrapBundle struct {
	IdentityID               []byte
	AccountGeneration        uint64
	PublicationRevision      uint64
	OlmEd25519IdentityKey    []byte
	OlmCurve25519IdentityKey []byte
	OneTimePreKeys           []SessionOneTimePreKey
	BindingSignature         []byte
}

type SessionBootstrapPublicationRecord struct {
	Bundle        SessionBootstrapBundle
	EncodedBundle []byte
	PayloadHash   [sha256.Size]byte
}

type StoredSessionBootstrap struct {
	EncodedBundle []byte
}

type PublishSessionBootstrapRequest struct {
	ProtocolVersion uint32
	Bundle          SessionBootstrapBundle
}

type ReserveSessionBootstrapRequest struct {
	ProtocolVersion    uint32
	CreatorIdentityID  []byte
	RedeemerIdentityID []byte
	InviteToken        []byte
	ReserveSignature   []byte
}

type ReserveSessionBootstrapResult struct {
	CreatorBundle     SessionBootstrapBundle
	CreatorOneTimeKey SessionOneTimePreKey
}

type SubmitSessionInitRequest struct {
	ProtocolVersion           uint32
	CreatorIdentityID         []byte
	RedeemerIdentityID        []byte
	InviteToken               []byte
	CreatorAccountGeneration  uint64
	CreatorOneTimePreKeyID    uint64
	RedeemerAccountGeneration uint64
	OlmMessageType            uint32
	OlmMessage                []byte
	SubmitSignature           []byte
}

type ClaimSessionInitRequest struct {
	ProtocolVersion   uint32
	CreatorIdentityID []byte
	InviteToken       []byte
	ClaimSignature    []byte
}

type ClaimSessionInitResult struct {
	RedeemerIdentityBundle PublicIdentityBundle
	RedemptionSignature    []byte
	RedeemedAt             int64
	RedeemerSessionBundle  SessionBootstrapBundle
	CreatorOneTimeKey      SessionOneTimePreKey
	OlmMessageType         uint32
	OlmMessage             []byte
}

type SessionReservationRecord struct {
	TokenHash          [sha256.Size]byte
	CreatorIdentityID  []byte
	RedeemerIdentityID []byte
	ReservedAt         int64
}

type StoredSessionReservation struct {
	CreatorBundle     []byte
	CreatorOneTimeKey SessionOneTimePreKey
}

type SessionInitRecord struct {
	TokenHash                  [sha256.Size]byte
	CreatorIdentityID          []byte
	RedeemerIdentityID         []byte
	CreatorAccountGeneration   uint64
	CreatorOneTimePreKeyID     uint64
	RedeemerAccountGeneration  uint64
	OlmMessageType             uint32
	OlmMessage                 []byte
	SubmitSignature            []byte
	RedeemerSessionBundle      []byte
	SubmittedAt                int64
}

type StoredSessionClaim struct {
	RedeemerIdentityBundle []byte
	RedemptionSignature    []byte
	RedeemedAt             int64
	RedeemerSessionBundle  []byte
	CreatorOneTimeKey      SessionOneTimePreKey
	OlmMessageType         uint32
	OlmMessage             []byte
}
