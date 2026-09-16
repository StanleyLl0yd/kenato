package messaging

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	m4EnvelopeVectorHex = "0801122022222222222222222222222222222222222222222222222222222222222222221a103333333333333333333333333333333322040102030428bca8d6b90732201111111111111111111111111111111111111111111111111111111111111111"
	m4ClientSendVectorHex = "08011a640801122022222222222222222222222222222222222222222222222222222222222222221a103333333333333333333333333333333322040102030428bca8d6b90732201111111111111111111111111111111111111111111111111111111111111111"
	m4ServerDeliveryVectorHex = "080122640801122022222222222222222222222222222222222222222222222222222222222222221a103333333333333333333333333333333322040102030428bca8d6b90732201111111111111111111111111111111111111111111111111111111111111111"
)

func TestM4ServerVisibleWireVectors(t *testing.T) {
	envelope := Envelope{
		ProtocolVersion:      ProtocolVersion,
		SenderIdentityID:     bytes.Repeat([]byte{0x11}, IdentityIDBytes),
		RecipientIdentityID:  bytes.Repeat([]byte{0x22}, IdentityIDBytes),
		MessageID:            bytes.Repeat([]byte{0x33}, MessageIDBytes),
		Ciphertext:           []byte{0x01, 0x02, 0x03, 0x04},
		ExpiresAtUnixSeconds: 2_000_000_060,
	}

	encodedEnvelope, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	assertM4Vector(t, "envelope", encodedEnvelope, m4EnvelopeVectorHex)

	clientFrame, err := EncodeClientFrame(ClientFrame{
		ProtocolVersion: ProtocolVersion,
		Send:            &envelope,
	})
	if err != nil {
		t.Fatalf("EncodeClientFrame: %v", err)
	}
	assertM4Vector(t, "client send", clientFrame, m4ClientSendVectorHex)

	serverFrame, err := EncodeServerFrame(ServerFrame{
		ProtocolVersion: ProtocolVersion,
		Delivery:        &envelope,
	})
	if err != nil {
		t.Fatalf("EncodeServerFrame: %v", err)
	}
	assertM4Vector(t, "server delivery", serverFrame, m4ServerDeliveryVectorHex)

	decodedClient, err := DecodeClientFrame(mustM4Hex(t, m4ClientSendVectorHex))
	if err != nil || decodedClient.Send == nil {
		t.Fatalf("DecodeClientFrame vector: frame=%#v err=%v", decodedClient, err)
	}
	decodedServer, err := DecodeServerFrame(mustM4Hex(t, m4ServerDeliveryVectorHex))
	if err != nil || decodedServer.Delivery == nil {
		t.Fatalf("DecodeServerFrame vector: frame=%#v err=%v", decodedServer, err)
	}
	if !bytes.Equal(decodedClient.Send.SenderIdentityID, envelope.SenderIdentityID) ||
		!bytes.Equal(decodedServer.Delivery.RecipientIdentityID, envelope.RecipientIdentityID) ||
		!bytes.Equal(decodedClient.Send.MessageID, envelope.MessageID) {
		t.Fatal("shared M4 wire vector decoded with mismatched routing metadata")
	}
}

func assertM4Vector(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	want := mustM4Hex(t, wantHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s vector mismatch\n got: %x\nwant: %x", name, got, want)
	}
}

func mustM4Hex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode M4 vector hex: %v", err)
	}
	return decoded
}
