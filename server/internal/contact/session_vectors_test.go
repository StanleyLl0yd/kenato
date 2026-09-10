package contact

import (
	"encoding/hex"
	"testing"
)

func TestSessionCanonicalPayloadVectors(t *testing.T) {
	creator := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	redeemer := mustHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	token := mustHex(t, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	bundle := SessionBootstrapBundle{
		IdentityID: creator,
		AccountGeneration: 2,
		PublicationRevision: 3,
		OlmEd25519IdentityKey: mustHex(t, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"),
		OlmCurve25519IdentityKey: mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
		OneTimePreKeys: []SessionOneTimePreKey{
			{ID: 7, PublicKey: mustHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")},
			{ID: 8, PublicKey: mustHex(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")},
		},
	}
	bootstrap, err := SessionBootstrapPayload(bundle)
	if err != nil { t.Fatal(err) }
	assertHex(t, bootstrap, "4b454e41544f2d53455353494f4e2d424f4f5453545241502d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000020000000000000003606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f000000020000000000000007a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000008c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")

	reserve, err := SessionReservePayload(creator, redeemer, token)
	if err != nil { t.Fatal(err) }
	assertHex(t, reserve, "4b454e41544f2d53455353494f4e2d524553455256452d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")

	claim, err := SessionClaimPayload(creator, token)
	if err != nil { t.Fatal(err) }
	assertHex(t, claim, "4b454e41544f2d53455353494f4e2d434c41494d2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
}

func TestSessionVectorHexHelpersRemainCanonical(t *testing.T) {
	if _, err := hex.DecodeString("00ff"); err != nil { t.Fatal(err) }
}
