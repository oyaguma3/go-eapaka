package eapaka

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

// Helper to decode hex for readability
func h(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestDeriveKeysAKA(t *testing.T) {
	// Dummy Inputs
	identity := "0123456789012345@wlan.mnc001.mcc001.3gppnetwork.org"
	ck := make([]byte, 16) // all zeros for test
	ik := make([]byte, 16)

	keys := DeriveKeysAKA(identity, ck, ik)

	if len(keys.K_encr) != 16 {
		t.Errorf("K_encr length mismatch: got %d, want 16", len(keys.K_encr))
	}
	if len(keys.K_aut) != 16 {
		t.Errorf("K_aut length mismatch: got %d, want 16", len(keys.K_aut))
	}
	if len(keys.MSK) != 64 {
		t.Errorf("MSK length mismatch: got %d, want 64", len(keys.MSK))
	}
	if len(keys.EMSK) != 64 {
		t.Errorf("EMSK length mismatch: got %d, want 64", len(keys.EMSK))
	}
}

func TestDeriveKeysAKAPrime_RFC5448_Case1(t *testing.T) {
	// RFC 9048 Appendix D Case 1
	identity := "0555444333222111"
	netName := "WLAN"
	ik := h("9744871ad32bf9bbd1dd5ce54e3e2e5a")
	ck := h("5349fbe098649f948f5d2e973a81c00f")
	autn := h("bb52e91c747ac3ab2a5c23d15ee351d5")

	// Expected Derived Keys
	expCkPrime := h("0093962d0dd84aa5684b045c9edffa04")
	expIkPrime := h("ccfc230ca74fcc96c0a5d61164f5a76c")
	expKEncr := h("766fa0a6c317174b812d52fbcd11a179")
	expKAut := h("0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea")
	expKRe := h("cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a")
	expMSK := h("67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a")
	expEMSK := h("f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb")

	// 1. Derive CK', IK'
	ckPrime, ikPrime, err := DeriveCKPrimeIKPrime(ck, ik, netName, autn)
	if err != nil {
		t.Fatalf("DeriveCKPrimeIKPrime failed: %v", err)
	}

	if !bytes.Equal(ckPrime, expCkPrime) {
		t.Errorf("CK' mismatch\nGot: %x\nWant: %x", ckPrime, expCkPrime)
	}
	if !bytes.Equal(ikPrime, expIkPrime) {
		t.Errorf("IK' mismatch\nGot: %x\nWant: %x", ikPrime, expIkPrime)
	}

	// 2. Derive Keys
	keys := DeriveKeysAKAPrime(identity, ckPrime, ikPrime)

	if !bytes.Equal(keys.K_encr, expKEncr) {
		t.Errorf("K_encr mismatch\nGot: %x\nWant: %x", keys.K_encr, expKEncr)
	}
	if !bytes.Equal(keys.K_aut, expKAut) {
		t.Errorf("K_aut mismatch\nGot: %x\nWant: %x", keys.K_aut, expKAut)
	}
	if !bytes.Equal(keys.K_re, expKRe) {
		t.Errorf("K_re mismatch\nGot: %x\nWant: %x", keys.K_re, expKRe)
	}
	if !bytes.Equal(keys.MSK, expMSK) {
		t.Errorf("MSK mismatch\nGot: %x\nWant: %x", keys.MSK, expMSK)
	}
	if !bytes.Equal(keys.EMSK, expEMSK) {
		t.Errorf("EMSK mismatch\nGot: %x\nWant: %x", keys.EMSK, expEMSK)
	}
}

/*
func TestDeriveKeysAKAPrime_RFC5448_Case2(t *testing.T) {
	// RFC 5448 Appendix C Case 2
	// ... (Commented out until Case 1 is resolved)
}
*/

func TestEncryptMPPEKey(t *testing.T) {
	// Case 1: Key length 32
	// P = Length(1) + Key(32) + Padding(?)
	// P len must be multiple of 16. 1+32=33. Next multiple is 48.
	// Padding = 15 bytes. Total P = 48 bytes.
	// Result = Salt(2) + P(48) = 50 bytes.
	key32 := make([]byte, 32)
	secret := []byte("radius-secret")
	reqAuth := make([]byte, 16)

	encrypted, err := EncryptMPPEKey(key32, secret, reqAuth)
	if err != nil {
		t.Fatalf("EncryptMPPEKey failed: %v", err)
	}

	expectedLen32 := 2 + 48
	if len(encrypted) != expectedLen32 {
		t.Errorf("Encrypted length mismatch (key32): got %d, want %d", len(encrypted), expectedLen32)
	}
	if (encrypted[0] & 0x80) == 0 {
		t.Error("Salt MSB is not set")
	}

	// Case 2: Key length 7
	// P = Length(1) + Key(7) + Padding(?)
	// P len must be multiple of 16. 1+7=8. Next multiple is 16.
	// Padding = 8 bytes. Total P = 16 bytes.
	// Result = Salt(2) + P(16) = 18 bytes.
	key7 := make([]byte, 7)
	encrypted7, err := EncryptMPPEKey(key7, secret, reqAuth)
	if err != nil {
		t.Fatalf("EncryptMPPEKey (key7) failed: %v", err)
	}

	expectedLen7 := 2 + 16
	if len(encrypted7) != expectedLen7 {
		t.Errorf("Encrypted length mismatch (key7): got %d, want %d", len(encrypted7), expectedLen7)
	}
}

// Internal PRF Test (Sanity check for chaining)
func TestPrfGenAKA(t *testing.T) {
	key := []byte("key")
	seed := []byte("seed")
	// Request 40 bytes (requires 2 iterations of SHA1: 20 + 20)
	out := prfGenAKA(key, seed, 40)

	if len(out) != 40 {
		t.Errorf("Output length mismatch: %d", len(out))
	}

	// First 20 bytes should be SHA1(key|seed)
	h := sha1.New()
	h.Write(key)
	h.Write(seed)
	expected1 := h.Sum(nil)

	if !bytes.Equal(out[:20], expected1) {
		t.Error("First block of PRF-AKA failed")
	}
}
