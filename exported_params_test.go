package eapaka

import (
	"bytes"
	"testing"
)

func TestSessionIDAKAPrime(t *testing.T) {
	rand := make([]byte, 16)
	autn := make([]byte, 16)
	id, err := SessionIDAKAPrime(rand, autn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id) != 1+16+16 {
		t.Fatalf("unexpected session id length: %d", len(id))
	}
	if id[0] != TypeAKAPrime {
		t.Fatalf("unexpected type prefix: %d", id[0])
	}
}

func TestSessionIDAKAPrimeReauth(t *testing.T) {
	nonce := make([]byte, 16)
	mac := make([]byte, 16)
	id, err := SessionIDAKAPrimeReauth(nonce, mac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id) != 1+16+16 {
		t.Fatalf("unexpected session id length: %d", len(id))
	}
	if id[0] != TypeAKAPrime {
		t.Fatalf("unexpected type prefix: %d", id[0])
	}
}

func TestPeerIDFromAttributes(t *testing.T) {
	attrs := []Attribute{
		&AtIdentity{Identity: "user@example.com"},
	}
	if got := PeerIDFromAttributes(attrs, "fallback"); got != "user@example.com" {
		t.Fatalf("unexpected peer id: %s", got)
	}
	if got := PeerIDFromAttributes(nil, "fallback"); got != "fallback" {
		t.Fatalf("unexpected peer id fallback: %s", got)
	}
}

func TestSessionIDAKA(t *testing.T) {
	rand := h("101112131415161718191a1b1c1d1e1f")
	autn := h("202122232425262728292a2b2c2d2e2f")
	id, err := SessionIDAKA(rand, autn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// RFC 5247 Appendix A: 0x17 || RAND || AUTN
	want := h("17" + "101112131415161718191a1b1c1d1e1f" + "202122232425262728292a2b2c2d2e2f")
	if !bytes.Equal(id, want) {
		t.Fatalf("SessionIDAKA = %x, want %x", id, want)
	}

	for _, tc := range []struct {
		name       string
		rand, autn []byte
	}{
		{"short_rand", rand[:15], autn},
		{"long_autn", rand, append(bytes.Clone(autn), 0)},
		{"nil", nil, nil},
	} {
		if _, err := SessionIDAKA(tc.rand, tc.autn); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}
