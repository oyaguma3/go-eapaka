package eapaka

import "testing"

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
