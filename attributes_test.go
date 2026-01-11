package eapaka

import "testing"

func TestAtKdfInput_Empty(t *testing.T) {
	attr := &AtKdfInput{NetworkName: ""}
	if _, err := attr.Marshal(); err == nil {
		t.Fatal("expected error for empty AT_KDF_INPUT network name")
	}

	if err := attr.Unmarshal([]byte{0x00, 0x00}); err == nil {
		t.Fatal("expected error for empty AT_KDF_INPUT network name in unmarshal")
	}
}
