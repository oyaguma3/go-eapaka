package eapaka

import "testing"

func TestValidateKdfOffer(t *testing.T) {
	if err := ValidateKdfOffer(nil); err == nil {
		t.Fatal("expected error for empty offer")
	}
	if err := ValidateKdfOffer([]uint16{KDFAKAPrimeWithCKIK, KDFAKAPrimeWithCKIK}); err == nil {
		t.Fatal("expected error for duplicate offer values")
	}
	if err := ValidateKdfOffer([]uint16{KDFReserved}); err == nil {
		t.Fatal("expected error for reserved offer value")
	}
	if err := ValidateKdfOffer([]uint16{KDFAKAPrimeWithCKIK}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKdfResponse(t *testing.T) {
	offer := []uint16{KDFAKAPrimeWithCKIK, 2}
	if _, err := ValidateKdfResponse(offer, []uint16{2}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := ValidateKdfResponse(offer, []uint16{KDFAKAPrimeWithCKIK}); err == nil {
		t.Fatal("expected error for preferred offer response")
	}
	if _, err := ValidateKdfResponse(offer, []uint16{3}); err == nil {
		t.Fatal("expected error for unoffered response")
	}
	if _, err := ValidateKdfResponse(offer, []uint16{2, 1}); err == nil {
		t.Fatal("expected error for multi-value response")
	}
}

func TestBuildKdfReofferAttributes(t *testing.T) {
	offer := []uint16{KDFAKAPrimeWithCKIK, 2}
	attrs, err := BuildKdfReofferAttributes(offer, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	values := KdfValuesFromAttributes(attrs)
	want := []uint16{2, KDFAKAPrimeWithCKIK, 2}
	if len(values) != len(want) {
		t.Fatalf("unexpected reoffer length: got %d want %d", len(values), len(want))
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("unexpected reoffer value at %d: got %d want %d", i, values[i], want[i])
		}
	}
	if err := ValidateKdfReoffer(offer, values, 2); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
}
