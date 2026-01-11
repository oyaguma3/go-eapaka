package eapaka

import "testing"

func TestIs5GNetworkName(t *testing.T) {
	if !Is5GNetworkName("5G:example") {
		t.Fatal("expected 5G prefix to be detected")
	}
	if Is5GNetworkName("WLAN") {
		t.Fatal("unexpected 5G prefix detection")
	}
}

func TestValidateKdfIdentity(t *testing.T) {
	err := ValidateKdfIdentity("5G:example", KDFAKAPrimeWithCKIK, "0123", false)
	if err == nil {
		t.Fatal("expected error for 5G identity with 0 prefix")
	}
	err = ValidateKdfIdentity("5G:example", KDFAKAPrimeWithCKIK, "6123", false)
	if err == nil {
		t.Fatal("expected error for 5G identity with 6 prefix")
	}
	err = ValidateKdfIdentity("5G:example", KDFAKAPrimeWithCKIK, "suci-123", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err = ValidateKdfIdentity("WLAN", KDFAKAPrimeWithCKIK, "0user", false)
	if err != nil {
		t.Fatalf("unexpected error for non-5G: %v", err)
	}
}
