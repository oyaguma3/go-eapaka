package eapaka

import (
	"errors"
	"strings"
)

// Is5GNetworkName reports whether the AT_KDF_INPUT Network Name uses the 5G prefix.
func Is5GNetworkName(networkName string) bool {
	return strings.HasPrefix(networkName, "5G:")
}

// Requires5GIdentityForKdf reports whether 5G identity handling applies for key derivation.
func Requires5GIdentityForKdf(networkName string, kdfValue uint16, isFastReauth bool) bool {
	return Is5GNetworkName(networkName) && kdfValue == KDFAKAPrimeWithCKIK && !isFastReauth
}

// ValidateKdfIdentity checks basic 5G identity requirements for key derivation.
// RFC 9048 Section 5.3.1 notes that "0" and "6" prefixes are not used in 5G.
func ValidateKdfIdentity(networkName string, kdfValue uint16, identity string, isFastReauth bool) error {
	if !Requires5GIdentityForKdf(networkName, kdfValue, isFastReauth) {
		return nil
	}
	if identity == "" {
		return errors.New("5G key derivation identity must be non-empty")
	}
	if strings.HasPrefix(identity, "0") || strings.HasPrefix(identity, "6") {
		return errors.New("5G key derivation identity must not use 0 or 6 prefix")
	}
	return nil
}
