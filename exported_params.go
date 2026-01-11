package eapaka

import "errors"

// SessionIDAKAPrime builds the EAP-AKA' Session-Id for full authentication.
// RFC 9048 Section 6: 0x32 || RAND || AUTN
func SessionIDAKAPrime(rand, autn []byte) ([]byte, error) {
	if len(rand) != 16 {
		return nil, errors.New("RAND must be 16 bytes")
	}
	if len(autn) != 16 {
		return nil, errors.New("AUTN must be 16 bytes")
	}
	out := make([]byte, 0, 1+16+16)
	out = append(out, TypeAKAPrime)
	out = append(out, rand...)
	out = append(out, autn...)
	return out, nil
}

// SessionIDAKAPrimeReauth builds the EAP-AKA' Session-Id for fast re-authentication.
// RFC 9048 Section 6: 0x32 || NONCE_S || MAC
func SessionIDAKAPrimeReauth(nonceS, mac []byte) ([]byte, error) {
	if len(nonceS) != 16 {
		return nil, errors.New("NONCE_S must be 16 bytes")
	}
	if len(mac) != 16 {
		return nil, errors.New("MAC must be 16 bytes")
	}
	out := make([]byte, 0, 1+16+16)
	out = append(out, TypeAKAPrime)
	out = append(out, nonceS...)
	out = append(out, mac...)
	return out, nil
}

// PeerIDFromAttributes returns the exported Peer-Id using AT_IDENTITY if present.
// RFC 9048 Section 6.
func PeerIDFromAttributes(attrs []Attribute, fallback string) string {
	for _, attr := range attrs {
		if idAttr, ok := attr.(*AtIdentity); ok {
			return idAttr.Identity
		}
	}
	return fallback
}

// ServerIDAKAPrime returns the exported Server-Id (empty string).
// RFC 9048 Section 6.
func ServerIDAKAPrime() string {
	return ""
}
