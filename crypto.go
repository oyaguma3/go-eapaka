package eapaka

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
)

// CalculateAndSetMac calculates the MAC for the packet and updates the AT_MAC attribute.
// It requires the K_aut key.
func (p *Packet) CalculateAndSetMac(kAut []byte) error {
	// 1. Find AT_MAC and zero it out
	var macAttr *AtMac
	found := false
	for i := range p.Attributes {
		if m, ok := p.Attributes[i].(*AtMac); ok {
			macAttr = m
			found = true
			break
		}
	}

	if !found {
		return errors.New("AT_MAC attribute not found")
	}

	// Save original MAC just in case (though we are overwriting it)
	// We need to zero it out for calculation
	originalMac := make([]byte, 16)
	if len(macAttr.MAC) == 16 {
		copy(originalMac, macAttr.MAC)
	}
	macAttr.MAC = make([]byte, 16) // Zeroed

	// 2. Marshal packet
	data, err := p.Marshal()
	if err != nil {
		// Restore?
		return err
	}

	// 3. Calculate MAC
	mac, err := p.calculateMac(kAut, data)
	if err != nil {
		return err
	}

	// 4. Set MAC
	copy(macAttr.MAC, mac)
	return nil
}

// VerifyMac verifies the MAC in the packet against the provided K_aut.
func (p *Packet) VerifyMac(kAut []byte) (bool, error) {
	// 1. Find AT_MAC
	var macAttr *AtMac
	found := false
	for i := range p.Attributes {
		if m, ok := p.Attributes[i].(*AtMac); ok {
			macAttr = m
			found = true
			break
		}
	}

	if !found {
		return false, errors.New("AT_MAC attribute not found")
	}

	receivedMac := make([]byte, 16)
	copy(receivedMac, macAttr.MAC)

	// 2. Zero out AT_MAC for calculation
	macAttr.MAC = make([]byte, 16)

	// 3. Marshal
	data, err := p.Marshal()
	if err != nil {
		// Restore
		copy(macAttr.MAC, receivedMac)
		return false, err
	}

	// 4. Calculate expected MAC
	expectedMac, err := p.calculateMac(kAut, data)
	if err != nil {
		copy(macAttr.MAC, receivedMac)
		return false, err
	}

	// 5. Restore AT_MAC
	copy(macAttr.MAC, receivedMac)

	// 6. Compare
	return subtle.ConstantTimeCompare(receivedMac, expectedMac) == 1, nil
}

func (p *Packet) calculateMac(kAut []byte, data []byte) ([]byte, error) {
	var h hash.Hash

	switch p.Type {
	case TypeAKA:
		h = hmac.New(sha1.New, kAut)
	case TypeAKAPrime:
		h = hmac.New(sha256.New, kAut)
	default:
		return nil, errors.New("unsupported EAP type for MAC calculation")
	}

	h.Write(data)
	fullMac := h.Sum(nil)

	// EAP-AKA and EAP-AKA' use the first 16 bytes of the HMAC output
	if len(fullMac) < 16 {
		return nil, errors.New("MAC calculation error")
	}
	return fullMac[:16], nil
}
