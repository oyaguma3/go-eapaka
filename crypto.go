package eapaka

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
)

func (p *Packet) findMacAttr() (*AtMac, error) {
	for i := range p.Attributes {
		if m, ok := p.Attributes[i].(*AtMac); ok {
			return m, nil
		}
	}
	return nil, errors.New("AT_MAC attribute not found")
}

func zeroMac(macAttr *AtMac) {
	macAttr.MAC = make([]byte, 16)
}

func snapshotMac(macAttr *AtMac) []byte {
	receivedMac := make([]byte, 16)
	copy(receivedMac, macAttr.MAC)
	return receivedMac
}

// CalculateAndSetMac calculates the MAC for the packet and updates the AT_MAC attribute.
// It requires the K_aut key.
func (p *Packet) CalculateAndSetMac(kAut []byte) error {
	// 1. Find AT_MAC and zero it out
	macAttr, err := p.findMacAttr()
	if err != nil {
		return err
	}
	zeroMac(macAttr)

	// 2. Marshal packet
	data, err := p.Marshal()
	if err != nil {
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
	macAttr, err := p.findMacAttr()
	if err != nil {
		return false, err
	}
	receivedMac := snapshotMac(macAttr)

	// 2. Zero out AT_MAC for calculation
	zeroMac(macAttr)

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
