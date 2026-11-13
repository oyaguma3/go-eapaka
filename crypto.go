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
	return nil, ErrMacNotFound
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
//
// It is equivalent to CalculateAndSetMacWithExtra with no extra data.
func (p *Packet) CalculateAndSetMac(kAut []byte) error {
	return p.CalculateAndSetMacWithExtra(kAut, nil)
}

// CalculateAndSetMacWithExtra calculates the MAC over the packet followed by
// extra, the message-specific data (RFC 4187 Section 10.15), and updates the
// AT_MAC attribute. It requires the K_aut key. The MAC is HMAC-SHA1-128 for
// EAP-AKA and HMAC-SHA-256-128 for EAP-AKA'.
//
// Among EAP-AKA/AKA' messages, only EAP-Response/AKA-Reauthentication has
// message-specific data: the 16-byte NONCE_S from the server's AT_NONCE_S
// (RFC 4187 Section 9.8). Other messages use no extra data (nil).
//
// Unlike Marshal, the MAC methods accept AT_BIDDING in EAP-AKA' packets, so
// the MAC of such a packet read with ParseWithOptions (see
// ParseOptions.AllowBiddingInAKAPrime) can be calculated and verified.
func (p *Packet) CalculateAndSetMacWithExtra(kAut, extra []byte) error {
	// 1. Find AT_MAC and zero it out
	macAttr, err := p.findMacAttr()
	if err != nil {
		return err
	}
	zeroMac(macAttr)

	// 2. Marshal packet
	// ParseWithOptions で読み込んだ、EAP-AKA' の AT_BIDDING を含むパケットも扱う
	data, err := p.marshal(false)
	if err != nil {
		return err
	}

	// 3. Calculate MAC
	mac, err := p.calculateMac(kAut, data, extra)
	if err != nil {
		return err
	}

	// 4. Set MAC
	copy(macAttr.MAC, mac)
	return nil
}

// VerifyMac verifies the MAC in the packet against the provided K_aut.
//
// It is equivalent to VerifyMacWithExtra with no extra data.
func (p *Packet) VerifyMac(kAut []byte) (bool, error) {
	return p.VerifyMacWithExtra(kAut, nil)
}

// VerifyMacWithExtra verifies the MAC in the packet against the provided K_aut,
// computing the expected MAC over the packet followed by extra, the
// message-specific data (see CalculateAndSetMacWithExtra). The MACs are compared
// in constant time, and the AT_MAC attribute is left unchanged.
//
// A server verifying EAP-Response/AKA-Reauthentication passes the NONCE_S it
// sent in AT_NONCE_S as extra (RFC 4187 Section 9.8). Like
// CalculateAndSetMacWithExtra, it accepts AT_BIDDING in EAP-AKA' packets.
func (p *Packet) VerifyMacWithExtra(kAut, extra []byte) (bool, error) {
	// 1. Find AT_MAC
	macAttr, err := p.findMacAttr()
	if err != nil {
		return false, err
	}
	receivedMac := snapshotMac(macAttr)

	// 2. Zero out AT_MAC for calculation
	zeroMac(macAttr)

	// 3. Marshal
	// ParseWithOptions で読み込んだ、EAP-AKA' の AT_BIDDING を含むパケットも扱う
	data, err := p.marshal(false)
	if err != nil {
		// Restore
		copy(macAttr.MAC, receivedMac)
		return false, err
	}

	// 4. Calculate expected MAC
	expectedMac, err := p.calculateMac(kAut, data, extra)
	if err != nil {
		copy(macAttr.MAC, receivedMac)
		return false, err
	}

	// 5. Restore AT_MAC
	copy(macAttr.MAC, receivedMac)

	// 6. Compare
	return subtle.ConstantTimeCompare(receivedMac, expectedMac) == 1, nil
}

// calculateMac は data（AT_MAC をゼロにした EAP パケット）に extra（メッセージ固有の
// データ。なければ nil）をつないだものに対して MAC を計算する。
func (p *Packet) calculateMac(kAut, data, extra []byte) ([]byte, error) {
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
	h.Write(extra)
	fullMac := h.Sum(nil)

	// EAP-AKA and EAP-AKA' use the first 16 bytes of the HMAC output
	if len(fullMac) < 16 {
		return nil, errors.New("MAC calculation error")
	}
	return fullMac[:16], nil
}
