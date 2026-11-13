package eapaka

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
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
//
// The MAC is calculated over the packet re-marshaled from the parsed
// attributes, in which reserved fields are zero. If the sender set reserved
// fields to non-zero values, a valid MAC does not match; use VerifyMacRaw to
// verify the MAC over the bytes as received.
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

// VerifyMacRaw verifies AT_MAC of an EAP-AKA/AKA' packet over its bytes as
// received, instead of over a packet re-marshaled from parsed attributes as
// Packet.VerifyMac does. Reserved fields and padding bytes are covered as
// transmitted, so non-zero reserved fields do not make a valid MAC mismatch;
// check such fields separately if needed.
//
// data is the EAP packet; bytes after the length given in its EAP header are
// ignored. extra is the message-specific data, as for
// Packet.VerifyMacWithExtra (NONCE_S for EAP-Response/AKA-Reauthentication,
// nil otherwise). The MAC is HMAC-SHA1-128 for EAP-AKA and HMAC-SHA-256-128
// for EAP-AKA', chosen by the Type field, and the MACs are compared in
// constant time. AT_BIDDING in EAP-AKA' packets is not rejected.
//
// RFC 4187 Section 10.15 sets the whole value field of AT_MAC (Reserved and
// MAC) to zero when calculating the MAC, whereas hostap zeroes only the MAC and
// keeps Reserved as transmitted. The two differ only when the Reserved field
// of AT_MAC is non-zero, in which case VerifyMacRaw accepts a MAC calculated
// either way.
func VerifyMacRaw(data, kAut, extra []byte) (bool, error) {
	pkt, typ, valOff, err := locateRawMac(data)
	if err != nil {
		return false, err
	}
	received := pkt[valOff+2 : valOff+rawMacValueLen]

	expected, err := rawMac(typ, kAut, pkt, valOff, true, extra)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(received, expected) == 1 {
		return true, nil
	}
	// AT_MAC の Reserved が 0 以外のときだけ、hostap と同じ計算（MAC 部分だけを 0 にする）でも確かめる
	if pkt[valOff] == 0 && pkt[valOff+1] == 0 {
		return false, nil
	}
	expected, err = rawMac(typ, kAut, pkt, valOff, false, extra)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(received, expected) == 1, nil
}

// CalculateAndSetMacRaw calculates the MAC over the EAP-AKA/AKA' packet data
// as it is, followed by extra, and writes it into the AT_MAC attribute of data
// in place. Unlike Packet.CalculateAndSetMac, it does not re-marshal the
// packet, so reserved fields keep the values in data (for example, to test how
// the other side handles non-zero reserved fields).
//
// The MAC is calculated with the whole value field of AT_MAC set to zero
// (RFC 4187 Section 10.15); the Reserved field of AT_MAC in data is left as
// it is. data is not modified if an error is returned. See VerifyMacRaw for
// data and extra.
func CalculateAndSetMacRaw(data, kAut, extra []byte) error {
	pkt, typ, valOff, err := locateRawMac(data)
	if err != nil {
		return err
	}
	mac, err := rawMac(typ, kAut, pkt, valOff, true, extra)
	if err != nil {
		return err
	}
	copy(pkt[valOff+2:valOff+rawMacValueLen], mac)
	return nil
}

// rawMacValueLen は AT_MAC の値フィールド（Reserved 2 バイト＋MAC 16 バイト）の長さ。
const rawMacValueLen = 2 + 16

// locateRawMac は data を EAP-AKA/AKA' の Request または Response として調べ、
// EAP ヘッダの Length までのパケット、Type、AT_MAC の値フィールドの先頭の位置を返す。
func locateRawMac(data []byte) (pkt []byte, typ uint8, valOff int, err error) {
	if len(data) < 4 {
		return nil, 0, 0, wrapErrorf(ErrMalformedPacket, "packet too short")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 4 {
		return nil, 0, 0, wrapErrorf(ErrMalformedPacket, "packet length too small")
	}
	if length > len(data) {
		return nil, 0, 0, wrapErrorf(ErrMalformedPacket, "packet length mismatch")
	}
	pkt = data[:length]
	if pkt[0] != CodeRequest && pkt[0] != CodeResponse {
		return nil, 0, 0, errors.New("AT_MAC is used only in EAP-Request and EAP-Response packets")
	}
	if len(pkt) < 5 {
		return nil, 0, 0, wrapErrorf(ErrMalformedPacket, "missing EAP type")
	}
	typ = pkt[4]
	if typ != TypeAKA && typ != TypeAKAPrime {
		return nil, 0, 0, errors.New("unsupported EAP type for MAC calculation")
	}
	if len(pkt) < 8 {
		return nil, 0, 0, wrapErrorf(ErrMalformedPacket, "invalid EAP-AKA header")
	}

	// 属性を順にたどって AT_MAC を探す（属性の中身は解析しない）
	valOff = -1
	for off := 8; off < len(pkt); {
		if off+2 > len(pkt) {
			return nil, 0, 0, wrapErrorf(ErrMalformedAttribute, "attribute header truncated")
		}
		attrType := AttributeType(pkt[off])
		attrLen := int(pkt[off+1]) * 4
		if attrLen == 0 {
			return nil, 0, 0, wrapErrorf(ErrMalformedAttribute, "attribute length zero")
		}
		if off+attrLen > len(pkt) {
			return nil, 0, 0, wrapErrorf(ErrMalformedAttribute, "attribute %d length overflow", attrType)
		}
		if attrType == AT_MAC {
			if attrLen != 2+rawMacValueLen {
				return nil, 0, 0, &AttributeError{Type: AT_MAC, Err: errors.New("invalid AT_MAC length")}
			}
			if valOff >= 0 {
				return nil, 0, 0, wrapErrorf(ErrMalformedPacket, "multiple AT_MAC attributes")
			}
			valOff = off + 2
		}
		off += attrLen
	}
	if valOff < 0 {
		return nil, 0, 0, ErrMacNotFound
	}
	return pkt, typ, valOff, nil
}

// rawMac は pkt のコピーの AT_MAC を 0 にして MAC を計算する。zeroReserved が true なら
// 値フィールド全体（RFC 4187 §10.15）、false なら MAC 部分だけ（hostap と同じ）を 0 にする。
func rawMac(typ uint8, kAut, pkt []byte, valOff int, zeroReserved bool, extra []byte) ([]byte, error) {
	tmp := bytes.Clone(pkt)
	start := valOff + 2
	if zeroReserved {
		start = valOff
	}
	clear(tmp[start : valOff+rawMacValueLen])
	return (&Packet{Type: typ}).calculateMac(kAut, tmp, extra)
}
