package eapaka

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// ComputeCheckcode computes the checkcode for AT_CHECKCODE: a SHA-1 hash
// (20 bytes) for EAP-AKA (RFC 4187 Section 10.13) or a SHA-256 hash (32 bytes)
// for EAP-AKA' (RFC 9048 Section 3.4.3), over the EAP-Request/AKA-Identity and
// EAP-Response/AKA-Identity packets exchanged in this authentication exchange.
//
// methodType is TypeAKA or TypeAKAPrime. identityPackets are whole EAP packets,
// as they were transmitted or received, in the order they were transmitted:
// the first request, its response, the second request, and so on. They are
// hashed as-is with no delimiters. Only full round trips are included, and a
// retransmitted packet (with the same Identifier) is included only once;
// choosing the packets is up to the caller. ComputeCheckcode checks that each
// packet is an AKA-Identity packet of methodType whose EAP Length matches its
// size, and that requests and responses alternate with matching Identifiers.
//
// If no packets are given, the result is an empty checkcode, which indicates
// that no AKA-Identity messages were exchanged.
func ComputeCheckcode(methodType uint8, identityPackets ...[]byte) ([]byte, error) {
	var h hash.Hash
	switch methodType {
	case TypeAKA:
		h = sha1.New()
	case TypeAKAPrime:
		h = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported EAP type %d for AT_CHECKCODE", methodType)
	}
	if len(identityPackets) == 0 {
		return []byte{}, nil
	}
	if len(identityPackets)%2 != 0 {
		return nil, errors.New("AKA-Identity packets must be request/response pairs")
	}

	for i, pkt := range identityPackets {
		// 偶数番目は Request、奇数番目はその Response
		wantCode := CodeRequest
		if i%2 == 1 {
			wantCode = CodeResponse
		}
		if err := checkIdentityPacket(pkt, methodType, wantCode); err != nil {
			return nil, fmt.Errorf("AKA-Identity packet %d: %w", i, err)
		}
		if i%2 == 1 && pkt[1] != identityPackets[i-1][1] {
			return nil, fmt.Errorf("AKA-Identity packet %d: identifier %d does not match the request (%d)", i, pkt[1], identityPackets[i-1][1])
		}
		h.Write(pkt)
	}
	return h.Sum(nil), nil
}

// checkIdentityPacket は pkt が methodType の AKA-Identity パケット（Code が code）で、
// EAP ヘッダの Length がパケットの長さと一致することを確かめる。
func checkIdentityPacket(pkt []byte, methodType, code uint8) error {
	// EAP ヘッダ（4）＋ Type・Subtype・Reserved（4）
	if len(pkt) < 8 {
		return fmt.Errorf("too short for an EAP-AKA packet (%d bytes)", len(pkt))
	}
	if n := int(binary.BigEndian.Uint16(pkt[2:4])); n != len(pkt) {
		return fmt.Errorf("EAP length %d does not match the packet size %d", n, len(pkt))
	}
	if pkt[0] != code {
		return fmt.Errorf("code is %d, want %d", pkt[0], code)
	}
	if pkt[4] != methodType || pkt[5] != SubtypeIdentity {
		return fmt.Errorf("type/subtype is %d/%d, want %d/%d", pkt[4], pkt[5], methodType, SubtypeIdentity)
	}
	return nil
}
