package eapaka

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Parse parses an EAP packet from a byte slice.
//
// It is equivalent to ParseWithOptions with the zero ParseOptions.
func Parse(data []byte) (*Packet, error) {
	return ParseWithOptions(data, ParseOptions{})
}

// ParseOptions relaxes checks that Parse applies. The zero value gives the
// same behavior as Parse.
type ParseOptions struct {
	// AllowBiddingInAKAPrime accepts AT_BIDDING in EAP-AKA' packets, which
	// RFC 9048 Section 4 does not allow ("This attribute is not included in
	// EAP-AKA' messages"). A tester can use it to parse such a packet from the
	// implementation under test and report the violation, instead of failing
	// to parse the packet.
	//
	// Marshal still rejects AT_BIDDING in EAP-AKA' packets, so the MAC of such
	// a packet cannot be calculated or verified with the Packet methods.
	AllowBiddingInAKAPrime bool
}

// ParseWithOptions parses an EAP packet from a byte slice like Parse, with the
// checks relaxed as specified by opts.
func ParseWithOptions(data []byte, opts ParseOptions) (*Packet, error) {
	if len(data) < 4 {
		return nil, errors.New("packet too short")
	}

	p := &Packet{}
	p.Code = data[0]
	p.Identifier = data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if length < 4 {
		return nil, errors.New("packet length too small")
	}
	if int(length) > len(data) {
		return nil, errors.New("packet length mismatch")
	}
	// Use only the slice indicated by length
	payload := data[4:length]

	// If Success or Failure, no more data expected
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		if len(payload) != 0 {
			return nil, errors.New("unexpected data in success/failure packet")
		}
		return p, nil
	}

	if len(payload) == 0 {
		return nil, errors.New("missing EAP type")
	}

	p.Type = payload[0]
	// Only parse attributes for AKA and AKA'
	if p.Type != TypeAKA && p.Type != TypeAKAPrime {
		// Not an AKA packet we understand structure of beyond Type
		return p, nil
	}

	if len(payload) < 4 {
		return nil, errors.New("invalid EAP-AKA header")
	}

	p.Subtype = payload[1]
	// Reserved bytes at payload[2:4] are ignored

	// Attributes start at payload[4]
	attrs, err := parseAttributes(payload[4:], p.Type == TypeAKAPrime && !opts.AllowBiddingInAKAPrime)
	if err != nil {
		return nil, err
	}
	p.Attributes = attrs

	return p, nil
}

// ParseAttributes parses a sequence of EAP-AKA/AKA' attributes that is not
// wrapped in an EAP packet, such as the decrypted contents of AT_ENCR_DATA.
//
// Attributes of unknown types are returned as *GenericAttribute; use
// IsSkippable to decide how to handle them (RFC 4187 Section 8.1).
// ParseAttributes does not check which attributes are allowed where the data
// came from. An empty input yields no attributes and no error.
func ParseAttributes(b []byte) ([]Attribute, error) {
	return parseAttributes(b, false)
}

// parseAttributes は属性の並びを解析する。rejectBidding が true なら AT_BIDDING を
// エラーにする（EAP-AKA' のメッセージには AT_BIDDING を含めない。RFC 9048 §4）。
func parseAttributes(data []byte, rejectBidding bool) ([]Attribute, error) {
	var attrs []Attribute
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			return nil, errors.New("attribute header truncated")
		}
		attrType := AttributeType(data[offset])
		attrLen := int(data[offset+1]) * 4 // Length in bytes

		if attrLen == 0 {
			return nil, errors.New("attribute length zero")
		}
		if offset+attrLen > len(data) {
			return nil, fmt.Errorf("attribute %d length overflow", attrType)
		}
		if rejectBidding && attrType == AT_BIDDING {
			return nil, errors.New("AT_BIDDING is only valid for EAP-AKA")
		}

		// Value is after Type(1) + Length(1) = 2 bytes
		valData := data[offset+2 : offset+attrLen]

		attr, err := decodeAttribute(attrType, valData)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)

		offset += attrLen
	}
	return attrs, nil
}
