package eapaka

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Parse parses an EAP packet from a byte slice.
func Parse(data []byte) (*Packet, error) {
	if len(data) < 4 {
		return nil, errors.New("packet too short")
	}

	p := &Packet{}
	p.Code = data[0]
	p.Identifier = data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if int(length) > len(data) {
		return nil, errors.New("packet length mismatch")
	}
	// Use only the slice indicated by length
	payload := data[4:length]

	// If Success or Failure, no more data expected (usually)
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		return p, nil
	}

	if len(payload) == 0 {
		return p, nil // Empty Request/Response?
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
	attrData := payload[4:]
	offset := 0
	for offset < len(attrData) {
		if offset+2 > len(attrData) {
			return nil, errors.New("attribute header truncated")
		}
		attrType := AttributeType(attrData[offset])
		attrLen := int(attrData[offset+1]) * 4 // Length in bytes

		if attrLen == 0 {
			return nil, errors.New("attribute length zero")
		}
		if offset+attrLen > len(attrData) {
			return nil, fmt.Errorf("attribute %d length overflow", attrType)
		}

		// Value is after Type(1) + Length(1) = 2 bytes
		valData := attrData[offset+2 : offset+attrLen]

		attr, err := decodeAttribute(attrType, valData)
		if err != nil {
			return nil, err
		}
		p.Attributes = append(p.Attributes, attr)

		offset += attrLen
	}

	return p, nil
}
