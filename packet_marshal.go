package eapaka

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Marshal serializes the EAP packet into a byte slice.
func (p *Packet) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// 1. Marshal Attributes first to calculate length
	var attrsBuf bytes.Buffer
	if p.Code == CodeRequest || p.Code == CodeResponse {
		// EAP-AKA/AKA' header inside EAP Data
		// Type (1) + Subtype (1) + Reserved (2) = 4 bytes
		// Only if Type is AKA or AKA'
		if p.Type == TypeAKA || p.Type == TypeAKAPrime {
			attrsBuf.WriteByte(p.Type)
			attrsBuf.WriteByte(p.Subtype)
			attrsBuf.Write([]byte{0x00, 0x00}) // Reserved
		}

		for _, attr := range p.Attributes {
			b, err := attr.Marshal()
			if err != nil {
				return nil, err
			}
			attrsBuf.Write(b)
		}
	}

	// 2. EAP Header
	// Code (1) + Identifier (1) + Length (2)
	eapLen := 4 + attrsBuf.Len()
	if eapLen > 65535 {
		return nil, errors.New("packet too long")
	}

	buf.WriteByte(p.Code)
	buf.WriteByte(p.Identifier)
	binary.Write(&buf, binary.BigEndian, uint16(eapLen))

	// 3. Append Attributes (which includes Method Type/Subtype header)
	buf.Write(attrsBuf.Bytes())

	return buf.Bytes(), nil
}
