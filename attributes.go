package eapaka

import (
	"encoding/binary"
	"errors"
)

// Attribute is the interface implemented by all EAP-AKA attributes.
type Attribute interface {
	// Type returns the attribute type (e.g., AT_RAND).
	Type() AttributeType

	// Marshal serializes the attribute into a byte slice, including padding.
	Marshal() ([]byte, error)

	// Unmarshal parses the value part of the attribute.
	Unmarshal(data []byte) error
}

// marshalAttribute is a helper to marshal header and data with padding.
func marshalAttribute(t AttributeType, data []byte) ([]byte, error) {
	// Length is in multiples of 4 bytes.
	// Header is 2 bytes (Type + Length).
	// Total length = 2 + len(data) + padding
	totalLen := 2 + len(data)
	padding := 0
	if totalLen%4 != 0 {
		padding = 4 - (totalLen % 4)
		totalLen += padding
	}

	if totalLen > 255*4 {
		return nil, errors.New("attribute too long")
	}

	b := make([]byte, totalLen)
	b[0] = uint8(t)
	b[1] = uint8(totalLen / 4)
	copy(b[2:], data)
	// Padding is zero-initialized by make
	return b, nil
}

// AT_RAND (RFC 4187 Section 10.6)
type AtRand struct {
	Rand []byte // 16 bytes
}

func (a *AtRand) Type() AttributeType { return AT_RAND }
func (a *AtRand) Marshal() ([]byte, error) {
	if len(a.Rand) != 16 {
		return nil, errors.New("AT_RAND must be 16 bytes")
	}
	return marshalAttribute(AT_RAND, a.Rand)
}
func (a *AtRand) Unmarshal(data []byte) error {
	if len(data) < 16 {
		return errors.New("invalid AT_RAND length")
	}
	a.Rand = make([]byte, 16)
	copy(a.Rand, data[:16])
	return nil
}

// AT_AUTN (RFC 4187 Section 10.7)
type AtAutn struct {
	Autn []byte // 16 bytes
}

func (a *AtAutn) Type() AttributeType { return AT_AUTN }
func (a *AtAutn) Marshal() ([]byte, error) {
	if len(a.Autn) != 16 {
		return nil, errors.New("AT_AUTN must be 16 bytes")
	}
	return marshalAttribute(AT_AUTN, a.Autn)
}
func (a *AtAutn) Unmarshal(data []byte) error {
	if len(data) < 16 {
		return errors.New("invalid AT_AUTN length")
	}
	a.Autn = make([]byte, 16)
	copy(a.Autn, data[:16])
	return nil
}

// AT_RES (RFC 4187 Section 10.8)
type AtRes struct {
	Res []byte // Variable length
}

func (a *AtRes) Type() AttributeType { return AT_RES }
func (a *AtRes) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes reserved + 2 bytes res length (bits) + res value
	resLenBits := len(a.Res) * 8
	buf := make([]byte, 2+len(a.Res))
	binary.BigEndian.PutUint16(buf[0:2], uint16(resLenBits))
	copy(buf[2:], a.Res)
	return marshalAttribute(AT_RES, buf)
}
func (a *AtRes) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_RES length")
	}
	resLenBits := binary.BigEndian.Uint16(data[0:2])
	resLenBytes := int((resLenBits + 7) / 8)
	if len(data) < 2+resLenBytes {
		return errors.New("invalid AT_RES data length")
	}
	a.Res = make([]byte, resLenBytes)
	copy(a.Res, data[2:2+resLenBytes])
	return nil
}

// AT_AUTS (RFC 4187 Section 10.9)
type AtAuts struct {
	Auts []byte // 14 bytes
}

func (a *AtAuts) Type() AttributeType { return AT_AUTS }
func (a *AtAuts) Marshal() ([]byte, error) {
	if len(a.Auts) != 14 {
		return nil, errors.New("AT_AUTS must be 14 bytes")
	}
	return marshalAttribute(AT_AUTS, a.Auts)
}
func (a *AtAuts) Unmarshal(data []byte) error {
	if len(data) < 14 {
		return errors.New("invalid AT_AUTS length")
	}
	a.Auts = make([]byte, 14)
	copy(a.Auts, data[:14])
	return nil
}

// AT_MAC (RFC 4187 Section 10.11)
type AtMac struct {
	MAC []byte // 16 bytes
}

func (a *AtMac) Type() AttributeType { return AT_MAC }
func (a *AtMac) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes reserved + 16 bytes MAC
	buf := make([]byte, 2+16)
	// Reserved bytes are 0
	if len(a.MAC) > 0 {
		if len(a.MAC) != 16 {
			return nil, errors.New("AT_MAC must be 16 bytes")
		}
		copy(buf[2:], a.MAC)
	}
	return marshalAttribute(AT_MAC, buf)
}
func (a *AtMac) Unmarshal(data []byte) error {
	if len(data) < 18 {
		return errors.New("invalid AT_MAC length")
	}
	a.MAC = make([]byte, 16)
	copy(a.MAC, data[2:18])
	return nil
}

// AT_IDENTITY (RFC 4187 Section 10.10)
type AtIdentity struct {
	Identity string
}

func (a *AtIdentity) Type() AttributeType { return AT_IDENTITY }
func (a *AtIdentity) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes actual length + identity
	idBytes := []byte(a.Identity)
	buf := make([]byte, 2+len(idBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(idBytes)))
	copy(buf[2:], idBytes)
	return marshalAttribute(AT_IDENTITY, buf)
}
func (a *AtIdentity) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_IDENTITY length")
	}
	actualLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(actualLen) {
		return errors.New("invalid AT_IDENTITY data length")
	}
	a.Identity = string(data[2 : 2+actualLen])
	return nil
}

// AT_PERMANENT_ID_REQ (RFC 4187 Section 10.2)
type AtPermanentIdReq struct {
	// Contains two reserved bytes, effectively empty for users
}

func (a *AtPermanentIdReq) Type() AttributeType { return AT_PERMANENT_ID_REQ }
func (a *AtPermanentIdReq) Marshal() ([]byte, error) {
	// Value is 2 bytes of reserved (0)
	return marshalAttribute(AT_PERMANENT_ID_REQ, make([]byte, 2))
}
func (a *AtPermanentIdReq) Unmarshal(data []byte) error {
	// Just check length, data is ignored (reserved)
	if len(data) < 2 {
		return errors.New("invalid AT_PERMANENT_ID_REQ length")
	}
	return nil
}

// AT_ANY_ID_REQ (RFC 4187 Section 10.3)
type AtAnyIdReq struct {
	// Contains two reserved bytes
}

func (a *AtAnyIdReq) Type() AttributeType { return AT_ANY_ID_REQ }
func (a *AtAnyIdReq) Marshal() ([]byte, error) {
	return marshalAttribute(AT_ANY_ID_REQ, make([]byte, 2))
}
func (a *AtAnyIdReq) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_ANY_ID_REQ length")
	}
	return nil
}

// AT_FULLAUTH_ID_REQ (RFC 4187 Section 10.4)
type AtFullauthIdReq struct {
	// Contains two reserved bytes
}

func (a *AtFullauthIdReq) Type() AttributeType { return AT_FULLAUTH_ID_REQ }
func (a *AtFullauthIdReq) Marshal() ([]byte, error) {
	return marshalAttribute(AT_FULLAUTH_ID_REQ, make([]byte, 2))
}
func (a *AtFullauthIdReq) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_FULLAUTH_ID_REQ length")
	}
	return nil
}

// AT_RESULT_IND (RFC 4187 Section 10.14)
type AtResultInd struct {
	// Contains two reserved bytes
}

func (a *AtResultInd) Type() AttributeType { return AT_RESULT_IND }
func (a *AtResultInd) Marshal() ([]byte, error) {
	return marshalAttribute(AT_RESULT_IND, make([]byte, 2))
}
func (a *AtResultInd) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_RESULT_IND length")
	}
	return nil
}

// AT_BIDDING (RFC 5448 Section 4)
type AtBidding struct {
	// Contains two reserved bytes
}

func (a *AtBidding) Type() AttributeType { return AT_BIDDING }
func (a *AtBidding) Marshal() ([]byte, error) {
	return marshalAttribute(AT_BIDDING, make([]byte, 2))
}
func (a *AtBidding) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_BIDDING length")
	}
	return nil
}

// AT_CHECKCODE (RFC 4187 Section 10.13)
type AtCheckcode struct {
	Checkcode []byte
}

func (a *AtCheckcode) Type() AttributeType { return AT_CHECKCODE }
func (a *AtCheckcode) Marshal() ([]byte, error) {
	// RFC 5448: 2 bytes reserved + checkcode
	buf := make([]byte, 2+len(a.Checkcode))
	copy(buf[2:], a.Checkcode)
	return marshalAttribute(AT_CHECKCODE, buf)
}
func (a *AtCheckcode) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_CHECKCODE length")
	}
	a.Checkcode = make([]byte, len(data)-2)
	copy(a.Checkcode, data[2:])
	return nil
}

// AT_PADDING (RFC 4187 Section 10.12)
type AtPadding struct {
	Length int // Number of zero bytes
}

func (a *AtPadding) Type() AttributeType { return AT_PADDING }
func (a *AtPadding) Marshal() ([]byte, error) {
	return marshalAttribute(AT_PADDING, make([]byte, a.Length))
}
func (a *AtPadding) Unmarshal(data []byte) error {
	a.Length = len(data)
	return nil
}

// AT_KDF_INPUT (RFC 5448 Section 3.1)
type AtKdfInput struct {
	NetworkName string
}

func (a *AtKdfInput) Type() AttributeType { return AT_KDF_INPUT }
func (a *AtKdfInput) Marshal() ([]byte, error) {
	// RFC 5448: Actual Network Name Length (2 bytes) + Network Name
	nameBytes := []byte(a.NetworkName)
	buf := make([]byte, 2+len(nameBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(nameBytes)))
	copy(buf[2:], nameBytes)
	return marshalAttribute(AT_KDF_INPUT, buf)
}
func (a *AtKdfInput) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_KDF_INPUT length")
	}
	actualLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(actualLen) {
		return errors.New("invalid AT_KDF_INPUT data length")
	}
	a.NetworkName = string(data[2 : 2+actualLen])
	return nil
}

// AT_KDF (RFC 5448 Section 3.2)
type AtKdf struct {
	KDF uint16
}

func (a *AtKdf) Type() AttributeType { return AT_KDF }
func (a *AtKdf) Marshal() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, a.KDF)
	return marshalAttribute(AT_KDF, buf)
}
func (a *AtKdf) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_KDF length")
	}
	a.KDF = binary.BigEndian.Uint16(data[:2])
	return nil
}

// AT_NONCE_MT (RFC 4186 Section 10.1)
type AtNonceMt struct {
	NonceMt []byte // 16 bytes
}

func (a *AtNonceMt) Type() AttributeType { return AT_NONCE_MT }
func (a *AtNonceMt) Marshal() ([]byte, error) {
	if len(a.NonceMt) != 16 {
		return nil, errors.New("AT_NONCE_MT must be 16 bytes")
	}
	// RFC 4186: 2 bytes reserved + 16 bytes Nonce_MT
	buf := make([]byte, 2+16)
	copy(buf[2:], a.NonceMt)
	return marshalAttribute(AT_NONCE_MT, buf)
}
func (a *AtNonceMt) Unmarshal(data []byte) error {
	if len(data) < 18 {
		return errors.New("invalid AT_NONCE_MT length")
	}
	a.NonceMt = make([]byte, 16)
	copy(a.NonceMt, data[2:18])
	return nil
}

// AT_NOTIFICATION (RFC 4187 Section 10.19)
type AtNotification struct {
	S    bool
	P    bool
	Code uint16
}

func (a *AtNotification) Type() AttributeType { return AT_NOTIFICATION }
func (a *AtNotification) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes code. S bit is MSB (0x8000), P bit is 2nd MSB (0x4000)
	val := a.Code & 0x3FFF
	if a.S {
		val |= 0x8000
	}
	if a.P {
		val |= 0x4000
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return marshalAttribute(AT_NOTIFICATION, buf)
}
func (a *AtNotification) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_NOTIFICATION length")
	}
	val := binary.BigEndian.Uint16(data[:2])
	a.S = (val & 0x8000) != 0
	a.P = (val & 0x4000) != 0
	a.Code = val & 0x3FFF
	return nil
}

// AT_VERSION_LIST (RFC 4186 Section 10.4)
type AtVersionList struct {
	Versions []uint16
}

func (a *AtVersionList) Type() AttributeType { return AT_VERSION_LIST }
func (a *AtVersionList) Marshal() ([]byte, error) {
	// RFC 4186: 2 bytes actual length + versions
	actualLen := len(a.Versions) * 2
	buf := make([]byte, 2+actualLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(actualLen))
	for i, v := range a.Versions {
		binary.BigEndian.PutUint16(buf[2+i*2:], v)
	}
	return marshalAttribute(AT_VERSION_LIST, buf)
}
func (a *AtVersionList) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_VERSION_LIST length")
	}
	actualLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(actualLen) {
		return errors.New("invalid AT_VERSION_LIST data length")
	}
	numVersions := int(actualLen) / 2
	a.Versions = make([]uint16, numVersions)
	for i := 0; i < numVersions; i++ {
		a.Versions[i] = binary.BigEndian.Uint16(data[2+i*2 : 4+i*2])
	}
	return nil
}

// AT_SELECTED_VERSION (RFC 4186 Section 10.5)
type AtSelectedVersion struct {
	Version uint16
}

func (a *AtSelectedVersion) Type() AttributeType { return AT_SELECTED_VERSION }
func (a *AtSelectedVersion) Marshal() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, a.Version)
	return marshalAttribute(AT_SELECTED_VERSION, buf)
}
func (a *AtSelectedVersion) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_SELECTED_VERSION length")
	}
	a.Version = binary.BigEndian.Uint16(data[:2])
	return nil
}

// AT_COUNTER (RFC 4187 Section 10.16)
type AtCounter struct {
	Counter uint16
}

func (a *AtCounter) Type() AttributeType { return AT_COUNTER }
func (a *AtCounter) Marshal() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, a.Counter)
	return marshalAttribute(AT_COUNTER, buf)
}
func (a *AtCounter) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_COUNTER length")
	}
	a.Counter = binary.BigEndian.Uint16(data[:2])
	return nil
}

// AT_COUNTER_TOO_SMALL (RFC 4187 Section 10.17)
type AtCounterTooSmall struct {
	// Contains two reserved bytes
}

func (a *AtCounterTooSmall) Type() AttributeType { return AT_COUNTER_TOO_SMALL }
func (a *AtCounterTooSmall) Marshal() ([]byte, error) {
	return marshalAttribute(AT_COUNTER_TOO_SMALL, make([]byte, 2))
}
func (a *AtCounterTooSmall) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_COUNTER_TOO_SMALL length")
	}
	return nil
}

// AT_NONCE_S (RFC 4187 Section 10.18)
type AtNonceS struct {
	NonceS []byte // 16 bytes
}

func (a *AtNonceS) Type() AttributeType { return AT_NONCE_S }
func (a *AtNonceS) Marshal() ([]byte, error) {
	if len(a.NonceS) != 16 {
		return nil, errors.New("AT_NONCE_S must be 16 bytes")
	}
	// RFC 4187: 2 bytes reserved + 16 bytes Nonce_S
	buf := make([]byte, 2+16)
	copy(buf[2:], a.NonceS)
	return marshalAttribute(AT_NONCE_S, buf)
}
func (a *AtNonceS) Unmarshal(data []byte) error {
	if len(data) < 18 {
		return errors.New("invalid AT_NONCE_S length")
	}
	a.NonceS = make([]byte, 16)
	copy(a.NonceS, data[2:18])
	return nil
}

// AT_CLIENT_ERROR_CODE (RFC 4187 Section 10.20)
type AtClientErrorCode struct {
	Code uint16
}

func (a *AtClientErrorCode) Type() AttributeType { return AT_CLIENT_ERROR_CODE }
func (a *AtClientErrorCode) Marshal() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, a.Code)
	return marshalAttribute(AT_CLIENT_ERROR_CODE, buf)
}
func (a *AtClientErrorCode) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_CLIENT_ERROR_CODE length")
	}
	a.Code = binary.BigEndian.Uint16(data[:2])
	return nil
}

// AT_IV (RFC 4187 Section 10.12)
type AtIv struct {
	IV []byte // 16 bytes
}

func (a *AtIv) Type() AttributeType { return AT_IV }
func (a *AtIv) Marshal() ([]byte, error) {
	if len(a.IV) != 16 {
		return nil, errors.New("AT_IV must be 16 bytes")
	}
	// RFC 4187: 2 bytes reserved + 16 bytes IV
	buf := make([]byte, 2+16)
	copy(buf[2:], a.IV)
	return marshalAttribute(AT_IV, buf)
}
func (a *AtIv) Unmarshal(data []byte) error {
	if len(data) < 18 {
		return errors.New("invalid AT_IV length")
	}
	a.IV = make([]byte, 16)
	copy(a.IV, data[2:18])
	return nil
}

// AT_ENCR_DATA (RFC 4187 Section 10.12)
type AtEncrData struct {
	EncryptedData []byte
}

func (a *AtEncrData) Type() AttributeType { return AT_ENCR_DATA }
func (a *AtEncrData) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes reserved + Encrypted Data
	buf := make([]byte, 2+len(a.EncryptedData))
	copy(buf[2:], a.EncryptedData)
	return marshalAttribute(AT_ENCR_DATA, buf)
}
func (a *AtEncrData) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_ENCR_DATA length")
	}
	a.EncryptedData = make([]byte, len(data)-2)
	copy(a.EncryptedData, data[2:])
	return nil
}

// AT_NEXT_PSEUDONYM (RFC 4187 Section 10.10)
type AtNextPseudonym struct {
	Pseudonym string
}

func (a *AtNextPseudonym) Type() AttributeType { return AT_NEXT_PSEUDONYM }
func (a *AtNextPseudonym) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes actual length + pseudonym
	// Encrypted inside AT_ENCR_DATA usually, but this struct just handles the attribute itself.
	idBytes := []byte(a.Pseudonym)
	buf := make([]byte, 2+len(idBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(idBytes)))
	copy(buf[2:], idBytes)
	return marshalAttribute(AT_NEXT_PSEUDONYM, buf)
}
func (a *AtNextPseudonym) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_NEXT_PSEUDONYM length")
	}
	actualLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(actualLen) {
		return errors.New("invalid AT_NEXT_PSEUDONYM data length")
	}
	a.Pseudonym = string(data[2 : 2+actualLen])
	return nil
}

// AT_NEXT_REAUTH_ID (RFC 4187 Section 10.11)
type AtNextReauthId struct {
	Identity string
}

func (a *AtNextReauthId) Type() AttributeType { return AT_NEXT_REAUTH_ID }
func (a *AtNextReauthId) Marshal() ([]byte, error) {
	// RFC 4187: 2 bytes actual length + identity
	idBytes := []byte(a.Identity)
	buf := make([]byte, 2+len(idBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(idBytes)))
	copy(buf[2:], idBytes)
	return marshalAttribute(AT_NEXT_REAUTH_ID, buf)
}
func (a *AtNextReauthId) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid AT_NEXT_REAUTH_ID length")
	}
	actualLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(actualLen) {
		return errors.New("invalid AT_NEXT_REAUTH_ID data length")
	}
	a.Identity = string(data[2 : 2+actualLen])
	return nil
}

// GenericAttribute for unknown types
type GenericAttribute struct {
	AttrType AttributeType
	Data     []byte
}

func (a *GenericAttribute) Type() AttributeType { return a.AttrType }
func (a *GenericAttribute) Marshal() ([]byte, error) {
	return marshalAttribute(a.AttrType, a.Data)
}
func (a *GenericAttribute) Unmarshal(data []byte) error {
	a.Data = make([]byte, len(data))
	copy(a.Data, data)
	return nil
}
