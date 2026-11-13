package eapaka

import (
	"errors"
	"fmt"
)

// Sentinel errors for malformed input received from a peer or server.
//
// Errors returned by this package wrap these values, so callers can test them
// with errors.Is, for example to map a failure to a conformance rule. The
// messages of the returned errors are the same as in earlier versions; the
// sentinel errors only add a way to classify them.
var (
	// ErrMalformedPacket reports an invalid EAP packet structure: the EAP
	// header, the Length field, the EAP-AKA header, or more than one AT_MAC.
	ErrMalformedPacket = errors.New("malformed EAP packet")

	// ErrMalformedAttribute reports a malformed attribute: a truncated
	// attribute header, a zero Length, a Length beyond the end of the data, or
	// a value that cannot be parsed. Errors for values that cannot be parsed
	// are *AttributeError, which also wraps the specific cause.
	ErrMalformedAttribute = errors.New("malformed attribute")

	// ErrBiddingInAKAPrime reports AT_BIDDING in an EAP-AKA' packet, which
	// RFC 9048 Section 4 does not allow.
	ErrBiddingInAKAPrime = errors.New("AT_BIDDING is only valid for EAP-AKA")

	// ErrEncrDataLength reports that the Encrypted Data of AT_ENCR_DATA is not
	// a positive multiple of 16 bytes (RFC 4187 Section 10.12).
	ErrEncrDataLength = errors.New("AT_ENCR_DATA length is not a positive multiple of 16")

	// ErrPaddingLength reports an AT_PADDING whose length is not 4, 8 or 12
	// bytes (RFC 4187 Section 10.12).
	ErrPaddingLength = errors.New("invalid AT_PADDING length")

	// ErrPaddingNotZero reports an AT_PADDING whose pad bytes are not zero
	// (RFC 4187 Section 10.12).
	ErrPaddingNotZero = errors.New("AT_PADDING bytes must be zero")

	// ErrPaddingNotLast reports an AT_PADDING that is not the last attribute
	// in AT_ENCR_DATA (RFC 4187 Section 10.12).
	ErrPaddingNotLast = errors.New("AT_PADDING is not the last attribute in AT_ENCR_DATA")

	// ErrMacNotFound reports a packet without AT_MAC.
	ErrMacNotFound = errors.New("AT_MAC attribute not found")

	// ErrEmptyKdfInput reports an empty network name in AT_KDF_INPUT
	// (RFC 9048 Section 3.1).
	ErrEmptyKdfInput = errors.New("AT_KDF_INPUT must be non-empty")

	// ErrMalformedMPPEKey reports an MS-MPPE-Send-Key or MS-MPPE-Recv-Key
	// value that cannot be decrypted: an invalid length or Key-Length
	// (RFC 2548 Section 2.4.2).
	ErrMalformedMPPEKey = errors.New("malformed MPPE key attribute")
)

// AttributeError reports an attribute whose value could not be parsed.
//
// It matches ErrMalformedAttribute and the underlying error (for example,
// ErrPaddingNotZero) with errors.Is. Use errors.AsType[*AttributeError] to get
// the attribute type.
type AttributeError struct {
	Type AttributeType // the attribute type
	Err  error         // the underlying error
}

func (e *AttributeError) Error() string {
	return fmt.Sprintf("failed to unmarshal attribute type %d: %v", e.Type, e.Err)
}

// Unwrap returns ErrMalformedAttribute and the underlying error.
func (e *AttributeError) Unwrap() []error {
	return []error{ErrMalformedAttribute, e.Err}
}

// wrappedError は、従来どおりのメッセージを保ったまま、sentinel error を
// errors.Is で判定できるようにする。
type wrappedError struct {
	msg      string
	sentinel error
}

func (e *wrappedError) Error() string { return e.msg }
func (e *wrappedError) Unwrap() error { return e.sentinel }

// wrapErrorf は、メッセージが format で、errors.Is で sentinel と判定されるエラーを返す。
func wrapErrorf(sentinel error, format string, args ...any) error {
	return &wrappedError{msg: fmt.Sprintf(format, args...), sentinel: sentinel}
}
