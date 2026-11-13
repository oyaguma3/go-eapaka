package eapaka

// Notification codes (RFC 4187 Section 10.19). The values are 16-bit codes
// that include the S bit (0x8000) and the P bit (0x4000); see AtNotification.
const (
	NotificationGeneralFailureAfterAuth uint16 = 0     // S = 0, P = 0
	NotificationTemporarilyDenied       uint16 = 1026  // S = 0, P = 0
	NotificationNotSubscribed           uint16 = 1031  // S = 0, P = 0
	NotificationGeneralFailure          uint16 = 16384 // S = 0, P = 1
	NotificationSuccess                 uint16 = 32768 // S = 1, P = 0
)

const (
	notificationSBit     uint16 = 0x8000
	notificationPBit     uint16 = 0x4000
	notificationCodeMask uint16 = 0x3FFF
)

// FullCode returns the 16-bit notification code including the S and P bits,
// which is the form of the values listed in RFC 4187 Section 10.19 (for
// example, NotificationGeneralFailure).
func (a *AtNotification) FullCode() uint16 {
	v := a.Code & notificationCodeMask
	if a.S {
		v |= notificationSBit
	}
	if a.P {
		v |= notificationPBit
	}
	return v
}

// NewNotification returns an AT_NOTIFICATION attribute for the 16-bit
// notification code, setting S and P from its two most significant bits.
//
// NewNotification does not reject codes that have both S and P set, which
// RFC 4187 Section 6.1 does not allow.
func NewNotification(code uint16) *AtNotification {
	return &AtNotification{
		S:    code&notificationSBit != 0,
		P:    code&notificationPBit != 0,
		Code: code & notificationCodeMask,
	}
}
