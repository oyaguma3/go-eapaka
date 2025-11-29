package eapaka

// EAP Codes (RFC 3748 Section 4)
const (
	CodeRequest  uint8 = 1
	CodeResponse uint8 = 2
	CodeSuccess  uint8 = 3
	CodeFailure  uint8 = 4
)

// EAP Method Types
const (
	TypeAKA      uint8 = 23 // RFC 4187
	TypeAKAPrime uint8 = 50 // RFC 5448
)

// EAP-AKA Subtypes (RFC 4187 Section 11)
const (
	SubtypeChallenge              uint8 = 1
	SubtypeAuthenticationReject   uint8 = 2
	SubtypeSynchronizationFailure uint8 = 4
	SubtypeIdentity               uint8 = 5
	SubtypeNotification           uint8 = 12
	SubtypeReauthentication       uint8 = 13
	SubtypeClientError            uint8 = 14
)

// Attribute Types (RFC 4187 Section 10.15)
type AttributeType uint8

const (
	AT_RAND              AttributeType = 1   // RFC 4187 Section 10.6
	AT_AUTN              AttributeType = 2   // RFC 4187 Section 10.7
	AT_RES               AttributeType = 3   // RFC 4187 Section 10.8
	AT_AUTS              AttributeType = 4   // RFC 4187 Section 10.9
	AT_PADDING           AttributeType = 6   // RFC 4187 Section 10.12
	AT_NONCE_MT          AttributeType = 7   // RFC 4186 Section 10.1
	AT_PERMANENT_ID_REQ  AttributeType = 10  // RFC 4187 Section 10.2
	AT_MAC               AttributeType = 11  // RFC 4187 Section 10.15
	AT_NOTIFICATION      AttributeType = 12  // RFC 4187 Section 10.19
	AT_ANY_ID_REQ        AttributeType = 13  // RFC 4187 Section 10.3
	AT_IDENTITY          AttributeType = 14  // RFC 4187 Section 10.5
	AT_VERSION_LIST      AttributeType = 15  // RFC 4186 Section 10.4
	AT_SELECTED_VERSION  AttributeType = 16  // RFC 4186 Section 10.5
	AT_FULLAUTH_ID_REQ   AttributeType = 17  // RFC 4187 Section 10.4
	AT_COUNTER           AttributeType = 19  // RFC 4187 Section 10.16
	AT_COUNTER_TOO_SMALL AttributeType = 20  // RFC 4187 Section 10.17
	AT_NONCE_S           AttributeType = 21  // RFC 4187 Section 10.18
	AT_CLIENT_ERROR_CODE AttributeType = 22  // RFC 4187 Section 10.20
	AT_KDF_INPUT         AttributeType = 23  // RFC 5448 Section 6.2 (assigned) / Section 3.1 (format)
	AT_KDF               AttributeType = 24  // RFC 5448 Section 6.2 (assigned) / Section 3.2 (format)
	AT_IV                AttributeType = 129 // RFC 4187 Section 10.12
	AT_ENCR_DATA         AttributeType = 130 // RFC 4187 Section 10.12
	AT_NEXT_PSEUDONYM    AttributeType = 132 // RFC 4187 Section 10.10
	AT_NEXT_REAUTH_ID    AttributeType = 133 // RFC 4187 Section 10.11
	AT_CHECKCODE         AttributeType = 134 // RFC 4187 Section 10.13
	AT_RESULT_IND        AttributeType = 135 // RFC 4187 Section 10.14
	AT_BIDDING           AttributeType = 136 // RFC 5448 Section 6.2 (assigned) / Section 4 (format)
)
