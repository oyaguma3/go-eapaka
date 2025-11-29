package eapaka

// Packet represents an EAP packet including EAP-AKA/AKA' specific data.
// It supports both EAP-Request/Response (with attributes) and EAP-Success/Failure (header only).
type Packet struct {
	// Code indicates the EAP Code (e.g., Request, Response).
	// See RFC 3748 Section 4.
	Code uint8

	// Identifier handles request/response matching.
	Identifier uint8

	// Type indicates the EAP Method Type.
	// Use TypeAKA (23) or TypeAKAPrime (50).
	// This field is ignored if Code is Success(3) or Failure(4).
	Type uint8

	// Subtype indicates the EAP-AKA Subtype (e.g., Challenge, Synchronization-Failure).
	// See RFC 4187 Section 11.
	Subtype uint8

	// Attributes contains the list of EAP-AKA attributes.
	Attributes []Attribute
}
