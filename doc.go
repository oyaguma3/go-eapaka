/*
Package eapaka implements EAP-AKA (RFC 4187) and EAP-AKA' (RFC 5448) protocols.

It provides functionality to marshal and unmarshal EAP packets, handle EAP-AKA attributes
(including Identity, Notification, Re-auth, etc.), and perform cryptographic operations.

Note: This library handles the attribute headers (Type and Length) and padding.
For the attribute value (data), you must construct the byte slice yourself according
to the RFC definitions and assign it to the corresponding field (e.g., Rand, Autn, Identity).

# Usage

To parse an incoming EAP packet:

	pkt, err := eapaka.Parse(data)
	if err != nil {
		// handle error
	}

To create and marshal a packet:

	pkt := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRand{Rand: randData},
			&eapaka.AtAutn{Autn: autnData},
			&eapaka.AtMac{MAC: make([]byte, 16)}, // Placeholder
		},
	}

	// Calculate MAC
	err := pkt.CalculateAndSetMac(kAut)

	data, err := pkt.Marshal()

# References

  - RFC 3748: Extensible Authentication Protocol (EAP)
  - RFC 4187: EAP Method for 3rd Gen Authentication and Key Agreement (EAP-AKA)
  - RFC 5448: Improved EAP Method for 3rd Gen Authentication and Key Agreement (EAP-AKA')
*/
package eapaka
