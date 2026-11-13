/*
Package eapaka implements EAP-AKA (RFC 4187) and EAP-AKA' (RFC 9048, which
obsoletes RFC 5448) protocols.

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
	if err != nil {
		// handle error
	}

To derive keys (EAP-AKA'):

	autn := ... // from USIM/HSS
	ckPrime, ikPrime, err := eapaka.DeriveCKPrimeIKPrime(ck, ik, "WLAN", autn)
	keys := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)

To derive keys on fast re-authentication, keep AkaKeys.MK (EAP-AKA) or
AkaPrimeKeys.K_re (EAP-AKA') from full authentication:

	reauth, err := eapaka.DeriveReauthKeysAKA(reauthID, counter, nonceS, keys.MK)
	reauth, err := eapaka.DeriveReauthKeysAKAPrime(reauthID, counter, nonceS, keys.K_re)

To encrypt and decrypt the nested attributes of AT_ENCR_DATA (AT_PADDING is
added and removed automatically):

	iv := eapaka.NewIV()
	encrypted, err := eapaka.EncryptAttributes(kEncr, iv, attrs)
	attrs, err := eapaka.DecryptAttributes(kEncr, iv, encrypted)

To calculate and verify the MAC of EAP-Response/AKA-Reauthentication, which
also covers NONCE_S:

	err := resp.CalculateAndSetMacWithExtra(kAut, nonceS)
	ok, err := resp.VerifyMacWithExtra(kAut, nonceS)

To encrypt and decrypt MS-MPPE-Keys:

	encKey, err := eapaka.EncryptMPPEKey(keys.MSK[:32], secret, reqAuth)
	key, err := eapaka.DecryptMPPEKey(encKey, secret, reqAuth)

To verify the MAC over the bytes as received (so that non-zero reserved
fields set by the sender do not make a valid MAC mismatch):

	ok, err := eapaka.VerifyMacRaw(data, kAut, nil)

Errors for malformed input wrap sentinel errors such as ErrMalformedAttribute,
ErrPaddingNotZero and ErrBiddingInAKAPrime, which can be tested with
errors.Is. An attribute that cannot be parsed is reported as *AttributeError.

Other helpers include ComputeCheckcode (AT_CHECKCODE), NewNotification and
AtNotification.FullCode (AT_NOTIFICATION codes), SessionIDAKA and
SessionIDAKAPrime (Session-Id), and ParseWithOptions.

The cryptographic helpers are tested against test vectors generated from
hostap and Python; see tools/vectorgen in the repository.

# References

  - RFC 2548: Microsoft Vendor-specific RADIUS Attributes (MS-MPPE-Send-Key, MS-MPPE-Recv-Key)
  - RFC 3748: Extensible Authentication Protocol (EAP)
  - RFC 4187: EAP Method for 3rd Gen Authentication and Key Agreement (EAP-AKA)
  - RFC 5247: EAP Key Management Framework (Session-Id)
  - RFC 9048: Improved EAP Method for 3rd Gen Authentication and Key Agreement (EAP-AKA'),
    which obsoletes RFC 5448
*/
package eapaka
