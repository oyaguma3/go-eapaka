package eapaka_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/oyaguma3/go-eapaka"
)

// mustHex は 16 進文字列をバイト列に変換する（Example 用）。
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ExampleEncryptAttributes shows a server encrypting the nested attributes of
// EAP-Request/AKA-Reauthentication and the peer decrypting them.
func ExampleEncryptAttributes() {
	// K_encr and K_aut from full authentication
	kEncr := mustHex("000102030405060708090a0b0c0d0e0f")
	kAut := mustHex("101112131415161718191a1b1c1d1e1f")
	nonceS := mustHex("0f0e0d0c0b0a09080706050403020100")

	// Server: encrypt AT_COUNTER, AT_NONCE_S and AT_NEXT_REAUTH_ID.
	// AT_PADDING is added automatically.
	iv := eapaka.NewIV()
	encrypted, err := eapaka.EncryptAttributes(kEncr, iv, []eapaka.Attribute{
		&eapaka.AtCounter{Counter: 1},
		&eapaka.AtNonceS{NonceS: nonceS},
		&eapaka.AtNextReauthId{Identity: "4next@wlan.mnc001.mcc001.3gppnetwork.org"},
	})
	if err != nil {
		panic(err)
	}
	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeReauthentication,
		Attributes: []eapaka.Attribute{
			&eapaka.AtIv{IV: iv},
			&eapaka.AtEncrData{EncryptedData: encrypted},
			&eapaka.AtMac{},
		},
	}
	if err := req.CalculateAndSetMac(kAut); err != nil {
		panic(err)
	}
	data, err := req.Marshal()
	if err != nil {
		panic(err)
	}

	// Peer: verify AT_MAC, then decrypt AT_ENCR_DATA with the IV from AT_IV.
	received, err := eapaka.Parse(data)
	if err != nil {
		panic(err)
	}
	if ok, err := received.VerifyMac(kAut); err != nil || !ok {
		panic("invalid AT_MAC")
	}
	var gotIV, gotEncrypted []byte
	for _, a := range received.Attributes {
		switch a := a.(type) {
		case *eapaka.AtIv:
			gotIV = a.IV
		case *eapaka.AtEncrData:
			gotEncrypted = a.EncryptedData
		}
	}
	attrs, err := eapaka.DecryptAttributes(kEncr, gotIV, gotEncrypted)
	if err != nil {
		panic(err)
	}
	for _, a := range attrs {
		switch a := a.(type) {
		case *eapaka.AtCounter:
			fmt.Println("counter:", a.Counter)
		case *eapaka.AtNonceS:
			fmt.Println("NONCE_S matches:", bytes.Equal(a.NonceS, nonceS))
		case *eapaka.AtNextReauthId:
			fmt.Println("next re-auth ID:", a.Identity)
		}
	}
	// Output:
	// counter: 1
	// NONCE_S matches: true
	// next re-auth ID: 4next@wlan.mnc001.mcc001.3gppnetwork.org
}

// ExampleDeriveReauthKeysAKA keeps the MK from EAP-AKA full authentication and
// derives new MSK and EMSK on fast re-authentication.
func ExampleDeriveReauthKeysAKA() {
	// Full authentication
	full := eapaka.DeriveKeysAKA("0555444333222111",
		mustHex("5349fbe098649f948f5d2e973a81c00f"), // CK
		mustHex("9744871ad32bf9bbd1dd5ce54e3e2e5a")) // IK

	// Fast re-authentication: the re-authentication identity, AT_COUNTER and
	// AT_NONCE_S. K_encr and K_aut from full authentication stay in use.
	reauth, err := eapaka.DeriveReauthKeysAKA("4a1b2c3d4e5f6071@wlan.mnc001.mcc001.3gppnetwork.org",
		1, mustHex("000102030405060708090a0b0c0d0e0f"), full.MK)
	if err != nil {
		panic(err)
	}
	fmt.Printf("MSK:  %x...\n", reauth.MSK[:8])
	fmt.Printf("EMSK: %x...\n", reauth.EMSK[:8])
	// Output:
	// MSK:  d557ff265b1c4f8a...
	// EMSK: 3ccd1a6d82ac2755...
}

// ExampleDeriveReauthKeysAKAPrime keeps K_re from EAP-AKA' full
// authentication and derives new MSK and EMSK on fast re-authentication.
func ExampleDeriveReauthKeysAKAPrime() {
	// Full authentication (RFC 9048 Appendix D, test case 1)
	ckPrime, ikPrime, err := eapaka.DeriveCKPrimeIKPrime(
		mustHex("5349fbe098649f948f5d2e973a81c00f"), // CK
		mustHex("9744871ad32bf9bbd1dd5ce54e3e2e5a"), // IK
		"WLAN", mustHex("bb52e91c747ac3ab2a5c23d15ee351d5")) // AUTN
	if err != nil {
		panic(err)
	}
	full := eapaka.DeriveKeysAKAPrime("0555444333222111", ckPrime, ikPrime)

	reauth, err := eapaka.DeriveReauthKeysAKAPrime("8a1b2c3d4e5f6071@wlan.mnc001.mcc001.3gppnetwork.org",
		1, mustHex("000102030405060708090a0b0c0d0e0f"), full.K_re)
	if err != nil {
		panic(err)
	}
	fmt.Printf("MSK: %x...\n", reauth.MSK[:8])
	// Output:
	// MSK: 44ac00a791c5dd5c...
}

// ExamplePacket_CalculateAndSetMacWithExtra shows the MAC of
// EAP-Response/AKA-Reauthentication, which covers the packet followed by the
// NONCE_S that the server sent (RFC 4187 Section 9.8).
func ExamplePacket_CalculateAndSetMacWithExtra() {
	kAut := mustHex("18c044070e5e642a2643876ff7a83812")
	nonceS := mustHex("0f0e0d0c0b0a09080706050403020100") // from the server's AT_NONCE_S

	// Peer
	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeReauthentication,
		Attributes: []eapaka.Attribute{
			&eapaka.AtMac{}, // AT_IV and AT_ENCR_DATA (with AT_COUNTER) omitted for brevity
		},
	}
	if err := resp.CalculateAndSetMacWithExtra(kAut, nonceS); err != nil {
		panic(err)
	}
	data, err := resp.Marshal()
	if err != nil {
		panic(err)
	}

	// Server
	received, err := eapaka.Parse(data)
	if err != nil {
		panic(err)
	}
	ok, err := received.VerifyMacWithExtra(kAut, nonceS)
	fmt.Println("with NONCE_S:", ok, err)
	ok, err = received.VerifyMac(kAut)
	fmt.Println("without NONCE_S:", ok, err)
	// Output:
	// with NONCE_S: true <nil>
	// without NONCE_S: false <nil>
}

// ExampleComputeCheckcode computes AT_CHECKCODE over one AKA-Identity round
// trip.
func ExampleComputeCheckcode() {
	req, err := (&eapaka.Packet{
		Code: eapaka.CodeRequest, Identifier: 1, Type: eapaka.TypeAKA, Subtype: eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{&eapaka.AtAnyIdReq{}},
	}).Marshal()
	if err != nil {
		panic(err)
	}
	resp, err := (&eapaka.Packet{
		Code: eapaka.CodeResponse, Identifier: 1, Type: eapaka.TypeAKA, Subtype: eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{&eapaka.AtIdentity{Identity: "2s7ah6n9q3f@wlan.mnc001.mcc001.3gppnetwork.org"}},
	}).Marshal()
	if err != nil {
		panic(err)
	}

	// Pass the packets as transmitted, in order.
	checkcode, err := eapaka.ComputeCheckcode(eapaka.TypeAKA, req, resp)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", checkcode)

	// No AKA-Identity exchange: an empty checkcode.
	empty, _ := eapaka.ComputeCheckcode(eapaka.TypeAKA)
	fmt.Println(len(empty))
	// Output:
	// 461147847249efd0dea6f7927ec75b3a40a02857
	// 0
}

// ExampleNewNotification converts between the 16-bit notification codes and
// the S, P and Code fields of AtNotification.
func ExampleNewNotification() {
	n := eapaka.NewNotification(eapaka.NotificationGeneralFailure)
	fmt.Println(n.S, n.P, n.Code, n.FullCode())

	received := &eapaka.AtNotification{S: true, Code: 0}
	fmt.Println(received.FullCode() == eapaka.NotificationSuccess)
	// Output:
	// false true 0 16384
	// true
}

// ExampleDecryptMPPEKey decrypts an MS-MPPE-Recv-Key attribute value.
func ExampleDecryptMPPEKey() {
	secret := []byte("testing123")
	reqAuth := mustHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0") // from the Access-Request
	key := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	enc, err := eapaka.EncryptMPPEKey(key, secret, reqAuth)
	if err != nil {
		panic(err)
	}
	// enc[0:2] is the Salt; check its most significant bit and uniqueness separately.
	got, err := eapaka.DecryptMPPEKey(enc, secret, reqAuth)
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.Equal(got, key), enc[0]&0x80 != 0)
	// Output:
	// true true
}

// ExampleVerifyMacRaw verifies the MAC over the bytes as received when the
// sender set a reserved field to a non-zero value.
func ExampleVerifyMacRaw() {
	kAut := mustHex("101112131415161718191a1b1c1d1e1f")
	pkt := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRand{Rand: make([]byte, 16)},
			&eapaka.AtMac{},
		},
	}
	data, err := pkt.Marshal()
	if err != nil {
		panic(err)
	}
	// The sender sets the Reserved field of AT_RAND (bytes 10-11) to a
	// non-zero value and calculates the MAC over those bytes.
	data[10] = 0x01
	if err := eapaka.CalculateAndSetMacRaw(data, kAut, nil); err != nil {
		panic(err)
	}

	parsed, err := eapaka.Parse(data)
	if err != nil {
		panic(err)
	}
	fromParsed, _ := parsed.VerifyMac(kAut)              // re-marshaled: Reserved becomes zero
	fromBytes, _ := eapaka.VerifyMacRaw(data, kAut, nil) // as received
	fmt.Println(fromParsed, fromBytes)
	// Output:
	// false true
}

// ExampleAttributeError classifies a parse error with errors.Is and gets the
// attribute type with errors.AsType.
func ExampleAttributeError() {
	// EAP-Request/AKA-Notification with an AT_PADDING whose pad bytes are not zero
	raw := []byte{0x01, 0x01, 0x00, 0x0c, 23, 12, 0x00, 0x00, 0x06, 0x01, 0x00, 0x01}
	_, err := eapaka.Parse(raw)

	fmt.Println(errors.Is(err, eapaka.ErrPaddingNotZero), errors.Is(err, eapaka.ErrMalformedAttribute))
	if attrErr, ok := errors.AsType[*eapaka.AttributeError](err); ok {
		fmt.Println(attrErr.Type == eapaka.AT_PADDING)
	}
	fmt.Println(err)
	// Output:
	// true true
	// true
	// failed to unmarshal attribute type 6: AT_PADDING bytes must be zero
}
