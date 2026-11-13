# go-eapaka

`go-eapaka` is a Go library for **EAP-AKA (RFC 4187)** and **EAP-AKA' (RFC 9048, which obsoletes RFC 5448)** protocols.
It provides robust functionality for **marshaling (generating)** and **unmarshaling (parsing)** EAP packets, designed for building RADIUS servers, EAP peers, and testing tools.

## Features

- **Zero External Dependencies**: Built using only the Go standard library (`encoding/binary`, `crypto/*`).
- **Security First**: Implements constant-time MAC verification to prevent timing attacks and handles sensitive data with care.

## Installation

```bash
go get github.com/oyaguma3/go-eapaka
```

## Usage

### Parsing an EAP Packet

```go
package main

import (
	"fmt"
	"github.com/oyaguma3/go-eapaka"
)

func main() {
	// Example raw bytes (EAP-Request/AKA-Identity)
	data := []byte{...}

	pkt, err := eapaka.Parse(data)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Code: %d, Type: %d\n", pkt.Code, pkt.Type)
	
	for _, attr := range pkt.Attributes {
		switch a := attr.(type) {
		case *eapaka.AtIdentity:
			fmt.Printf("Identity: %s\n", a.Identity)
		}
	}
}
```

### Creating an EAP Packet

```go
package main

import (
	"github.com/oyaguma3/go-eapaka"
)

func main() {
	pkt := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRand{Rand: make([]byte, 16)}, // Fill with actual RAND
			&eapaka.AtAutn{Autn: make([]byte, 16)}, // Fill with actual AUTN
			&eapaka.AtMac{MAC: make([]byte, 16)},   // Placeholder for MAC
		},
	}

	// Calculate and set MAC (K_aut is required)
	// kAut := ...
	// pkt.CalculateAndSetMac(kAut)

	data, err := pkt.Marshal()
	if err != nil {
		panic(err)
	}
	
	// Send data...
}
```

### AT_BIDDING (AKA/AKA' Negotiation)

```go
bid := &eapaka.AtBidding{}
bid.SetAKAPrime(true) // Advertise AKA' support

pkt := &eapaka.Packet{
	Code:       eapaka.CodeRequest,
	Identifier: 1,
	Type:       eapaka.TypeAKA,
	Subtype:    eapaka.SubtypeIdentity,
	Attributes: []eapaka.Attribute{
		bid,
	},
}
```

### Key Derivation (KDF)

Derive session keys for EAP-AKA (RFC 4187) and EAP-AKA' (RFC 9048).

```go
// EAP-AKA' Example
identity := "0555444333222111"
ck := ... // from USIM
ik := ... // from USIM
autn := ... // from USIM
netName := "WLAN"

// 1. Derive CK', IK' (RFC 9048 / TS 33.402)
ckPrime, ikPrime, _ := eapaka.DeriveCKPrimeIKPrime(ck, ik, netName, autn)

// 2. Derive Master Keys (K_encr, K_aut, MSK, EMSK)
keys := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)

fmt.Printf("MSK: %x\n", keys.MSK)
```

**Note on EAP-AKA' KDF**: `DeriveCKPrimeIKPrime` follows TS 33.402 Annex A.2 and matches RFC 9048 Appendix D test vectors. See `kdf_test.go` for details.

### Fast Re-authentication

Keep `MK` (EAP-AKA) or `K_re` (EAP-AKA') from full authentication, and derive a new MSK and EMSK on each fast re-authentication (RFC 4187 Section 7, RFC 9048 Section 3.3). `K_encr` and `K_aut` from full authentication stay in use.

```go
// EAP-AKA
full := eapaka.DeriveKeysAKA(identity, ck, ik)
reauth, err := eapaka.DeriveReauthKeysAKA(reauthID, counter, nonceS, full.MK)

// EAP-AKA'
fullPrime := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)
reauthPrime, err := eapaka.DeriveReauthKeysAKAPrime(reauthID, counter, nonceS, fullPrime.K_re)
```

`reauthID` is the fast re-authentication identity without terminating null characters, `counter` is the `AT_COUNTER` value, and `nonceS` is the 16-byte `AT_NONCE_S` value.

#### Encrypted Attributes (AT_ENCR_DATA)

`EncryptAttributes` appends `AT_PADDING` as needed and encrypts the attributes with AES-128-CBC. `DecryptAttributes` checks that `AT_PADDING` is last and zero-filled, and removes it (RFC 4187 Section 10.12). Use a new IV for every `AT_ENCR_DATA`.

```go
iv := eapaka.NewIV()
encrypted, err := eapaka.EncryptAttributes(full.K_encr, iv, []eapaka.Attribute{
	&eapaka.AtCounter{Counter: 1},
	&eapaka.AtNonceS{NonceS: nonceS},
	&eapaka.AtNextReauthId{Identity: nextReauthID},
})
attrs := []eapaka.Attribute{
	&eapaka.AtIv{IV: iv},
	&eapaka.AtEncrData{EncryptedData: encrypted},
	&eapaka.AtMac{},
}

// Receiving side (after verifying AT_MAC)
nested, err := eapaka.DecryptAttributes(full.K_encr, iv, encrypted)
```

`ParseAttributes` parses a bare sequence of attributes. Unknown attributes are returned as `*GenericAttribute`; `IsSkippable` tells whether such an attribute may be ignored (RFC 4187 Section 8.1).

#### MAC with NONCE_S

The MAC of EAP-Response/AKA-Reauthentication covers the packet followed by `NONCE_S` (RFC 4187 Section 9.8). Other messages use `CalculateAndSetMac` and `VerifyMac`.

```go
// Peer
err := resp.CalculateAndSetMacWithExtra(full.K_aut, nonceS)

// Server
ok, err := resp.VerifyMacWithExtra(full.K_aut, nonceS)
```

### MS-MPPE-Key Encryption

Encrypt and decrypt the `MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key` attributes for RADIUS (RFC 2548).

```go
// Split MSK into Send/Recv keys
sendKey := keys.MSK[0:32]
recvKey := keys.MSK[32:64]

// Encrypt keys (requires RADIUS shared secret and Request Authenticator)
secret := []byte("radius-secret")
reqAuth := ... // 16 bytes from RADIUS Access-Request

encSendKey, _ := eapaka.EncryptMPPEKey(sendKey, secret, reqAuth)
encRecvKey, _ := eapaka.EncryptMPPEKey(recvKey, secret, reqAuth)

// RADIUS client side: decrypt the attribute value (Salt + encrypted String)
decrypted, err := eapaka.DecryptMPPEKey(encRecvKey, secret, reqAuth)
```

`DecryptMPPEKey` does not check the Salt. Check that its most significant bit is set (`enc[0]&0x80 != 0`) and that it is unique within the Access-Accept yourself.

### AT_CHECKCODE

`ComputeCheckcode` hashes the EAP-Request/AKA-Identity and EAP-Response/AKA-Identity packets as transmitted, in order, with SHA-1 (EAP-AKA) or SHA-256 (EAP-AKA') (RFC 4187 Section 10.13, RFC 9048 Section 3.4.3). With no packets, it returns an empty checkcode.

```go
checkcode, err := eapaka.ComputeCheckcode(eapaka.TypeAKA, req1, resp1, req2, resp2)
attr := &eapaka.AtCheckcode{Checkcode: checkcode}
```

### Notification Codes

`AtNotification.Code` holds only the lower 14 bits. Use `NewNotification` and `FullCode` with the 16-bit codes of RFC 4187 Section 10.19, which include the S bit (0x8000) and the P bit (0x4000).

```go
attr := eapaka.NewNotification(eapaka.NotificationGeneralFailure) // S = 0, P = 1

if received.FullCode() == eapaka.NotificationSuccess {
	// ...
}
```

Constants: `NotificationGeneralFailureAfterAuth` (0), `NotificationTemporarilyDenied` (1026), `NotificationNotSubscribed` (1031), `NotificationGeneralFailure` (16384), `NotificationSuccess` (32768).

### Exported Parameters (Session-Id)

- `SessionIDAKA(rand, autn)`: EAP-AKA, `0x17 || RAND || AUTN` (RFC 5247 Appendix A)
- `SessionIDAKAPrime(rand, autn)` and `SessionIDAKAPrimeReauth(nonceS, mac)`: EAP-AKA' (RFC 9048 Section 6)
- `PeerIDFromAttributes` and `ServerIDAKAPrime`

### Parsing Options

`Parse` rejects `AT_BIDDING` in EAP-AKA' packets (RFC 9048 Section 4). A tester can accept such a packet to report the violation:

```go
pkt, err := eapaka.ParseWithOptions(data, eapaka.ParseOptions{AllowBiddingInAKAPrime: true})
ok, err := pkt.VerifyMac(kAut) // The MAC methods accept AT_BIDDING; Marshal still rejects it.
```

## Supported Attributes

**Note**: This library handles the attribute headers (Type and Length) and padding. For the attribute value (data), you must construct the byte slice yourself according to the RFC definitions and assign it to the corresponding field (e.g., `Rand`, `Autn`, `Identity`). For `AT_RAND` and `AT_AUTN`, pass only 16-byte `Rand`/`Autn`; the `Reserved(2)` bytes are handled internally.

- **Authentication**: `AT_RAND`, `AT_AUTN`, `AT_RES`, `AT_AUTS`, `AT_MAC`
- **Identity**: `AT_IDENTITY`, `AT_PERMANENT_ID_REQ`, `AT_ANY_ID_REQ`, `AT_FULLAUTH_ID_REQ`
- **Notification & Error**: `AT_NOTIFICATION`, `AT_CLIENT_ERROR_CODE`
- **Re-authentication**: `AT_COUNTER`, `AT_COUNTER_TOO_SMALL`, `AT_NONCE_S`, `AT_NEXT_PSEUDONYM`, `AT_NEXT_REAUTH_ID`
- **Encryption**: `AT_IV`, `AT_ENCR_DATA`, `AT_PADDING`
- **EAP-AKA' Extensions**: `AT_KDF`, `AT_KDF_INPUT`, `AT_BIDDING` (flags: `AtBiddingFlagAKAPrime`)
- **Others**: `AT_CHECKCODE`, `AT_RESULT_IND`, `AT_NONCE_MT`, `AT_VERSION_LIST`, `AT_SELECTED_VERSION`

## Test Vectors

The cryptographic helpers are tested against vectors generated from implementations independent of this library: hostap 2.12 (hostapd / wpa_supplicant) and the Python standard library. The vectors are in `testdata/vectors`. `tools/vectorgen` contains the generators and the instructions to regenerate and check them (`make -C tools/vectorgen check`).

## Changes in v0.2.0

Added APIs (no existing function or method was removed or changed in signature):

- Fast re-authentication keys: `ReauthKeys`, `DeriveReauthKeysAKA`, `DeriveReauthKeysAKAPrime`, and `AkaKeys.MK` (a new last field)
- AT_ENCR_DATA: `EncryptAttributes`, `DecryptAttributes`, `NewIV`, `ParseAttributes`, `IsSkippable`
- MAC with extra data: `Packet.CalculateAndSetMacWithExtra`, `Packet.VerifyMacWithExtra`
- `ComputeCheckcode`, `NewNotification`, `AtNotification.FullCode`, the `Notification*` constants, `SessionIDAKA`
- `DecryptMPPEKey`, `ParseOptions`, `ParseWithOptions`

Compatibility notes:

- `AkaKeys` has a new field, so unkeyed composite literals of `AkaKeys` no longer compile. Keyed literals and values returned by `DeriveKeysAKA` are unaffected.
- The MAC methods now calculate and verify the MAC of EAP-AKA' packets that contain `AT_BIDDING` instead of returning an error. `Marshal` and `Parse` still reject such packets.

## RFC Compliance Updates (2026-02-20)

The following behavior was updated to align with RFC 4187 / RFC 5448:

- `AT_RAND` and `AT_AUTN` now encode/decode the Value field as `Reserved(2) + RAND/AUTN(16)` (RFC 4187).
- `AT_PADDING` now validates strict RFC constraints:
  - Value length must be `2`, `6`, or `10` bytes (attribute total length `4`, `8`, or `12` bytes).
  - All bytes must be `0x00` on unmarshal.
- `AT_CHECKCODE` now validates size as `0`, `20` (EAP-AKA), or `32` (EAP-AKA').

Compatibility note:

- If you relied on previous non-compliant behavior, parsing/marshaling results may change.
- RFC-compliant peers should now interoperate correctly for `AT_RAND` / `AT_AUTN`.

## References

- [RFC 2548: Microsoft Vendor-specific RADIUS Attributes](https://www.rfc-editor.org/rfc/rfc2548)
- [RFC 3748: Extensible Authentication Protocol (EAP)](https://tools.ietf.org/html/rfc3748)
- [RFC 4187: EAP Method for 3rd Generation Authentication and Key Agreement (EAP-AKA)](https://tools.ietf.org/html/rfc4187)
- [RFC 5247: Extensible Authentication Protocol (EAP) Key Management Framework](https://www.rfc-editor.org/rfc/rfc5247)
- [RFC 9048: Improved Extensible Authentication Protocol Method for 3GPP Mobile Network Authentication and Key Agreement (EAP-AKA')](https://www.rfc-editor.org/rfc/rfc9048) (obsoletes RFC 5448)

## License

MIT
