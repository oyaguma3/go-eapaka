# go-eapaka

`go-eapaka` is a Go library for **EAP-AKA (RFC 4187)** and **EAP-AKA' (RFC 5448)** protocols.
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

### Key Derivation (KDF)

Derive session keys for EAP-AKA (RFC 4187) and EAP-AKA' (RFC 5448).

```go
// EAP-AKA' Example
identity := "0555444333222111"
ck := ... // from USIM
ik := ... // from USIM
netName := "WLAN"

// 1. Derive CK', IK' (RFC 5448)
ckPrime, ikPrime := eapaka.DeriveCKPrimeIKPrime(ck, ik, netName)

// 2. Derive Master Keys (K_encr, K_aut, MSK, EMSK)
keys := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)

fmt.Printf("MSK: %x\n", keys.MSK)
```

**Note on EAP-AKA' KDF**: There is a known discrepancy between the RFC 5448 Appendix C test vectors and the output of `DeriveCKPrimeIKPrime`/`DeriveKeysAKAPrime`. This implementation matches the logic found in other major implementations (e.g., free5GC) and strictly follows the RFC text. See `kdf_test.go` for details.

### MS-MPPE-Key Encryption

Encrypt the `MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key` attributes for RADIUS.

```go
// Split MSK into Send/Recv keys
sendKey := keys.MSK[0:32]
recvKey := keys.MSK[32:64]

// Encrypt keys (requires RADIUS shared secret and Request Authenticator)
secret := []byte("radius-secret")
reqAuth := ... // 16 bytes from RADIUS Access-Request

encSendKey, _ := eapaka.EncryptMPPEKey(sendKey, secret, reqAuth)
encRecvKey, _ := eapaka.EncryptMPPEKey(recvKey, secret, reqAuth)
```

## Supported Attributes

**Note**: This library handles the attribute headers (Type and Length) and padding. For the attribute value (data), you must construct the byte slice yourself according to the RFC definitions and assign it to the corresponding field (e.g., `Rand`, `Autn`, `Identity`).

- **Authentication**: `AT_RAND`, `AT_AUTN`, `AT_RES`, `AT_AUTS`, `AT_MAC`
- **Identity**: `AT_IDENTITY`, `AT_PERMANENT_ID_REQ`, `AT_ANY_ID_REQ`, `AT_FULLAUTH_ID_REQ`
- **Notification & Error**: `AT_NOTIFICATION`, `AT_CLIENT_ERROR_CODE`
- **Re-authentication**: `AT_COUNTER`, `AT_COUNTER_TOO_SMALL`, `AT_NONCE_S`, `AT_NEXT_PSEUDONYM`, `AT_NEXT_REAUTH_ID`
- **Encryption**: `AT_IV`, `AT_ENCR_DATA`, `AT_PADDING`
- **EAP-AKA' Extensions**: `AT_KDF`, `AT_KDF_INPUT`, `AT_BIDDING`
- **Others**: `AT_CHECKCODE`, `AT_RESULT_IND`, `AT_NONCE_MT`, `AT_VERSION_LIST`, `AT_SELECTED_VERSION`

## References

- [RFC 3748: Extensible Authentication Protocol (EAP)](https://tools.ietf.org/html/rfc3748)
- [RFC 4187: EAP Method for 3rd Generation Authentication and Key Agreement (EAP-AKA)](https://tools.ietf.org/html/rfc4187)
- [RFC 5448: Improved EAP Method for 3rd Generation Authentication and Key Agreement (EAP-AKA')](https://tools.ietf.org/html/rfc5448)

## License

MIT
