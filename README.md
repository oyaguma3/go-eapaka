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
