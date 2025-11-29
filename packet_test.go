package eapaka_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/oyaguma3/go-eapaka"
)

func TestPacket_RoundTrip(t *testing.T) {
	// 1. Arrange: Create a complex packet
	original := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRand{Rand: make([]byte, 16)},
			&eapaka.AtAutn{Autn: make([]byte, 16)},
			&eapaka.AtMac{MAC: make([]byte, 16)},
			&eapaka.AtIdentity{Identity: "user@example.com"},
		},
	}
	// Fill some data
	for i := range original.Attributes[0].(*eapaka.AtRand).Rand {
		original.Attributes[0].(*eapaka.AtRand).Rand[i] = byte(i)
	}

	// 2. Act: Marshal and then Parse
	bin, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	parsed, err := eapaka.Parse(bin)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// 3. Assert: Compare
	// We need to allow unexported fields if any, but our structs are all exported.
	// However, cmp might need options for interfaces.
	// Actually, cmp handles interfaces well if the underlying types match.
	if diff := cmp.Diff(original, parsed); diff != "" {
		t.Errorf("Packet mismatch (-want +got):\n%s", diff)
	}
}

func TestPacket_Attributes(t *testing.T) {
	// Test specific complex attributes
	original := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 10,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeNotification,
		Attributes: []eapaka.Attribute{
			&eapaka.AtNotification{S: true, P: false, Code: 1026},
			&eapaka.AtCounter{Counter: 12345},
			&eapaka.AtClientErrorCode{Code: 1},
		},
	}

	bin, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	parsed, err := eapaka.Parse(bin)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if diff := cmp.Diff(original, parsed); diff != "" {
		t.Errorf("Packet mismatch (-want +got):\n%s", diff)
	}
}

func TestPacket_Success(t *testing.T) {
	original := &eapaka.Packet{
		Code:       eapaka.CodeSuccess,
		Identifier: 2,
	}
	bin, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	parsed, err := eapaka.Parse(bin)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if diff := cmp.Diff(original, parsed); diff != "" {
		t.Errorf("Packet mismatch (-want +got):\n%s", diff)
	}
}

func ExampleParse() {
	// Raw bytes example (EAP-Success: Code=3, ID=1, Len=4)
	raw := []byte{0x03, 0x01, 0x00, 0x04}

	pkt, _ := eapaka.Parse(raw)

	switch pkt.Code {
	case eapaka.CodeSuccess:
		fmt.Println("Auth Success")
	case eapaka.CodeRequest:
		if pkt.Type == eapaka.TypeAKA {
			fmt.Println("AKA Request")
		}
	}
	// Output: Auth Success
}
