package eapaka_test

import (
	"bytes"
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

func TestParse_RFCFormattedRandAutn(t *testing.T) {
	rand := make([]byte, 16)
	autn := make([]byte, 16)
	for i := 0; i < 16; i++ {
		rand[i] = byte(i + 1)
		autn[i] = byte(0xA0 + i)
	}

	// AT_RAND: Type(1) + Len(1=5) + Reserved(2) + RAND(16)
	atRand := append([]byte{byte(eapaka.AT_RAND), 0x05, 0x00, 0x00}, rand...)
	// AT_AUTN: Type(1) + Len(1=5) + Reserved(2) + AUTN(16)
	atAutn := append([]byte{byte(eapaka.AT_AUTN), 0x05, 0x00, 0x00}, autn...)

	payload := []byte{eapaka.TypeAKA, eapaka.SubtypeChallenge, 0x00, 0x00}
	payload = append(payload, atRand...)
	payload = append(payload, atAutn...)

	length := 4 + len(payload)
	raw := []byte{eapaka.CodeRequest, 0x22, byte(length >> 8), byte(length)}
	raw = append(raw, payload...)

	parsed, err := eapaka.Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(parsed.Attributes) != 2 {
		t.Fatalf("unexpected attribute count: want=2 got=%d", len(parsed.Attributes))
	}

	parsedRand, ok := parsed.Attributes[0].(*eapaka.AtRand)
	if !ok {
		t.Fatalf("unexpected attr[0] type: %T", parsed.Attributes[0])
	}
	if !bytes.Equal(parsedRand.Rand, rand) {
		t.Fatalf("unexpected parsed RAND:\nwant=%x\ngot =%x", rand, parsedRand.Rand)
	}

	parsedAutn, ok := parsed.Attributes[1].(*eapaka.AtAutn)
	if !ok {
		t.Fatalf("unexpected attr[1] type: %T", parsed.Attributes[1])
	}
	if !bytes.Equal(parsedAutn.Autn, autn) {
		t.Fatalf("unexpected parsed AUTN:\nwant=%x\ngot =%x", autn, parsedAutn.Autn)
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
			&eapaka.AtBidding{Flags: eapaka.AtBiddingFlagAKAPrime},
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

func TestParse_InvalidPackets(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "length_too_small",
			data: []byte{eapaka.CodeRequest, 1, 0x00, 0x03},
		},
		{
			name: "success_with_payload",
			data: []byte{eapaka.CodeSuccess, 1, 0x00, 0x05, 0x00},
		},
		{
			name: "request_missing_type",
			data: []byte{eapaka.CodeRequest, 1, 0x00, 0x04},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := eapaka.Parse(tc.data); err == nil {
				t.Fatal("expected error for invalid packet")
			}
		})
	}
}

func TestPacket_Marshal_UnsupportedType(t *testing.T) {
	pkt := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       0,
	}

	if _, err := pkt.Marshal(); err == nil {
		t.Fatal("expected error for unsupported type in request/response")
	}
}

func TestPacket_Marshal_ATBiddingWithAKAPrime(t *testing.T) {
	pkt := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKAPrime,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtBidding{Flags: eapaka.AtBiddingFlagAKAPrime},
		},
	}

	if _, err := pkt.Marshal(); err == nil {
		t.Fatal("expected error for AT_BIDDING in AKA'")
	}
}

func TestParse_ATBiddingWithAKAPrime(t *testing.T) {
	bidding, err := (&eapaka.AtBidding{Flags: eapaka.AtBiddingFlagAKAPrime}).Marshal()
	if err != nil {
		t.Fatalf("failed to marshal AT_BIDDING: %v", err)
	}

	payload := append([]byte{eapaka.TypeAKAPrime, eapaka.SubtypeChallenge, 0x00, 0x00}, bidding...)
	data := make([]byte, 0, 4+len(payload))
	data = append(data, eapaka.CodeRequest, 1, 0x00, byte(4+len(payload)))
	data = append(data, payload...)

	if _, err := eapaka.Parse(data); err == nil {
		t.Fatal("expected error for AT_BIDDING in AKA' packet")
	}
}

func TestAtBiddingFlags(t *testing.T) {
	attr := &eapaka.AtBidding{}
	if attr.SupportsAKAPrime() {
		t.Fatal("expected AKA' support to be disabled by default")
	}

	attr.SetAKAPrime(true)
	if !attr.SupportsAKAPrime() {
		t.Fatal("expected AKA' support to be enabled")
	}

	attr.SetAKAPrime(false)
	if attr.SupportsAKAPrime() {
		t.Fatal("expected AKA' support to be disabled")
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
