package eapaka

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// challengeWithBidding は AT_BIDDING を含む EAP-Request/AKA-Challenge（Type は typ）を
// バイト列で組み立てる。Marshal は EAP-AKA' の AT_BIDDING を拒否するので手で組み立てる。
func challengeWithBidding(t *testing.T, typ uint8) []byte {
	t.Helper()
	bidding, err := (&AtBidding{Flags: AtBiddingFlagAKAPrime}).Marshal()
	if err != nil {
		t.Fatalf("AtBidding.Marshal: %v", err)
	}
	payload := append([]byte{typ, SubtypeChallenge, 0, 0}, bidding...)
	data := []byte{CodeRequest, 7, 0, byte(4 + len(payload))}
	return append(data, payload...)
}

func TestParseWithOptions_BiddingInAKAPrime(t *testing.T) {
	allow := ParseOptions{AllowBiddingInAKAPrime: true}
	tests := []struct {
		name    string
		typ     uint8
		opts    ParseOptions
		wantErr bool
	}{
		{"aka_prime_default", TypeAKAPrime, ParseOptions{}, true},
		{"aka_prime_allowed", TypeAKAPrime, allow, false},
		{"aka_default", TypeAKA, ParseOptions{}, false},
		{"aka_allowed", TypeAKA, allow, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := challengeWithBidding(t, tt.typ)
			p, err := ParseWithOptions(data, tt.opts)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "AT_BIDDING is only valid for EAP-AKA") {
					t.Fatalf("ParseWithOptions error = %v, want the AT_BIDDING error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseWithOptions: %v", err)
			}
			want := &Packet{
				Code:       CodeRequest,
				Identifier: 7,
				Type:       tt.typ,
				Subtype:    SubtypeChallenge,
				Attributes: []Attribute{&AtBidding{Flags: AtBiddingFlagAKAPrime}},
			}
			if diff := cmp.Diff(want, p); diff != "" {
				t.Errorf("packet mismatch (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("marshal_still_rejects", func(t *testing.T) {
		p, err := ParseWithOptions(challengeWithBidding(t, TypeAKAPrime), allow)
		if err != nil {
			t.Fatalf("ParseWithOptions: %v", err)
		}
		if _, err := p.Marshal(); err == nil {
			t.Error("Marshal accepted AT_BIDDING in an EAP-AKA' packet")
		}
	})
}

// TestParseWithOptions_SameAsParse は、AT_BIDDING のない入力では、Parse・既定の
// ParseWithOptions・AT_BIDDING を許す ParseWithOptions が同じ結果になることを確かめる。
func TestParseWithOptions_SameAsParse(t *testing.T) {
	inputs := map[string][]byte{
		"too_short":           {CodeRequest, 1, 0},
		"length_too_small":    {CodeRequest, 1, 0x00, 0x03},
		"success":             {CodeSuccess, 1, 0x00, 0x04},
		"success_with_data":   {CodeSuccess, 1, 0x00, 0x05, 0x00},
		"request_missing_eap": {CodeRequest, 1, 0x00, 0x04},
	}
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		inputs["packets/"+v.Name] = v.Packet
	}
	for _, v := range loadVectors[checkcodeVector](t, "checkcode.json") {
		for i, p := range v.Packets {
			inputs["checkcode/"+v.Name+"/"+strconv.Itoa(i)] = p
		}
	}

	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			want, wantErr := Parse(data)
			for _, opts := range []ParseOptions{{}, {AllowBiddingInAKAPrime: true}} {
				got, err := ParseWithOptions(data, opts)
				if (err == nil) != (wantErr == nil) {
					t.Fatalf("opts %+v: error = %v, Parse error = %v", opts, err, wantErr)
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("opts %+v: packet mismatch with Parse (-Parse +ParseWithOptions):\n%s", opts, diff)
				}
			}
		})
	}
}

// TestParseWithOptions_BiddingViolationMac は、hostap が意図的に組み立てた
// AT_BIDDING 入りの EAP-AKA' パケット（RFC 9048 §4 違反）を AllowBiddingInAKAPrime で
// 読み込み、MAC を検証・計算し直せることを確かめる。
func TestParseWithOptions_BiddingViolationMac(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets_bidding_violation.json") {
		t.Run(v.Name, func(t *testing.T) {
			if _, err := Parse(v.Packet); err == nil {
				t.Fatal("Parse accepted AT_BIDDING in an EAP-AKA' packet")
			}
			p, err := ParseWithOptions(v.Packet, ParseOptions{AllowBiddingInAKAPrime: true})
			if err != nil {
				t.Fatalf("ParseWithOptions: %v", err)
			}
			if p.Type != TypeAKAPrime {
				t.Fatalf("Type = %d, want %d", p.Type, TypeAKAPrime)
			}
			var bidding *AtBidding
			for _, a := range p.Attributes {
				if b, ok := a.(*AtBidding); ok {
					bidding = b
				}
			}
			if bidding == nil || !bidding.SupportsAKAPrime() {
				t.Fatalf("AT_BIDDING with the D bit not found: %#v", bidding)
			}

			// hostap の MAC を検証できる
			for name, verify := range map[string]func() (bool, error){
				"VerifyMac":          func() (bool, error) { return p.VerifyMac(v.KAut) },
				"VerifyMacWithExtra": func() (bool, error) { return p.VerifyMacWithExtra(v.KAut, v.Extra) },
			} {
				if ok, err := verify(); err != nil || !ok {
					t.Errorf("%s = %v, %v, want true, nil", name, ok, err)
				}
			}
			wrongKey := bytes.Clone(v.KAut)
			wrongKey[0] ^= 0x01
			if ok, err := p.VerifyMac(wrongKey); err != nil || ok {
				t.Errorf("VerifyMac with a wrong key = %v, %v, want false, nil", ok, err)
			}

			// 計算し直すと hostap の AT_MAC と一致する
			mac, err := p.findMacAttr()
			if err != nil {
				t.Fatalf("findMacAttr: %v", err)
			}
			mac.MAC = bytes.Repeat([]byte{0xff}, 16)
			if err := p.CalculateAndSetMac(v.KAut); err != nil {
				t.Fatalf("CalculateAndSetMac: %v", err)
			}
			if diff := cmp.Diff([]byte(v.MAC), mac.MAC); diff != "" {
				t.Errorf("AT_MAC mismatch (-want +got):\n%s", diff)
			}

			// Marshal は AT_BIDDING を拒否したまま
			if _, err := p.Marshal(); err == nil {
				t.Error("Marshal accepted AT_BIDDING in an EAP-AKA' packet")
			}
		})
	}
}
