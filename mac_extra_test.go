package eapaka

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestVerifyMacWithExtra_Packets は、hostap が計算した MAC（追加データあり・なし、
// HMAC-SHA1-128・HMAC-SHA-256-128）を検証でき、追加データや鍵が違えば失敗することを確かめる。
func TestVerifyMacWithExtra_Packets(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			ok, err := p.VerifyMacWithExtra(v.KAut, v.Extra)
			if err != nil {
				t.Fatalf("VerifyMacWithExtra: %v", err)
			}
			if !ok {
				t.Fatal("VerifyMacWithExtra = false, want true")
			}
			// 検証してもパケット（AT_MAC の値）は変わらない
			b, err := p.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Packet), b); diff != "" {
				t.Errorf("packet changed by VerifyMacWithExtra (-want +got):\n%s", diff)
			}

			wrongKey := bytes.Clone(v.KAut)
			wrongKey[0] ^= 0x01
			type mismatch struct {
				name  string
				kAut  []byte
				extra []byte
			}
			mismatches := []mismatch{{"wrong_key", wrongKey, v.Extra}}
			if len(v.Extra) == 0 {
				mismatches = append(mismatches, mismatch{"unexpected_extra", v.KAut, h("0f0e0d0c0b0a09080706050403020100")})
			} else {
				modified := bytes.Clone(v.Extra)
				modified[len(modified)-1] ^= 0x01
				mismatches = append(mismatches,
					mismatch{"missing_extra", v.KAut, nil},
					mismatch{"modified_extra", v.KAut, modified},
					mismatch{"truncated_extra", v.KAut, v.Extra[:len(v.Extra)-1]},
				)
			}
			for _, m := range mismatches {
				ok, err := p.VerifyMacWithExtra(m.kAut, m.extra)
				if err != nil {
					t.Fatalf("%s: VerifyMacWithExtra: %v", m.name, err)
				}
				if ok {
					t.Errorf("%s: VerifyMacWithExtra = true, want false", m.name)
				}
			}
		})
	}
}

// TestCalculateAndSetMacWithExtra_Packets は、AT_MAC を計算し直すと hostap の
// パケットと同じバイト列になることを確かめる。
func TestCalculateAndSetMacWithExtra_Packets(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			mac, err := p.findMacAttr()
			if err != nil {
				t.Fatalf("findMacAttr: %v", err)
			}
			mac.MAC = bytes.Repeat([]byte{0xff}, 16) // 古い値を壊しておく

			if err := p.CalculateAndSetMacWithExtra(v.KAut, v.Extra); err != nil {
				t.Fatalf("CalculateAndSetMacWithExtra: %v", err)
			}
			if diff := cmp.Diff([]byte(v.MAC), mac.MAC); diff != "" {
				t.Errorf("AT_MAC mismatch (-want +got):\n%s", diff)
			}
			b, err := p.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Packet), b); diff != "" {
				t.Errorf("packet mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMacWithExtra_NilAndEmptyExtra は、追加データの nil と空のスライスが同じ扱いになり、
// 既存の VerifyMac・CalculateAndSetMac が追加データなしと同じ結果になることを確かめる。
func TestMacWithExtra_NilAndEmptyExtra(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		if len(v.Extra) != 0 {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			for name, verify := range map[string]func() (bool, error){
				"VerifyMac":                 func() (bool, error) { return p.VerifyMac(v.KAut) },
				"VerifyMacWithExtra(nil)":   func() (bool, error) { return p.VerifyMacWithExtra(v.KAut, nil) },
				"VerifyMacWithExtra(empty)": func() (bool, error) { return p.VerifyMacWithExtra(v.KAut, []byte{}) },
			} {
				if ok, err := verify(); err != nil || !ok {
					t.Errorf("%s = %v, %v, want true, nil", name, ok, err)
				}
			}

			if err := p.CalculateAndSetMacWithExtra(v.KAut, []byte{}); err != nil {
				t.Fatalf("CalculateAndSetMacWithExtra: %v", err)
			}
			b, err := p.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Packet), b); diff != "" {
				t.Errorf("packet mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestReauthResponse_BuildAndVerify は、ピアが EAP-Response/AKA-Reauthentication を
// 一から組み立てる流れ（EncryptAttributes → CalculateAndSetMacWithExtra）で hostap と
// 同じバイト列になり、サーバ側が VerifyMacWithExtra で検証できることを確かめる。
func TestReauthResponse_BuildAndVerify(t *testing.T) {
	n := 0
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		if len(v.Extra) == 0 {
			continue
		}
		n++
		t.Run(v.Name, func(t *testing.T) {
			attrs, err := ParseAttributes(v.Plaintext)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if _, ok := attrs[len(attrs)-1].(*AtPadding); ok {
				attrs = attrs[:len(attrs)-1] // AT_PADDING は EncryptAttributes が付ける
			}
			encrypted, err := EncryptAttributes(v.KEncr, v.IV, attrs)
			if err != nil {
				t.Fatalf("EncryptAttributes: %v", err)
			}

			// ピア側: 組み立てて、NONCE_S を追加データにして MAC を付ける
			p := &Packet{
				Code:       CodeResponse,
				Identifier: v.Packet[1],
				Type:       vectorMethodType(t, v.Method),
				Subtype:    SubtypeReauthentication,
				Attributes: []Attribute{
					&AtIv{IV: v.IV},
					&AtEncrData{EncryptedData: encrypted},
					&AtMac{},
				},
			}
			if err := p.CalculateAndSetMacWithExtra(v.KAut, v.Extra); err != nil {
				t.Fatalf("CalculateAndSetMacWithExtra: %v", err)
			}
			b, err := p.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Packet), b); diff != "" {
				t.Fatalf("packet mismatch (-want +got):\n%s", diff)
			}

			// サーバ側: 受け取ったパケットを、送った NONCE_S で検証する
			received, err := Parse(b)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if ok, err := received.VerifyMacWithExtra(v.KAut, v.Extra); err != nil || !ok {
				t.Errorf("VerifyMacWithExtra = %v, %v, want true, nil", ok, err)
			}
		})
	}
	if n == 0 {
		t.Fatal("no vector with extra data")
	}
}

func TestMacWithExtra_Errors(t *testing.T) {
	kAut := make([]byte, 16)
	nonceS := make([]byte, 16)
	tests := []struct {
		name    string
		packet  *Packet
		wantErr string
	}{
		{
			name: "no_at_mac",
			packet: &Packet{
				Code: CodeResponse, Identifier: 1, Type: TypeAKA, Subtype: SubtypeReauthentication,
				Attributes: []Attribute{&AtCounter{Counter: 1}},
			},
			wantErr: "AT_MAC attribute not found",
		},
		{
			// EAP-Success には EAP-AKA の Type がないので MAC を計算できない
			name: "unsupported_type",
			packet: &Packet{
				Code: CodeSuccess, Identifier: 1,
				Attributes: []Attribute{&AtMac{MAC: make([]byte, 16)}},
			},
			wantErr: "unsupported EAP type for MAC calculation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.packet.CalculateAndSetMacWithExtra(kAut, nonceS); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("CalculateAndSetMacWithExtra error = %v, want containing %q", err, tt.wantErr)
			}
			if _, err := tt.packet.VerifyMacWithExtra(kAut, nonceS); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("VerifyMacWithExtra error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
