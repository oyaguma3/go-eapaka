package eapaka

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// rawMacVectorFiles は、受信したバイト列での MAC の計算・検証を確かめるベクタファイル。
var rawMacVectorFiles = []string{
	"packets.json",
	"packets_bidding_violation.json",
	"packets_reserved_nonzero.json",
}

func TestVerifyMacRaw_Vectors(t *testing.T) {
	for _, file := range rawMacVectorFiles {
		for _, v := range loadVectors[packetVector](t, file) {
			t.Run(file+"/"+v.Name, func(t *testing.T) {
				if ok, err := VerifyMacRaw(v.Packet, v.KAut, v.Extra); err != nil || !ok {
					t.Fatalf("VerifyMacRaw = %v, %v, want true, nil", ok, err)
				}
				// EAP ヘッダの Length より後ろのバイトは無視する
				if ok, err := VerifyMacRaw(append(bytes.Clone(v.Packet), 0xff, 0xff), v.KAut, v.Extra); err != nil || !ok {
					t.Errorf("VerifyMacRaw with trailing bytes = %v, %v, want true, nil", ok, err)
				}

				wrongKey := bytes.Clone(v.KAut)
				wrongKey[0] ^= 0x01
				mismatches := map[string][2][]byte{"wrong_key": {wrongKey, v.Extra}}
				if len(v.Extra) == 0 {
					mismatches["unexpected_extra"] = [2][]byte{v.KAut, h("0f0e0d0c0b0a09080706050403020100")}
				} else {
					mismatches["missing_extra"] = [2][]byte{v.KAut, nil}
				}
				for name, m := range mismatches {
					if ok, err := VerifyMacRaw(v.Packet, m[0], m[1]); err != nil || ok {
						t.Errorf("%s: VerifyMacRaw = %v, %v, want false, nil", name, ok, err)
					}
				}
			})
		}
	}
}

func TestCalculateAndSetMacRaw_Vectors(t *testing.T) {
	for _, file := range rawMacVectorFiles {
		for _, v := range loadVectors[packetVector](t, file) {
			t.Run(file+"/"+v.Name, func(t *testing.T) {
				data := bytes.Clone(v.Packet)
				// AT_MAC は最後の属性（値フィールドの後ろ 16 バイトが MAC）
				copy(data[len(data)-16:], bytes.Repeat([]byte{0xff}, 16))
				if err := CalculateAndSetMacRaw(data, v.KAut, v.Extra); err != nil {
					t.Fatalf("CalculateAndSetMacRaw: %v", err)
				}
				if diff := cmp.Diff([]byte(v.Packet), data); diff != "" {
					t.Errorf("packet mismatch (-want +got):\n%s", diff)
				}
			})
		}
	}
}

// TestMacRaw_ReservedNonZero は、予約フィールドを 0 以外にした hostap のパケットについて、
// 構造体から組み立て直す VerifyMacWithExtra は一致しないが、VerifyMacRaw は一致すること、
// 中身は通常どおり解析・復号できることを確かめる。
func TestMacRaw_ReservedNonZero(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets_reserved_nonzero.json") {
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			// 予約フィールドは解析で捨てられるので、組み立て直したパケットは元と違う
			if b, err := p.Marshal(); err != nil || bytes.Equal(b, v.Packet) {
				t.Fatalf("re-marshaled packet unexpectedly equals the original (err %v)", err)
			}
			if ok, err := p.VerifyMacWithExtra(v.KAut, v.Extra); err != nil || ok {
				t.Errorf("VerifyMacWithExtra = %v, %v, want false, nil", ok, err)
			}
			if ok, err := VerifyMacRaw(v.Packet, v.KAut, v.Extra); err != nil || !ok {
				t.Errorf("VerifyMacRaw = %v, %v, want true, nil", ok, err)
			}

			if len(v.IV) == 0 {
				return
			}
			var iv, encr []byte
			for _, a := range p.Attributes {
				switch a := a.(type) {
				case *AtIv:
					iv = a.IV
				case *AtEncrData:
					encr = a.EncryptedData
				}
			}
			got, err := DecryptAttributes(v.KEncr, iv, encr)
			if err != nil {
				t.Fatalf("DecryptAttributes: %v", err)
			}
			want, err := ParseAttributes(v.Plaintext)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if diff := cmp.Diff(want[:len(want)-1], got); diff != "" { // 最後は AT_PADDING
				t.Errorf("attributes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMacRaw_AtMacReservedNonZero は、AT_MAC 自身の Reserved が 0 以外のとき、
// RFC 4187 §10.15（値フィールド全体を 0 にする）と hostap（MAC 部分だけを 0 にする）の
// どちらの方法で計算した MAC も VerifyMacRaw が受け付けることを確かめる。
func TestMacRaw_AtMacReservedNonZero(t *testing.T) {
	v := findVector(t, loadVectors[packetVector](t, "packets.json"), "aka_reauth_response",
		func(v packetVector) string { return v.Name })
	if vectorMethodType(t, v.Method) != TypeAKA || len(v.Extra) == 0 {
		t.Fatal("unexpected vector")
	}
	reservedOff := len(v.Packet) - 18 // AT_MAC の値フィールド（Reserved 2 ＋ MAC 16）

	t.Run("rfc4187", func(t *testing.T) {
		data := bytes.Clone(v.Packet)
		data[reservedOff], data[reservedOff+1] = 0xab, 0xcd
		if err := CalculateAndSetMacRaw(data, v.KAut, v.Extra); err != nil {
			t.Fatalf("CalculateAndSetMacRaw: %v", err)
		}
		// RFC 4187 では Reserved も 0 にして計算するので、MAC は Reserved が 0 のときと同じ
		if !bytes.Equal(data[reservedOff+2:], v.MAC) {
			t.Errorf("MAC = %x, want %x", data[reservedOff+2:], []byte(v.MAC))
		}
		if data[reservedOff] != 0xab || data[reservedOff+1] != 0xcd {
			t.Error("CalculateAndSetMacRaw changed the Reserved field of AT_MAC")
		}
		if ok, err := VerifyMacRaw(data, v.KAut, v.Extra); err != nil || !ok {
			t.Errorf("VerifyMacRaw = %v, %v, want true, nil", ok, err)
		}
	})

	t.Run("hostap", func(t *testing.T) {
		data := bytes.Clone(v.Packet)
		data[reservedOff], data[reservedOff+1] = 0xab, 0xcd
		// hostap と同じく、MAC 部分だけを 0 にして HMAC-SHA1-128 を計算する
		clear(data[reservedOff+2:])
		mac := hmac.New(sha1.New, v.KAut)
		mac.Write(data)
		mac.Write(v.Extra)
		copy(data[reservedOff+2:], mac.Sum(nil)[:16])
		if bytes.Equal(data[reservedOff+2:], v.MAC) {
			t.Fatal("the hostap-style MAC unexpectedly equals the RFC 4187 one")
		}
		if ok, err := VerifyMacRaw(data, v.KAut, v.Extra); err != nil || !ok {
			t.Errorf("VerifyMacRaw = %v, %v, want true, nil", ok, err)
		}
	})

	t.Run("invalid_mac", func(t *testing.T) {
		data := bytes.Clone(v.Packet)
		data[reservedOff], data[reservedOff+1] = 0xab, 0xcd
		data[len(data)-1] ^= 0x01
		if ok, err := VerifyMacRaw(data, v.KAut, v.Extra); err != nil || ok {
			t.Errorf("VerifyMacRaw = %v, %v, want false, nil", ok, err)
		}
	})
}

func TestMacRaw_Errors(t *testing.T) {
	kAut := make([]byte, 16)
	mac := "0b050000" + "00000000000000000000000000000000"
	// 属性ヘッダの途中で終わるパケット: 1 バイト足し、EAP ヘッダの Length も 1 増やす
	truncated := append(akaRequest(TypeAKA, mac), 0x13)
	truncated[3]++
	tests := []struct {
		name     string
		data     []byte
		want     error // errors.Is で true になるもの（nil なら確かめない）
		wantAttr AttributeType
	}{
		{"too_short", []byte{CodeRequest, 1, 0}, ErrMalformedPacket, 0},
		{"length_too_small", []byte{CodeRequest, 1, 0, 3}, ErrMalformedPacket, 0},
		{"length_beyond_data", akaRequest(TypeAKA, mac)[:20], ErrMalformedPacket, 0},
		{"missing_type", []byte{CodeRequest, 1, 0, 4}, ErrMalformedPacket, 0},
		{"short_aka_header", []byte{CodeRequest, 1, 0, 6, TypeAKA, SubtypeChallenge}, ErrMalformedPacket, 0},
		{"success_packet", []byte{CodeSuccess, 1, 0, 4}, nil, 0},
		{"unsupported_type", akaRequest(18, mac), nil, 0},
		{"no_at_mac", akaRequest(TypeAKA, "13010001"), ErrMacNotFound, 0},
		{"multiple_at_mac", akaRequest(TypeAKA, mac+mac), ErrMalformedPacket, 0},
		{"at_mac_wrong_length", akaRequest(TypeAKA, "0b040000"+"000000000000000000000000"), ErrMalformedAttribute, AT_MAC},
		{"attribute_length_zero", akaRequest(TypeAKA, "13000001"+mac), ErrMalformedAttribute, 0},
		{"attribute_length_overflow", akaRequest(TypeAKA, mac+"13020001"), ErrMalformedAttribute, 0},
		{"attribute_header_truncated", truncated, ErrMalformedAttribute, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := VerifyMacRaw(tt.data, kAut, nil); err == nil {
				t.Fatal("VerifyMacRaw: expected an error")
			} else if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("VerifyMacRaw error = %v, want %v", err, tt.want)
			} else if attrErr, ok := errors.AsType[*AttributeError](err); tt.wantAttr != 0 && (!ok || attrErr.Type != tt.wantAttr) {
				t.Errorf("VerifyMacRaw error = %v, want an AttributeError for type %d", err, tt.wantAttr)
			}

			data := bytes.Clone(tt.data)
			if err := CalculateAndSetMacRaw(data, kAut, nil); err == nil {
				t.Fatal("CalculateAndSetMacRaw: expected an error")
			} else if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("CalculateAndSetMacRaw error = %v, want %v", err, tt.want)
			}
			if !bytes.Equal(data, tt.data) {
				t.Error("CalculateAndSetMacRaw modified data on error")
			}
		})
	}
}
