package eapaka

import (
	"bytes"
	"strings"
	"testing"
)

// checkcodePackets は checkcode.json のケースのパケットを [][]byte で返す。
func checkcodePackets(v checkcodeVector) [][]byte {
	pkts := make([][]byte, len(v.Packets))
	for i, p := range v.Packets {
		pkts[i] = bytes.Clone(p)
	}
	return pkts
}

func TestComputeCheckcode_Vectors(t *testing.T) {
	for _, v := range loadVectors[checkcodeVector](t, "checkcode.json") {
		t.Run(v.Name, func(t *testing.T) {
			got, err := ComputeCheckcode(vectorMethodType(t, v.Method), checkcodePackets(v)...)
			if err != nil {
				t.Fatalf("ComputeCheckcode: %v", err)
			}
			if !bytes.Equal(got, v.Checkcode) {
				t.Errorf("checkcode = %x, want %x", got, []byte(v.Checkcode))
			}
			if got == nil {
				t.Error("checkcode is nil, want a non-nil (possibly empty) slice")
			}

			// そのまま AT_CHECKCODE に入れて送受信できる
			b, err := (&AtCheckcode{Checkcode: got}).Marshal()
			if err != nil {
				t.Fatalf("AtCheckcode.Marshal: %v", err)
			}
			attrs, err := ParseAttributes(b)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if cc, ok := attrs[0].(*AtCheckcode); !ok || !bytes.Equal(cc.Checkcode, got) {
				t.Errorf("parsed AT_CHECKCODE = %#v, want checkcode %x", attrs[0], got)
			}
		})
	}
}

func TestComputeCheckcode_Errors(t *testing.T) {
	vectors := loadVectors[checkcodeVector](t, "checkcode.json")
	base := func(name string) [][]byte {
		return checkcodePackets(findVector(t, vectors, name, func(v checkcodeVector) string { return v.Name }))
	}
	modify := func(name string, f func(pkts [][]byte) [][]byte) [][]byte {
		return f(base(name))
	}

	tests := []struct {
		name       string
		methodType uint8
		packets    [][]byte
		wantErr    string
	}{
		{"unsupported_type", 18, base("aka_three_rounds"), "unsupported EAP type 18"},
		{"unsupported_type_no_packets", 18, nil, "unsupported EAP type 18"},
		{"odd_number_of_packets", TypeAKA, base("aka_three_rounds")[:3], "request/response pairs"},
		{"wrong_method_type", TypeAKAPrime, base("aka_three_rounds"), "type/subtype is 23/5, want 50/5"},
		{"not_identity_subtype", TypeAKA, modify("aka_any_id_pseudonym", func(p [][]byte) [][]byte {
			p[0][5] = SubtypeChallenge
			return p
		}), "type/subtype is 23/1, want 23/5"},
		{"response_first", TypeAKA, modify("aka_any_id_pseudonym", func(p [][]byte) [][]byte {
			return [][]byte{p[1], p[0]}
		}), "code is 2, want 1"},
		{"identifier_mismatch", TypeAKAPrime, modify("aka_prime_three_rounds", func(p [][]byte) [][]byte {
			p[3][1] ^= 0xff
			return p
		}), "packet 3: identifier"},
		{"length_mismatch", TypeAKA, modify("aka_any_id_pseudonym", func(p [][]byte) [][]byte {
			p[1] = append(p[1], 0) // EAP ヘッダの Length は変えずに 1 バイト足す
			return p
		}), "does not match the packet size"},
		{"too_short", TypeAKA, modify("aka_any_id_pseudonym", func(p [][]byte) [][]byte {
			p[0] = p[0][:7]
			return p
		}), "too short"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ComputeCheckcode(tt.methodType, tt.packets...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ComputeCheckcode error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
