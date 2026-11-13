package eapaka

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsSkippable(t *testing.T) {
	tests := []struct {
		typ  AttributeType
		want bool
	}{
		{0, false},
		{AT_RAND, false},
		{AT_PADDING, false},
		{AT_KDF, false},
		{127, false},
		{128, true},
		{AT_IV, true},
		{AT_ENCR_DATA, true},
		{AT_BIDDING, true},
		{255, true},
	}
	for _, tt := range tests {
		if got := IsSkippable(tt.typ); got != tt.want {
			t.Errorf("IsSkippable(%d) = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

func TestNewIV(t *testing.T) {
	a, b := NewIV(), NewIV()
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("NewIV length = %d, %d, want 16", len(a), len(b))
	}
	if bytes.Equal(a, b) {
		t.Errorf("NewIV returned the same value twice: %x", a)
	}
}

func TestParseAttributes(t *testing.T) {
	nonce := h("000102030405060708090a0b0c0d0e0f")
	tests := []struct {
		name string
		in   []byte
		want []Attribute
	}{
		{name: "empty", in: nil, want: nil},
		{
			name: "counter_and_nonce",
			in:   h("13010005" + "15050000000102030405060708090a0b0c0d0e0f"),
			want: []Attribute{&AtCounter{Counter: 5}, &AtNonceS{NonceS: nonce}},
		},
		{
			name: "next_pseudonym_and_padding",
			in:   h("840300083273376168366e39" + "06010000"),
			want: []Attribute{&AtNextPseudonym{Pseudonym: "2s7ah6n9"}, &AtPadding{Length: 2}},
		},
		{
			name: "unknown_non_skippable",
			in:   h("63010102"),
			want: []Attribute{&GenericAttribute{AttrType: 99, Data: []byte{1, 2}}},
		},
		{
			name: "unknown_skippable",
			in:   h("c8010304"),
			want: []Attribute{&GenericAttribute{AttrType: 200, Data: []byte{3, 4}}},
		},
		{
			// 入れ子の属性の文脈は判定しないので、AT_BIDDING もそのまま返す
			name: "bidding",
			in:   h("88018000"),
			want: []Attribute{&AtBidding{Flags: AtBiddingFlagAKAPrime}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAttributes(tt.in)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseAttributes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseAttributes_Errors(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantErr string
	}{
		{"header_truncated", h("13010001" + "13"), "attribute header truncated"},
		{"length_zero", h("13000001"), "attribute length zero"},
		{"length_overflow", h("13020001"), "length overflow"},
		{"invalid_known_attribute", h("15010000"), "invalid AT_NONCE_S length"},
		{"padding_not_zero", h("06010001"), "AT_PADDING bytes must be zero"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAttributes(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseAttributes error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestEncryptAttributes_Vectors は、hostap が作った平文の属性を暗号化すると
// hostap の暗号文と一致することを確かめる（AT_PADDING の付け方を含む）。
func TestEncryptAttributes_Vectors(t *testing.T) {
	for _, v := range loadVectors[encrDataVector](t, "encr_data.json") {
		t.Run(v.Name, func(t *testing.T) {
			attrs, err := ParseAttributes(v.Attributes)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			got, err := EncryptAttributes(v.KEncr, v.IV, attrs)
			if err != nil {
				t.Fatalf("EncryptAttributes: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Ciphertext), got); diff != "" {
				t.Errorf("ciphertext mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecryptAttributes_Vectors(t *testing.T) {
	for _, v := range loadVectors[encrDataVector](t, "encr_data.json") {
		t.Run(v.Name, func(t *testing.T) {
			ciphertext := bytes.Clone(v.Ciphertext)
			got, err := DecryptAttributes(v.KEncr, v.IV, ciphertext)
			if err != nil {
				t.Fatalf("DecryptAttributes: %v", err)
			}
			want, err := ParseAttributes(v.Attributes)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("attributes mismatch (-want +got):\n%s", diff)
			}
			if !bytes.Equal(ciphertext, v.Ciphertext) {
				t.Error("DecryptAttributes modified the ciphertext")
			}
		})
	}
}

// TestEncryptDecryptAttributes_Packets は、hostap が組み立てたパケットの
// AT_ENCR_DATA を復号でき、同じ IV で暗号化し直すと元の暗号文に戻ることを確かめる。
func TestEncryptDecryptAttributes_Packets(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		if len(v.IV) == 0 {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var encr *AtEncrData
			for _, a := range p.Attributes {
				if e, ok := a.(*AtEncrData); ok {
					encr = e
				}
			}
			if encr == nil {
				t.Fatal("AT_ENCR_DATA not found")
			}

			got, err := DecryptAttributes(v.KEncr, v.IV, encr.EncryptedData)
			if err != nil {
				t.Fatalf("DecryptAttributes: %v", err)
			}
			// hostap の平文は AT_PADDING を含むので、それを除いたものと比べる
			want, err := ParseAttributes(v.Plaintext)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if _, ok := want[len(want)-1].(*AtPadding); ok {
				want = want[:len(want)-1]
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("attributes mismatch (-want +got):\n%s", diff)
			}

			ct, err := EncryptAttributes(v.KEncr, v.IV, got)
			if err != nil {
				t.Fatalf("EncryptAttributes: %v", err)
			}
			if diff := cmp.Diff(encr.EncryptedData, ct); diff != "" {
				t.Errorf("re-encrypted data mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecryptAttributes_ReauthRequestContents は、hostap が作った
// EAP-Request/AKA-Reauthentication の AT_ENCR_DATA の中身を、手で書いた期待値と比べる。
func TestDecryptAttributes_ReauthRequestContents(t *testing.T) {
	want := map[string][]Attribute{
		"aka_reauth_request": {
			&AtCounter{Counter: 1},
			&AtNonceS{NonceS: h("0f0e0d0c0b0a09080706050403020100")},
			&AtNextReauthId{Identity: "4next0002@wlan.mnc001.mcc001.3gppnetwork.org"},
		},
		"aka_prime_reauth_request": {
			&AtCounter{Counter: 1},
			&AtNonceS{NonceS: h("0f0e0d0c0b0a09080706050403020100")},
			&AtNextReauthId{Identity: "8next0002@wlan.mnc001.mcc001.3gppnetwork.org"},
		},
	}
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		w, ok := want[v.Name]
		if !ok {
			continue
		}
		delete(want, v.Name)
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
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
			if diff := cmp.Diff(w, got); diff != "" {
				t.Errorf("attributes mismatch (-want +got):\n%s", diff)
			}
		})
	}
	for name := range want {
		t.Errorf("vector %q not found", name)
	}
}

func TestEncryptDecryptAttributes_RoundTrip(t *testing.T) {
	kEncr := h("000102030405060708090a0b0c0d0e0f")
	nonce := h("0f0e0d0c0b0a09080706050403020100")
	tests := []struct {
		name    string
		attrs   []Attribute
		wantLen int // 暗号文の長さ（AT_PADDING を含む）
	}{
		{"counter_pad12", []Attribute{&AtCounter{Counter: 1}}, 16},
		{"counter_nonce_pad8", []Attribute{&AtCounter{Counter: 1}, &AtNonceS{NonceS: nonce}}, 32},
		{"pseudonym_pad4", []Attribute{&AtNextPseudonym{Pseudonym: "2s7ah6n9"}}, 16},
		{"counter_nonce_reauth_nopad", []Attribute{
			&AtCounter{Counter: 2},
			&AtNonceS{NonceS: nonce},
			&AtNextReauthId{Identity: "4reauth01@example"},
		}, 48},
		{"counter_too_small", []Attribute{&AtCounter{Counter: 3}, &AtCounterTooSmall{}}, 16},
		{"unknown_skippable", []Attribute{
			&AtCounter{Counter: 1},
			&GenericAttribute{AttrType: 200, Data: []byte{1, 2}},
		}, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv := NewIV()
			ct, err := EncryptAttributes(kEncr, iv, tt.attrs)
			if err != nil {
				t.Fatalf("EncryptAttributes: %v", err)
			}
			if len(ct) != tt.wantLen {
				t.Errorf("ciphertext length = %d, want %d", len(ct), tt.wantLen)
			}
			got, err := DecryptAttributes(kEncr, iv, ct)
			if err != nil {
				t.Fatalf("DecryptAttributes: %v", err)
			}
			if diff := cmp.Diff(tt.attrs, got); diff != "" {
				t.Errorf("round trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// oddLengthAttribute は長さが 4 の倍数でないバイト列を返す、不正な Attribute の実装。
type oddLengthAttribute struct{}

func (oddLengthAttribute) Type() AttributeType      { return 200 }
func (oddLengthAttribute) Marshal() ([]byte, error) { return []byte{200, 1, 0}, nil }
func (oddLengthAttribute) Unmarshal([]byte) error   { return nil }

func TestEncryptAttributes_Errors(t *testing.T) {
	key, iv := make([]byte, 16), make([]byte, 16)
	counter := []Attribute{&AtCounter{Counter: 1}}
	tests := []struct {
		name    string
		kEncr   []byte
		iv      []byte
		attrs   []Attribute
		wantErr string
	}{
		{"short_key", make([]byte, 15), iv, counter, "K_encr must be 16 bytes"},
		{"long_key", make([]byte, 32), iv, counter, "K_encr must be 16 bytes"},
		{"short_iv", key, make([]byte, 15), counter, "IV must be 16 bytes"},
		{"long_iv", key, make([]byte, 17), counter, "IV must be 16 bytes"},
		{"no_attributes", key, iv, nil, "no attributes to encrypt"},
		{"padding_given", key, iv, []Attribute{&AtCounter{Counter: 1}, &AtPadding{Length: 10}}, "AT_PADDING must not be given"},
		{"marshal_error", key, iv, []Attribute{&AtNonceS{NonceS: make([]byte, 15)}}, "AT_NONCE_S must be 16 bytes"},
		{"bad_marshaled_length", key, iv, []Attribute{oddLengthAttribute{}}, "not a positive multiple of 4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptAttributes(tt.kEncr, tt.iv, tt.attrs)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("EncryptAttributes error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// cbcEncryptRaw は平文をそのまま AES-128-CBC で暗号化する（不正な平文を作るテスト用）。
func cbcEncryptRaw(t *testing.T, kEncr, iv, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kEncr)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out
}

func TestDecryptAttributes_Errors(t *testing.T) {
	kEncr := h("000102030405060708090a0b0c0d0e0f")
	iv := h("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	// AT_COUNTER（4 バイト）＋ AT_PADDING（12 バイト）
	valid := cbcEncryptRaw(t, kEncr, iv, h("13010001"+"060300000000000000000000"))
	enc := func(plainHex string) []byte { return cbcEncryptRaw(t, kEncr, iv, h(plainHex)) }

	tests := []struct {
		name       string
		kEncr      []byte
		iv         []byte
		ciphertext []byte
		wantErr    string
	}{
		{"short_key", kEncr[:15], iv, valid, "K_encr must be 16 bytes"},
		{"short_iv", kEncr, iv[:8], valid, "IV must be 16 bytes"},
		{"empty", kEncr, iv, nil, "not a positive multiple of 16"},
		{"not_multiple_of_16", kEncr, iv, valid[:15], "not a positive multiple of 16"},
		{"not_multiple_of_16_long", kEncr, iv, append(bytes.Clone(valid), 0), "not a positive multiple of 16"},
		{"padding_not_zero", kEncr, iv, enc("13010001" + "060300000000000000000001"), "AT_PADDING bytes must be zero"},
		{"padding_not_last", kEncr, iv, enc("060300000000000000000000" + "13010001"), "AT_PADDING is not the last attribute"},
		{"padding_too_long", kEncr, iv, enc("0604" + "0000000000000000000000000000"), "invalid AT_PADDING length"},
		{"nested_length_zero", kEncr, iv, enc("13000001" + "000000000000000000000000"), "attribute length zero"},
		{"nested_length_overflow", kEncr, iv, enc("13050001" + "000000000000000000000000"), "length overflow"},
		{"nested_invalid_attribute", kEncr, iv, enc("15010000" + "060300000000000000000000"), "invalid AT_NONCE_S length"},
		{"wrong_key", h("ffeeddccbbaa99887766554433221100"), iv, valid, "parse decrypted AT_ENCR_DATA"},
		{"wrong_iv", kEncr, h("00000000000000000000000000000000"), valid, "parse decrypted AT_ENCR_DATA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptAttributes(tt.kEncr, tt.iv, tt.ciphertext)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecryptAttributes error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
