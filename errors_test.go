package eapaka

import (
	"errors"
	"testing"
)

// akaRequest は Type が typ の EAP-Request/AKA-Reauthentication のヘッダに attrHex をつないだパケットを返す。
func akaRequest(typ uint8, attrHex string) []byte {
	attrs := h(attrHex)
	pkt := []byte{CodeRequest, 1, 0, byte(8 + len(attrs)), typ, SubtypeReauthentication, 0, 0}
	return append(pkt, attrs...)
}

// TestSentinelErrors は、受信データの異常に対して errors.Is で sentinel error を判定でき、
// エラーメッセージが従来と同じであることを確かめる。
func TestSentinelErrors(t *testing.T) {
	kEncr := h("000102030405060708090a0b0c0d0e0f")
	iv := h("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	decrypt := func(plainHex string) func() error {
		return func() error {
			_, err := DecryptAttributes(kEncr, iv, cbcEncryptRaw(t, kEncr, iv, h(plainHex)))
			return err
		}
	}
	parse := func(data []byte) func() error {
		return func() error {
			_, err := Parse(data)
			return err
		}
	}
	mppe := findVector(t, loadVectors[mppeVector](t, "mppe.json"), "mppe_key32",
		func(v mppeVector) string { return v.Name })

	tests := []struct {
		name     string
		run      func() error
		want     []error // errors.Is で true になるもの
		notWant  []error // errors.Is で false になるもの
		wantMsg  string  // 完全一致するメッセージ（空なら確かめない）
		wantAttr AttributeType
	}{
		{
			name: "packet_too_short", run: parse([]byte{CodeRequest, 1, 0}),
			want: []error{ErrMalformedPacket}, notWant: []error{ErrMalformedAttribute},
			wantMsg: "packet too short",
		},
		{
			name: "packet_length_mismatch", run: parse([]byte{CodeRequest, 1, 0, 9, TypeAKA}),
			want: []error{ErrMalformedPacket}, wantMsg: "packet length mismatch",
		},
		{
			name: "invalid_eap_aka_header", run: parse([]byte{CodeRequest, 1, 0, 6, TypeAKA, SubtypeChallenge}),
			want: []error{ErrMalformedPacket}, wantMsg: "invalid EAP-AKA header",
		},
		{
			name: "attribute_length_zero", run: parse(akaRequest(TypeAKA, "13000001")),
			want: []error{ErrMalformedAttribute}, notWant: []error{ErrMalformedPacket},
			wantMsg: "attribute length zero",
		},
		{
			name: "attribute_length_overflow", run: parse(akaRequest(TypeAKA, "13020001")),
			want: []error{ErrMalformedAttribute}, wantMsg: "attribute 19 length overflow",
		},
		{
			name: "attribute_value_invalid", run: parse(akaRequest(TypeAKA, "15010000")),
			want: []error{ErrMalformedAttribute}, notWant: []error{ErrPaddingNotZero},
			wantMsg: "failed to unmarshal attribute type 21: invalid AT_NONCE_S length", wantAttr: AT_NONCE_S,
		},
		{
			name: "bidding_in_aka_prime_parse", run: parse(akaRequest(TypeAKAPrime, "88018000")),
			want: []error{ErrBiddingInAKAPrime}, notWant: []error{ErrMalformedAttribute},
			wantMsg: "AT_BIDDING is only valid for EAP-AKA",
		},
		{
			name: "bidding_in_aka_prime_marshal",
			run: func() error {
				_, err := (&Packet{Code: CodeRequest, Type: TypeAKAPrime, Subtype: SubtypeChallenge,
					Attributes: []Attribute{&AtBidding{}}}).Marshal()
				return err
			},
			want: []error{ErrBiddingInAKAPrime},
		},
		{
			name: "padding_not_zero_in_packet", run: parse(akaRequest(TypeAKA, "06010001")),
			want:    []error{ErrMalformedAttribute, ErrPaddingNotZero},
			wantMsg: "failed to unmarshal attribute type 6: AT_PADDING bytes must be zero", wantAttr: AT_PADDING,
		},
		{
			name: "encr_data_length", run: func() error {
				_, err := DecryptAttributes(kEncr, iv, make([]byte, 15))
				return err
			},
			want: []error{ErrEncrDataLength}, wantMsg: "AT_ENCR_DATA length 15 is not a positive multiple of 16",
		},
		{
			name: "padding_not_zero_in_encr_data", run: decrypt("13010001" + "060300000000000000000001"),
			want: []error{ErrPaddingNotZero, ErrMalformedAttribute}, notWant: []error{ErrPaddingNotLast},
			wantAttr: AT_PADDING,
		},
		{
			name: "padding_length_in_encr_data", run: decrypt("0604" + "0000000000000000000000000000"),
			want: []error{ErrPaddingLength, ErrMalformedAttribute}, wantAttr: AT_PADDING,
		},
		{
			name: "padding_not_last", run: decrypt("060300000000000000000000" + "13010001"),
			want: []error{ErrPaddingNotLast}, notWant: []error{ErrMalformedAttribute},
			wantMsg: "AT_PADDING is not the last attribute in AT_ENCR_DATA",
		},
		{
			name: "broken_nested_attribute", run: decrypt("13000001" + "000000000000000000000000"),
			want: []error{ErrMalformedAttribute}, notWant: []error{ErrPaddingNotZero},
		},
		{
			name: "mac_not_found", run: func() error {
				_, err := (&Packet{Code: CodeResponse, Type: TypeAKA, Subtype: SubtypeReauthentication}).VerifyMac(make([]byte, 16))
				return err
			},
			want: []error{ErrMacNotFound}, wantMsg: "AT_MAC attribute not found",
		},
		{
			name: "empty_kdf_input_parse", run: parse(akaRequest(TypeAKAPrime, "17010000")),
			want: []error{ErrEmptyKdfInput, ErrMalformedAttribute}, wantAttr: AT_KDF_INPUT,
		},
		{
			name: "empty_kdf_input_derive", run: func() error {
				_, _, err := DeriveCKPrimeIKPrime(make([]byte, 16), make([]byte, 16), "", make([]byte, 16))
				return err
			},
			want: []error{ErrEmptyKdfInput}, wantMsg: "AT_KDF_INPUT must be non-empty",
		},
		{
			name: "mppe_length", run: func() error {
				_, err := DecryptMPPEKey(mppe.Encrypted[:17], mppe.Secret, mppe.ReqAuth)
				return err
			},
			want:    []error{ErrMalformedMPPEKey},
			wantMsg: "eapaka: invalid MPPE key attribute length 17 (want the Salt and a positive multiple of 16 bytes)",
		},
		{
			name: "mppe_key_length", run: func() error {
				enc := append([]byte(nil), mppe.Encrypted...)
				enc[2] ^= 32 // 復号した Key-Length が 0 になる
				_, err := DecryptMPPEKey(enc, mppe.Secret, mppe.ReqAuth)
				return err
			},
			want: []error{ErrMalformedMPPEKey},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, target := range tt.want {
				if !errors.Is(err, target) {
					t.Errorf("errors.Is(%q, %q) = false, want true", err, target)
				}
			}
			for _, target := range tt.notWant {
				if errors.Is(err, target) {
					t.Errorf("errors.Is(%q, %q) = true, want false", err, target)
				}
			}
			if tt.wantMsg != "" && err.Error() != tt.wantMsg {
				t.Errorf("message = %q, want %q", err.Error(), tt.wantMsg)
			}
			attrErr, ok := errors.AsType[*AttributeError](err)
			if tt.wantAttr != 0 {
				if !ok || attrErr.Type != tt.wantAttr {
					t.Errorf("AttributeError = %v, %v, want type %d", attrErr, ok, tt.wantAttr)
				}
			} else if ok {
				t.Errorf("unexpected AttributeError for type %d", attrErr.Type)
			}
		})
	}
}

// TestCallerErrorsAreNotSentinel は、呼び出し側の誤り（鍵の長さなど）が受信データの異常を表す
// sentinel error と判定されないことを確かめる。
func TestCallerErrorsAreNotSentinel(t *testing.T) {
	sentinels := []error{
		ErrMalformedPacket, ErrMalformedAttribute, ErrBiddingInAKAPrime, ErrEncrDataLength,
		ErrPaddingLength, ErrPaddingNotZero, ErrPaddingNotLast, ErrMacNotFound,
		ErrEmptyKdfInput, ErrMalformedMPPEKey,
	}
	_, errKey := DecryptAttributes(make([]byte, 15), make([]byte, 16), make([]byte, 16))
	_, errNonce := DeriveReauthKeysAKA("id", 1, make([]byte, 15), make([]byte, 20))
	_, errReqAuth := DecryptMPPEKey(make([]byte, 18), []byte("s"), make([]byte, 15))
	for i, err := range []error{errKey, errNonce, errReqAuth} {
		if err == nil {
			t.Fatalf("case %d: expected an error", i)
		}
		for _, s := range sentinels {
			if errors.Is(err, s) {
				t.Errorf("case %d: errors.Is(%q, %q) = true, want false", i, err, s)
			}
		}
	}
}
