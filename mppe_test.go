package eapaka

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestEncryptMPPEKeyWithSalt_Vectors は、Salt を固定した暗号化が Python のベクタ
// （hostap の radius.c でも照合済み）と一致することを確かめる。
func TestEncryptMPPEKeyWithSalt_Vectors(t *testing.T) {
	for _, v := range loadVectors[mppeVector](t, "mppe.json") {
		t.Run(v.Name, func(t *testing.T) {
			got, err := encryptMPPEKeyWithSalt(v.Key, v.Secret, v.ReqAuth, v.Salt)
			if err != nil {
				t.Fatalf("encryptMPPEKeyWithSalt: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Encrypted), got); diff != "" {
				t.Errorf("encrypted mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecryptMPPEKey_Vectors(t *testing.T) {
	for _, v := range loadVectors[mppeVector](t, "mppe.json") {
		t.Run(v.Name, func(t *testing.T) {
			enc := bytes.Clone(v.Encrypted)
			got, err := DecryptMPPEKey(enc, v.Secret, v.ReqAuth)
			if err != nil {
				t.Fatalf("DecryptMPPEKey: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Key), got); diff != "" {
				t.Errorf("key mismatch (-want +got):\n%s", diff)
			}
			if !bytes.Equal(enc, v.Encrypted) {
				t.Error("DecryptMPPEKey modified its input")
			}
		})
	}
}

func TestEncryptDecryptMPPEKey_RoundTrip(t *testing.T) {
	secret := []byte("radius-secret")
	reqAuth := h("00112233445566778899aabbccddeeff")
	for _, keyLen := range []int{1, 15, 16, 31, 32, 47, 64, 255} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i*7 + 3)
		}
		enc, err := EncryptMPPEKey(key, secret, reqAuth)
		if err != nil {
			t.Fatalf("key length %d: EncryptMPPEKey: %v", keyLen, err)
		}
		if enc[0]&0x80 == 0 {
			t.Errorf("key length %d: Salt MSB is not set", keyLen)
		}
		// Salt（2）＋ Key-Length・Key・Padding を 16 の倍数にそろえたもの
		if want := 2 + (1+keyLen+15)/16*16; len(enc) != want {
			t.Errorf("key length %d: encrypted length = %d, want %d", keyLen, len(enc), want)
		}
		got, err := DecryptMPPEKey(enc, secret, reqAuth)
		if err != nil {
			t.Fatalf("key length %d: DecryptMPPEKey: %v", keyLen, err)
		}
		if !bytes.Equal(got, key) {
			t.Errorf("key length %d: round trip mismatch: got %x, want %x", keyLen, got, key)
		}
	}
}

// TestDecryptMPPEKey_DoesNotCheckSalt は、Salt の最上位ビットを検査しないことを確かめる
// （Salt の検査は呼び出し側の役割）。
func TestDecryptMPPEKey_DoesNotCheckSalt(t *testing.T) {
	key := h("000102030405060708090a0b0c0d0e0f")
	secret := []byte("radius-secret")
	reqAuth := make([]byte, 16)
	enc, err := encryptMPPEKeyWithSalt(key, secret, reqAuth, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("encryptMPPEKeyWithSalt: %v", err)
	}
	got, err := DecryptMPPEKey(enc, secret, reqAuth)
	if err != nil {
		t.Fatalf("DecryptMPPEKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("key = %x, want %x", got, key)
	}
}

func TestDecryptMPPEKey_Errors(t *testing.T) {
	v := findVector(t, loadVectors[mppeVector](t, "mppe.json"), "mppe_key32",
		func(v mppeVector) string { return v.Name })
	// 32 バイトの鍵なので P は 48 バイト（3 ブロック）
	if len(v.Key) != 32 || len(v.Encrypted) != 2+48 {
		t.Fatalf("unexpected vector: key %d bytes, encrypted %d bytes", len(v.Key), len(v.Encrypted))
	}
	// c(1) の先頭バイトを変えると、復号した Key-Length だけが変わる
	// （b(1) = MD5(S + R + A) は c(1) に依存しない）
	withKeyLength := func(n byte) []byte {
		enc := bytes.Clone(v.Encrypted)
		enc[2] ^= byte(len(v.Key)) ^ n
		return enc
	}

	tests := []struct {
		name    string
		enc     []byte
		reqAuth []byte
		wantErr string
	}{
		{"short_req_auth", v.Encrypted, v.ReqAuth[:15], "invalid Request Authenticator length"},
		{"nil", nil, v.ReqAuth, "invalid MPPE key attribute length 0"},
		{"salt_only", v.Encrypted[:2], v.ReqAuth, "invalid MPPE key attribute length 2"},
		{"string_too_short", v.Encrypted[:2+15], v.ReqAuth, "invalid MPPE key attribute length 17"},
		{"string_not_multiple_of_16", v.Encrypted[:len(v.Encrypted)-1], v.ReqAuth, "invalid MPPE key attribute length 49"},
		{"extra_byte", append(bytes.Clone(v.Encrypted), 0), v.ReqAuth, "invalid MPPE key attribute length 51"},
		{"key_length_zero", withKeyLength(0), v.ReqAuth, "invalid MPPE Key-Length 0"},
		{"key_length_exceeds_data", withKeyLength(48), v.ReqAuth, "invalid MPPE Key-Length 48"},
		{"key_length_255", withKeyLength(255), v.ReqAuth, "invalid MPPE Key-Length 255"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptMPPEKey(tt.enc, v.Secret, tt.reqAuth)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecryptMPPEKey error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}

	t.Run("key_length_max", func(t *testing.T) {
		// Key-Length は復号したデータ（48 バイト）から Key-Length 自身を除いた 47 まで
		got, err := DecryptMPPEKey(withKeyLength(47), v.Secret, v.ReqAuth)
		if err != nil {
			t.Fatalf("DecryptMPPEKey: %v", err)
		}
		if len(got) != 47 {
			t.Errorf("key length = %d, want 47", len(got))
		}
	})

	t.Run("wrong_secret", func(t *testing.T) {
		got, err := DecryptMPPEKey(v.Encrypted, []byte("wrong-secret"), v.ReqAuth)
		if err == nil && bytes.Equal(got, v.Key) {
			t.Error("DecryptMPPEKey with a wrong secret returned the original key")
		}
	})
}

func TestEncryptMPPEKeyWithSalt_Errors(t *testing.T) {
	key, reqAuth := make([]byte, 32), make([]byte, 16)
	tests := []struct {
		name               string
		key, reqAuth, salt []byte
		wantErr            string
	}{
		{"empty_key", nil, reqAuth, []byte{0x80, 0x00}, "invalid key length"},
		{"key_too_long", make([]byte, 256), reqAuth, []byte{0x80, 0x00}, "invalid key length"},
		{"short_req_auth", key, reqAuth[:15], []byte{0x80, 0x00}, "invalid Request Authenticator length"},
		{"short_salt", key, reqAuth, []byte{0x80}, "invalid MPPE Salt length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptMPPEKeyWithSalt(tt.key, []byte("secret"), tt.reqAuth, tt.salt)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("encryptMPPEKeyWithSalt error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
