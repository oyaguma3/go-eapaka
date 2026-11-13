package eapaka

import (
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// findVector はベクタの一覧から名前で 1 ケースを探す。
func findVector[T any](t *testing.T, cases []T, name string, nameOf func(T) string) T {
	t.Helper()
	for _, c := range cases {
		if nameOf(c) == name {
			return c
		}
	}
	t.Fatalf("vector %q not found", name)
	var zero T
	return zero
}

func TestDeriveReauthKeysAKA_Vectors(t *testing.T) {
	for _, v := range loadVectors[reauthAKAVector](t, "reauth_keys_aka.json") {
		t.Run(v.Name, func(t *testing.T) {
			// 新しく書いた XKEY' の組み立てを、中間値で確かめる
			if diff := cmp.Diff([]byte(v.XKeyPrime), xkeyPrimeAKA(v.Identity, v.Counter, v.NonceS, v.MK)); diff != "" {
				t.Errorf("XKEY' mismatch (-want +got):\n%s", diff)
			}

			got, err := DeriveReauthKeysAKA(v.Identity, v.Counter, v.NonceS, v.MK)
			if err != nil {
				t.Fatalf("DeriveReauthKeysAKA: %v", err)
			}
			want := ReauthKeys{MSK: v.MSK, EMSK: v.EMSK}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("DeriveReauthKeysAKA mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeriveReauthKeysAKAPrime_Vectors(t *testing.T) {
	for _, v := range loadVectors[reauthAKAPrimeVector](t, "reauth_keys_aka_prime.json") {
		t.Run(v.Name, func(t *testing.T) {
			got, err := DeriveReauthKeysAKAPrime(v.Identity, v.Counter, v.NonceS, v.KRe)
			if err != nil {
				t.Fatalf("DeriveReauthKeysAKAPrime: %v", err)
			}
			want := ReauthKeys{MSK: v.MSK, EMSK: v.EMSK}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("DeriveReauthKeysAKAPrime mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDeriveReauthKeys_FromFullAuth は、フル認証の API が返す MK・K_re を
// そのまま再認証の鍵導出に渡す流れを、hostap のベクタで確かめる。
// reauth_keys_aka(_prime).json の counter1・counter2 のケースは、aka_keys.json の
// aka_full_1 と aka_prime_keys.json の aka_prime_full_rfc9048_case1 の鍵から作られている。
func TestDeriveReauthKeys_FromFullAuth(t *testing.T) {
	t.Run("aka", func(t *testing.T) {
		full := findVector(t, loadVectors[akaKeysVector](t, "aka_keys.json"), "aka_full_1",
			func(v akaKeysVector) string { return v.Name })
		keys := DeriveKeysAKA(full.Identity, full.CK, full.IK)

		reauths := loadVectors[reauthAKAVector](t, "reauth_keys_aka.json")
		for _, name := range []string{"aka_reauth_counter1", "aka_reauth_counter2"} {
			v := findVector(t, reauths, name, func(v reauthAKAVector) string { return v.Name })
			got, err := DeriveReauthKeysAKA(v.Identity, v.Counter, v.NonceS, keys.MK)
			if err != nil {
				t.Fatalf("%s: DeriveReauthKeysAKA: %v", name, err)
			}
			if diff := cmp.Diff(ReauthKeys{MSK: v.MSK, EMSK: v.EMSK}, got); diff != "" {
				t.Errorf("%s: mismatch (-want +got):\n%s", name, diff)
			}
		}
	})

	t.Run("aka_prime", func(t *testing.T) {
		full := findVector(t, loadVectors[akaPrimeKeysVector](t, "aka_prime_keys.json"), "aka_prime_full_rfc9048_case1",
			func(v akaPrimeKeysVector) string { return v.Name })
		ckPrime, ikPrime, err := DeriveCKPrimeIKPrime(full.CK, full.IK, full.NetworkName, full.AUTN)
		if err != nil {
			t.Fatalf("DeriveCKPrimeIKPrime: %v", err)
		}
		keys := DeriveKeysAKAPrime(full.Identity, ckPrime, ikPrime)

		reauths := loadVectors[reauthAKAPrimeVector](t, "reauth_keys_aka_prime.json")
		for _, name := range []string{"aka_prime_reauth_counter1", "aka_prime_reauth_counter2"} {
			v := findVector(t, reauths, name, func(v reauthAKAPrimeVector) string { return v.Name })
			got, err := DeriveReauthKeysAKAPrime(v.Identity, v.Counter, v.NonceS, keys.K_re)
			if err != nil {
				t.Fatalf("%s: DeriveReauthKeysAKAPrime: %v", name, err)
			}
			if diff := cmp.Diff(ReauthKeys{MSK: v.MSK, EMSK: v.EMSK}, got); diff != "" {
				t.Errorf("%s: mismatch (-want +got):\n%s", name, diff)
			}
		}
	})
}

// TestDeriveKeysAKA_MK は、AkaKeys.MK が MK = SHA1(Identity|IK|CK) であることを確かめる
// （RFC 4187 §7）。
func TestDeriveKeysAKA_MK(t *testing.T) {
	tests := []struct {
		name     string
		identity string
		ik, ck   []byte
	}{
		{"zero_keys", "test_identity", make([]byte, 16), make([]byte, 16)},
		{"nai", "0123456789012345@wlan.mnc001.mcc001.3gppnetwork.org",
			h("000102030405060708090a0b0c0d0e0f"), h("101112131415161718191a1b1c1d1e1f")},
		{"empty_identity", "", h("ffeeddccbbaa99887766554433221100"), h("00112233445566778899aabbccddeeff")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum := sha1.Sum([]byte(tt.identity + string(tt.ik) + string(tt.ck)))
			got := DeriveKeysAKA(tt.identity, tt.ck, tt.ik).MK
			if diff := cmp.Diff(sum[:], got); diff != "" {
				t.Errorf("MK mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeriveReauthKeysAKA_Errors(t *testing.T) {
	nonce, mk := make([]byte, 16), make([]byte, 20)
	tests := []struct {
		name    string
		nonceS  []byte
		mk      []byte
		wantErr string
	}{
		{"nonce_nil", nil, mk, "NONCE_S must be 16 bytes"},
		{"nonce_short", make([]byte, 15), mk, "NONCE_S must be 16 bytes"},
		{"nonce_long", make([]byte, 17), mk, "NONCE_S must be 16 bytes"},
		{"mk_nil", nonce, nil, "MK must be 20 bytes"},
		{"mk_short", nonce, make([]byte, 19), "MK must be 20 bytes"},
		{"mk_long", nonce, make([]byte, 21), "MK must be 20 bytes"},
		// EAP-AKA' の K_re を誤って渡した場合
		{"k_re_given", nonce, make([]byte, 32), "MK must be 20 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveReauthKeysAKA("4reauth@example", 1, tt.nonceS, tt.mk)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DeriveReauthKeysAKA error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDeriveReauthKeysAKAPrime_Errors(t *testing.T) {
	nonce, kRe := make([]byte, 16), make([]byte, 32)
	tests := []struct {
		name    string
		nonceS  []byte
		kRe     []byte
		wantErr string
	}{
		{"nonce_nil", nil, kRe, "NONCE_S must be 16 bytes"},
		{"nonce_short", make([]byte, 15), kRe, "NONCE_S must be 16 bytes"},
		{"nonce_long", make([]byte, 17), kRe, "NONCE_S must be 16 bytes"},
		{"k_re_nil", nonce, nil, "K_re must be 32 bytes"},
		{"k_re_short", nonce, make([]byte, 31), "K_re must be 32 bytes"},
		{"k_re_long", nonce, make([]byte, 33), "K_re must be 32 bytes"},
		// EAP-AKA の MK を誤って渡した場合
		{"mk_given", nonce, make([]byte, 20), "K_re must be 32 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveReauthKeysAKAPrime("8reauth@example", 1, tt.nonceS, tt.kRe)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DeriveReauthKeysAKAPrime error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestReauthLabelAKAPrime(t *testing.T) {
	// RFC 9048 §3.3: NUL を含まない 16 文字の ASCII 文字列
	if len(reauthLabelAKAPrime) != 16 {
		t.Errorf("len(%q) = %d, want 16", reauthLabelAKAPrime, len(reauthLabelAKAPrime))
	}
}
