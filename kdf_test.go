package eapaka

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

// Helper to decode hex for readability
func h(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// TestPrfGenAKA_FIPS186_2 は FIPS 186-2 Change Notice 1 準拠の PRF 出力を検証する。
// 期待値は wpa_supplicant と同一アルゴリズムのリファレンス実装から生成。
func TestPrfGenAKA_FIPS186_2(t *testing.T) {
	tests := []struct {
		name     string
		mk       []byte
		outLen   int
		expected string // hex
	}{
		{
			name:   "MK=all_zeros_160bytes",
			mk:     make([]byte, 20),
			outLen: 160,
			expected: "92b404e556588ced6c1acd4ebf053f6809f73a93" +
				"55acad4d81ef20b346f80f4a2bf74a28de570979" +
				"7a1d99aa13d2cf2231fd6a0b6a72a6bd04d94d16" +
				"1f2e4ee2983bba47409c8376093bcd12b305f2cd" +
				"36508927b34a57565ab9719e424194a05820086f" +
				"28c16be4cd8a4700f3d71d68ce2d37e48183c52b" +
				"fa3f631e67deb968ab16b0ee7daf4d3192ded1fc" +
				"9eaac56a78d0ff7573976eb333bd999e46eb4ba8",
		},
		{
			name: "MK=SHA1(test_identity||zeros)_160bytes",
			mk: func() []byte {
				h := sha1.New()
				h.Write([]byte("test_identity"))
				h.Write(make([]byte, 16)) // IK = zeros
				h.Write(make([]byte, 16)) // CK = zeros
				return h.Sum(nil)
			}(),
			outLen: 160,
			expected: "501777a46df62c9050853af006ee0da79b5dd921" +
				"fa5239fe438e8f5456f8a2e85a316e9048ab0ccf" +
				"d08ff3cfe018bbf3f3ee1962d87f19e53d5bc952" +
				"6197d03d465c1007619fbc890e29832b44cb4985" +
				"304a87cfc3e82f5061fc75f5be81b89aa003d000" +
				"05fdcc69e406bd4a4a54d5a73278923fff00e81d" +
				"f6aff57dce443e38608bd7d91327c4a6a3535322" +
				"64ad4c8ec7a58604c389422e715f3b1d4da664f5",
		},
		{
			name:   "MK=all_zeros_40bytes",
			mk:     make([]byte, 20),
			outLen: 40,
			expected: "92b404e556588ced6c1acd4ebf053f6809f73a93" +
				"55acad4d81ef20b346f80f4a2bf74a28de570979",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := prfGenAKA(tc.mk, tc.outLen)
			expected := h(tc.expected)
			if !bytes.Equal(got, expected) {
				t.Errorf("PRF出力不一致\n期待: %x\n実際: %x", expected, got)
			}
		})
	}
}

// TestDeriveKeysAKA は EAP-AKA 鍵導出の長さと値を検証する。
func TestDeriveKeysAKA(t *testing.T) {
	t.Run("鍵長の検証", func(t *testing.T) {
		identity := "0123456789012345@wlan.mnc001.mcc001.3gppnetwork.org"
		ck := make([]byte, 16)
		ik := make([]byte, 16)

		keys := DeriveKeysAKA(identity, ck, ik)

		if len(keys.K_encr) != 16 {
			t.Errorf("K_encr length mismatch: got %d, want 16", len(keys.K_encr))
		}
		if len(keys.K_aut) != 16 {
			t.Errorf("K_aut length mismatch: got %d, want 16", len(keys.K_aut))
		}
		if len(keys.MSK) != 64 {
			t.Errorf("MSK length mismatch: got %d, want 64", len(keys.MSK))
		}
		if len(keys.EMSK) != 64 {
			t.Errorf("EMSK length mismatch: got %d, want 64", len(keys.EMSK))
		}
	})

	t.Run("値の検証_FIPS186_2", func(t *testing.T) {
		// テスト用入力: identity="test_identity", CK=IK=all zeros
		identity := "test_identity"
		ck := make([]byte, 16)
		ik := make([]byte, 16)

		// MK = SHA1(identity || IK || CK)
		sh := sha1.New()
		sh.Write([]byte(identity))
		sh.Write(ik)
		sh.Write(ck)
		mk := sh.Sum(nil)

		// PRF(MK, 160) の期待値
		expectedKeyBlock := h(
			"501777a46df62c9050853af006ee0da79b5dd921" +
				"fa5239fe438e8f5456f8a2e85a316e9048ab0ccf" +
				"d08ff3cfe018bbf3f3ee1962d87f19e53d5bc952" +
				"6197d03d465c1007619fbc890e29832b44cb4985" +
				"304a87cfc3e82f5061fc75f5be81b89aa003d000" +
				"05fdcc69e406bd4a4a54d5a73278923fff00e81d" +
				"f6aff57dce443e38608bd7d91327c4a6a3535322" +
				"64ad4c8ec7a58604c389422e715f3b1d4da664f5",
		)

		keys := DeriveKeysAKA(identity, ck, ik)

		// K_encr = keyBlock[0:16]
		if !bytes.Equal(keys.K_encr, expectedKeyBlock[0:16]) {
			t.Errorf("K_encr mismatch\n期待: %x\n実際: %x", expectedKeyBlock[0:16], keys.K_encr)
		}
		// K_aut = keyBlock[16:32]
		if !bytes.Equal(keys.K_aut, expectedKeyBlock[16:32]) {
			t.Errorf("K_aut mismatch\n期待: %x\n実際: %x", expectedKeyBlock[16:32], keys.K_aut)
		}
		// MSK = keyBlock[32:96]
		if !bytes.Equal(keys.MSK, expectedKeyBlock[32:96]) {
			t.Errorf("MSK mismatch\n期待: %x\n実際: %x", expectedKeyBlock[32:96], keys.MSK)
		}
		// EMSK = keyBlock[96:160]
		if !bytes.Equal(keys.EMSK, expectedKeyBlock[96:160]) {
			t.Errorf("EMSK mismatch\n期待: %x\n実際: %x", expectedKeyBlock[96:160], keys.EMSK)
		}

		// MK が期待通りか確認
		expectedMK := h("397e3f73f188dfc170df2e21b101aa05082f098e")
		if !bytes.Equal(mk, expectedMK) {
			t.Errorf("MK mismatch\n期待: %x\n実際: %x", expectedMK, mk)
		}
	})
}

func TestDeriveKeysAKAPrime_RFC5448_Case1(t *testing.T) {
	// RFC 9048 Appendix D Case 1
	identity := "0555444333222111"
	netName := "WLAN"
	ik := h("9744871ad32bf9bbd1dd5ce54e3e2e5a")
	ck := h("5349fbe098649f948f5d2e973a81c00f")
	autn := h("bb52e91c747ac3ab2a5c23d15ee351d5")

	// Expected Derived Keys
	expCkPrime := h("0093962d0dd84aa5684b045c9edffa04")
	expIkPrime := h("ccfc230ca74fcc96c0a5d61164f5a76c")
	expKEncr := h("766fa0a6c317174b812d52fbcd11a179")
	expKAut := h("0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea")
	expKRe := h("cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a")
	expMSK := h("67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a")
	expEMSK := h("f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb")

	// 1. Derive CK', IK'
	ckPrime, ikPrime, err := DeriveCKPrimeIKPrime(ck, ik, netName, autn)
	if err != nil {
		t.Fatalf("DeriveCKPrimeIKPrime failed: %v", err)
	}

	if !bytes.Equal(ckPrime, expCkPrime) {
		t.Errorf("CK' mismatch\nGot: %x\nWant: %x", ckPrime, expCkPrime)
	}
	if !bytes.Equal(ikPrime, expIkPrime) {
		t.Errorf("IK' mismatch\nGot: %x\nWant: %x", ikPrime, expIkPrime)
	}

	// 2. Derive Keys
	keys := DeriveKeysAKAPrime(identity, ckPrime, ikPrime)

	if !bytes.Equal(keys.K_encr, expKEncr) {
		t.Errorf("K_encr mismatch\nGot: %x\nWant: %x", keys.K_encr, expKEncr)
	}
	if !bytes.Equal(keys.K_aut, expKAut) {
		t.Errorf("K_aut mismatch\nGot: %x\nWant: %x", keys.K_aut, expKAut)
	}
	if !bytes.Equal(keys.K_re, expKRe) {
		t.Errorf("K_re mismatch\nGot: %x\nWant: %x", keys.K_re, expKRe)
	}
	if !bytes.Equal(keys.MSK, expMSK) {
		t.Errorf("MSK mismatch\nGot: %x\nWant: %x", keys.MSK, expMSK)
	}
	if !bytes.Equal(keys.EMSK, expEMSK) {
		t.Errorf("EMSK mismatch\nGot: %x\nWant: %x", keys.EMSK, expEMSK)
	}
}

func TestEncryptMPPEKey(t *testing.T) {
	// Case 1: Key length 32
	key32 := make([]byte, 32)
	secret := []byte("radius-secret")
	reqAuth := make([]byte, 16)

	encrypted, err := EncryptMPPEKey(key32, secret, reqAuth)
	if err != nil {
		t.Fatalf("EncryptMPPEKey failed: %v", err)
	}

	expectedLen32 := 2 + 48
	if len(encrypted) != expectedLen32 {
		t.Errorf("Encrypted length mismatch (key32): got %d, want %d", len(encrypted), expectedLen32)
	}
	if (encrypted[0] & 0x80) == 0 {
		t.Error("Salt MSB is not set")
	}

	// Case 2: Key length 7
	key7 := make([]byte, 7)
	encrypted7, err := EncryptMPPEKey(key7, secret, reqAuth)
	if err != nil {
		t.Fatalf("EncryptMPPEKey (key7) failed: %v", err)
	}

	expectedLen7 := 2 + 16
	if len(encrypted7) != expectedLen7 {
		t.Errorf("Encrypted length mismatch (key7): got %d, want %d", len(encrypted7), expectedLen7)
	}
}
