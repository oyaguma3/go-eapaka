package eapaka

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"math/big"
)

// AkaKeys holds the key material derived for EAP-AKA (RFC 4187).
type AkaKeys struct {
	K_encr []byte // 128 bits (16 bytes)
	K_aut  []byte // 128 bits (16 bytes)
	MSK    []byte // 512 bits (64 bytes)
	EMSK   []byte // 512 bits (64 bytes)
}

// AkaPrimeKeys holds the key material derived for EAP-AKA' (RFC 5448).
type AkaPrimeKeys struct {
	K_encr []byte // 128 bits (16 bytes)
	K_aut  []byte // 256 bits (32 bytes) - Note: Larger than AKA
	K_re   []byte // 256 bits (32 bytes)
	MSK    []byte // 512 bits (64 bytes)
	EMSK   []byte // 512 bits (64 bytes)
}

// DeriveKeysAKA derives the key hierarchy for EAP-AKA as per RFC 4187.
// identity: The EAP Identity (NAI) from the EAP-Response/Identity packet.
// ck, ik: Cipher Key and Integrity Key provided by the USIM/HSS.
func DeriveKeysAKA(identity string, ck, ik []byte) AkaKeys {
	// RFC 4187 Section 7: MK = SHA1(Identity | IK | CK)
	h := sha1.New()
	h.Write([]byte(identity))
	h.Write(ik)
	h.Write(ck)
	mk := h.Sum(nil) // 20 bytes

	// FIPS 186-2 PRF で 160バイトの鍵素材を生成
	keyBlock := prfGenAKA(mk, 160)

	// RFC 4187 Section 7: Key mapping
	return AkaKeys{
		K_encr: keyBlock[0:16],
		K_aut:  keyBlock[16:32],
		MSK:    keyBlock[32:96],
		EMSK:   keyBlock[96:160],
	}
}

// DeriveKeysAKAPrime derives the key hierarchy for EAP-AKA' as per RFC 5448.
// identity: The EAP Identity (NAI).
// ckPrime, ikPrime: CK' and IK' derived from CK/IK and Network Name.
func DeriveKeysAKAPrime(identity string, ckPrime, ikPrime []byte) AkaPrimeKeys {
	// RFC 5448 Section 3.3
	// MK is calculated as part of the PRF' generation
	// Key for PRF' is IK'|CK'
	key := append(append([]byte{}, ikPrime...), ckPrime...)

	// Seed for PRF' is "EAP-AKA'" | Identity
	seed := append([]byte("EAP-AKA'"), []byte(identity)...)

	// Total bytes needed: 16 + 32 + 32 + 64 + 64 = 208 bytes
	// RFC 5448 calls the output of this PRF' "MK"
	keyBlock := prfPlusIKEv2(key, seed, 208)

	return AkaPrimeKeys{
		K_encr: keyBlock[0:16],
		K_aut:  keyBlock[16:48], // 32 bytes
		K_re:   keyBlock[48:80], // 32 bytes
		MSK:    keyBlock[80:144],
		EMSK:   keyBlock[144:208],
	}
}

// DeriveCKPrimeIKPrime derives CK' and IK' from CK, IK, AUTN, and Access Network Name.
// RFC 9048 Section 3.3 and TS 33.402 Annex A.2.
// netName: Access Network Name (AT_KDF_INPUT).
// autn: AUTN from the AKA run; SQN xor AK is derived from autn[0:6].
func DeriveCKPrimeIKPrime(ck, ik []byte, netName string, autn []byte) (ckPrime, ikPrime []byte, err error) {
	if len(ck) != 16 || len(ik) != 16 {
		return nil, nil, errors.New("CK and IK must be 16 bytes")
	}
	if len(autn) < 6 {
		return nil, nil, errors.New("AUTN must be at least 6 bytes")
	}
	if netName == "" {
		return nil, nil, errors.New("AT_KDF_INPUT must be non-empty")
	}

	// SQN xor AK is the first 6 bytes of AUTN.
	sqnXorAk := autn[:6]

	// Key for KDF is CK || IK.
	key := append(append([]byte{}, ck...), ik...)

	// S = FC || P0 || L0 || P1 || L1
	// FC = 0x20, P0 = Network Name, P1 = SQN xor AK.
	s := make([]byte, 0, 1+len(netName)+2+6+2)
	s = append(s, 0x20)
	s = append(s, []byte(netName)...)
	netLen := uint16(len(netName))
	s = append(s, byte(netLen>>8), byte(netLen))
	s = append(s, sqnXorAk...)
	sqnLen := uint16(len(sqnXorAk))
	s = append(s, byte(sqnLen>>8), byte(sqnLen))

	h := hmac.New(sha256.New, key)
	h.Write(s)
	out := h.Sum(nil)
	ckPrime = out[:16]
	ikPrime = out[16:32]
	return ckPrime, ikPrime, nil
}

// -----------------------------------------------------------------------------
// Internal PRF Implementations
// -----------------------------------------------------------------------------

// prfGenAKA は FIPS 186-2 Change Notice 1 に基づく PRF を実装する。
// RFC 4187 Section 7 / RFC 4186 Appendix B で参照される。
//
// アルゴリズム:
//
//	XKEY = MK (20バイト) をゼロパディングして64バイト
//	t = SHA-1初期ハッシュ値
//	for j = 0 to m-1:
//	    w_0 = G(t, XKEY)                  // SHA-1圧縮関数（パディングなし）
//	    XKEY = (1 + XKEY + w_0) mod 2^160  // 先頭20バイトのみ更新
//	    w_1 = G(t, XKEY)
//	    XKEY = (1 + XKEY + w_1) mod 2^160
//	    output_j = w_0 || w_1              // 40バイト/イテレーション
func prfGenAKA(mk []byte, outputLen int) []byte {
	// mod 2^160 用の定数
	mod2_160 := new(big.Int).Lsh(big.NewInt(1), 160) // 2^160
	one := big.NewInt(1)

	// XKEY = MK (20バイト) + ゼロパディング (44バイト) = 64バイトブロック
	xkey := make([]byte, sha1Chunk)
	copy(xkey, mk)

	var output []byte

	for len(output) < outputLen {
		// 各イテレーションで2つの w を生成（w_0, w_1）
		for i := 0; i < 2; i++ {
			// G(t, XKEY) = SHA-1圧縮関数（SHA-1初期状態, XKEY）
			w := sha1CompressToBytes(sha1InitH, xkey)
			output = append(output, w...)

			// XKEY = (1 + XKEY + w) mod 2^160
			// xkey の先頭20バイトのみを更新（残り44バイトはゼロのまま）
			xkeyInt := new(big.Int).SetBytes(xkey[:20])
			wInt := new(big.Int).SetBytes(w)
			xkeyInt.Add(xkeyInt, wInt)
			xkeyInt.Add(xkeyInt, one)
			xkeyInt.Mod(xkeyInt, mod2_160)

			// big.Int.Bytes() は先頭ゼロを省略するため、20バイトに右詰めする
			xkeyBytes := xkeyInt.Bytes()
			// xkey の先頭20バイトをクリアして新しい値を設定
			for j := 0; j < 20; j++ {
				xkey[j] = 0
			}
			copy(xkey[20-len(xkeyBytes):20], xkeyBytes)

			if len(output) >= outputLen {
				break
			}
		}
	}

	return output[:outputLen]
}

// prfPlusIKEv2 implements PRF+ based on RFC 4306 (IKEv2).
// Used in EAP-AKA' (RFC 5448). Uses HMAC-SHA-256.
func prfPlusIKEv2(key, seed []byte, outputLen int) []byte {
	var output []byte
	var current []byte
	counter := byte(1)
	h := hmac.New(sha256.New, key)

	// T1 = HMAC(K, S | 0x01)
	// T2 = HMAC(K, T1 | S | 0x02)
	for len(output) < outputLen {
		h.Reset()
		if counter > 1 {
			h.Write(current) // Chain previous block
		}
		h.Write(seed)
		h.Write([]byte{counter})
		current = h.Sum(nil)
		output = append(output, current...)
		counter++
	}

	return output[:outputLen]
}
