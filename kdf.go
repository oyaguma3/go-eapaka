package eapaka

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
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

	// Generate 160 bytes of key material using PRF(MK, 0)
	// w (seed) is 0x00
	keyBlock := prfGenAKA(mk, []byte{0x00}, 160)

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

// DeriveCKPrimeIKPrime derives CK' and IK' from CK, IK and Access Network Name.
// RFC 5448 Section 3.1 & 3.2.
// netName: Typically "WLAN" for Wi-Fi calling.
func DeriveCKPrimeIKPrime(ck, ik []byte, netName string) (ckPrime, ikPrime []byte) {
	// Access Network Identity
	anId := []byte(netName)

	// Key for PRF' is IK|CK
	key := append(append([]byte{}, ik...), ck...)

	// S = FC | P0 | L0 | P1 | L1 ...
	// FC = 0x20 for CK', 0x21 for IK'
	// P0 = "EAP-AKA'"
	// P1 = Access Network Identity (netName)

	mkSeed := func(fc byte) []byte {
		// RFC 5448 Section 3.1
		// S = FC || "EAP-AKA'" || len("EAP-AKA'") || AN-ID || len(AN-ID)
		// Note: Lengths are 2-byte integers (big endian)

		s := make([]byte, 0, 1+8+2+len(anId)+2)
		s = append(s, fc)
		s = append(s, []byte("EAP-AKA'")...)
		s = append(s, 0x00, 0x08) // len("EAP-AKA'") = 8
		s = append(s, anId...)
		// len(anId)
		l := uint16(len(anId))
		s = append(s, byte(l>>8), byte(l))
		return s
	}

	// Output length of PRF' is 32 bytes (SHA-256), but CK'/IK' are 128-bit (16 bytes) ?
	// RFC 5448 Section 3.1: "CK' ... is the first 128 bits"

	// CK' calculation
	seedCk := mkSeed(0x20)
	fullCk := prfPlusIKEv2(key, seedCk, 32)
	ckPrime = fullCk[:16]

	// IK' calculation
	seedIk := mkSeed(0x21)
	fullIk := prfPlusIKEv2(key, seedIk, 32)
	ikPrime = fullIk[:16]

	return ckPrime, ikPrime
}

// -----------------------------------------------------------------------------
// Internal PRF Implementations
// -----------------------------------------------------------------------------

// prfGenAKA implements the PRF based on FIPS 186-2 Change Notice 1 (SHA-1).
// Used in EAP-AKA (RFC 4187).
func prfGenAKA(key []byte, seed []byte, outputLen int) []byte {
	var output []byte
	var current []byte
	h := sha1.New()

	// x_0 = SHA1(key | seed)
	h.Write(key)
	h.Write(seed)
	current = h.Sum(nil)
	output = append(output, current...)

	// x_j = SHA1(key | x_{j-1})
	for len(output) < outputLen {
		h.Reset()
		h.Write(key)
		h.Write(current)
		current = h.Sum(nil)
		output = append(output, current...)
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
