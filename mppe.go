package eapaka

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
)

// EncryptMPPEKey encrypts the given key (e.g., MSK part) for inclusion in
// MS-MPPE-Send-Key or MS-MPPE-Recv-Key attributes.
//
// Ref: RFC 2548 Section 2.4.2 and 2.4.3
// key: The key to encrypt (typically 32 bytes).
// secret: The RADIUS shared secret.
// reqAuth: The Request Authenticator from the Access-Request packet (16 bytes).
func EncryptMPPEKey(key []byte, secret []byte, reqAuth []byte) ([]byte, error) {
	if len(key) == 0 || len(key) > 255 {
		return nil, errors.New("eapaka: invalid key length for MPPE encryption")
	}

	// 1. Generate Salt (2 bytes)
	// "The most significant bit ... MUST be set"
	salt := make([]byte, 2)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	salt[0] |= 0x80

	// 2. Prepare Plaintext
	// Structure: [Length(1)] + [Key] + [Padding]
	// RFC 2548: "The length of the salt + length + key + padding must be a multiple of 16"

	plainLen := 1 + len(key)

	// Calculate total length needed (Salt + Plaintext)
	totalLen := 2 + plainLen
	padLen := 0
	if totalLen%16 != 0 {
		padLen = 16 - (totalLen % 16)
	}

	// Construct buffer
	plaintext := make([]byte, plainLen+padLen)
	plaintext[0] = byte(len(key))
	copy(plaintext[1:], key)
	// Padding is zero-valued by make()

	// 3. Encrypt
	// Result buffer: [Salt(2)] + [Encrypted Blocks...]
	result := make([]byte, 2+len(plaintext))
	copy(result[0:2], salt)

	h := md5.New()

	// b(1) = MD5(Secret + RequestAuthenticator + Salt)
	h.Write(secret)
	h.Write(reqAuth)
	h.Write(salt)
	b := h.Sum(nil) // 16 bytes

	// c(i) = p(i) ^ b(i)
	cipherOffset := 2
	for i := 0; i < len(plaintext); i += 16 {
		// Handle last block which might be less than 16 bytes
		end := i + 16
		if end > len(plaintext) {
			end = len(plaintext)
		}
		pBlock := plaintext[i:end]
		cBlock := make([]byte, len(pBlock))

		for j := 0; j < len(pBlock); j++ {
			cBlock[j] = pBlock[j] ^ b[j]
		}

		copy(result[cipherOffset+i:], cBlock)

		// Prepare b(i+1) = MD5(Secret + c(i))
		h.Reset()
		h.Write(secret)
		h.Write(cBlock) // Use the ciphertext of the current block
		b = h.Sum(nil)
	}

	return result, nil
}
