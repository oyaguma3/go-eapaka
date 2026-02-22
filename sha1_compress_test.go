package eapaka

import (
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

// TestSha1Compress_MatchesStdlib は、SHA-1圧縮関数 + 手動パディングの結果が
// 標準ライブラリの sha1.Sum() と一致することを検証する。
// これにより圧縮関数の正しさを保証する。
func TestSha1Compress_MatchesStdlib(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "20バイトデータ",
			data: []byte("12345678901234567890"),
		},
		{
			name: "空データ",
			data: []byte{},
		},
		{
			name: "64バイトデータ（1ブロック丁度）",
			data: make([]byte, 64),
		},
		{
			name: "ランダムパターン",
			data: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 標準ライブラリによる期待値
			expected := sha1.Sum(tc.data)

			// 手動でSHA-1パディングを行い、圧縮関数を呼ぶ
			padded := sha1Pad(tc.data)
			state := sha1InitH // 初期状態をコピー

			for off := 0; off < len(padded); off += sha1Chunk {
				sha1Compress(&state, padded[off:off+sha1Chunk])
			}

			// 状態をバイト列に変換
			var got [20]byte
			binary.BigEndian.PutUint32(got[0:4], state[0])
			binary.BigEndian.PutUint32(got[4:8], state[1])
			binary.BigEndian.PutUint32(got[8:12], state[2])
			binary.BigEndian.PutUint32(got[12:16], state[3])
			binary.BigEndian.PutUint32(got[16:20], state[4])

			if got != expected {
				t.Errorf("SHA-1不一致\n入力: %x\n期待: %x\n実際: %x", tc.data, expected, got)
			}
		})
	}
}

// sha1Pad はSHA-1のメッセージパディングを適用する。
// テスト用ヘルパー。
func sha1Pad(msg []byte) []byte {
	msgLen := len(msg)
	// パディング: 0x80 + ゼロ埋め + 8バイト長
	padLen := sha1Chunk - ((msgLen + 9) % sha1Chunk)
	if padLen == sha1Chunk {
		padLen = 0
	}
	totalLen := msgLen + 1 + padLen + 8
	padded := make([]byte, totalLen)
	copy(padded, msg)
	padded[msgLen] = 0x80
	// 末尾8バイトにビット長をビッグエンディアンで書き込む
	bitLen := uint64(msgLen) * 8
	binary.BigEndian.PutUint64(padded[totalLen-8:], bitLen)
	return padded
}

// TestSha1Compress_GFunction はFIPS 186-2のG関数として圧縮関数が
// パディングなしで呼べることを検証する。
func TestSha1Compress_GFunction(t *testing.T) {
	// G(t, c) = SHA-1圧縮関数（初期状態t, ブロックc）
	// パディングなしで呼ぶため、sha1.Sum()とは異なる結果になるはず
	block := make([]byte, 64)
	for i := range block {
		block[i] = byte(i)
	}

	state := sha1InitH
	sha1Compress(&state, block)

	// sha1.Sum(block) はパディングを追加するので異なるはず
	stdResult := sha1.Sum(block)
	var compressResult [20]byte
	binary.BigEndian.PutUint32(compressResult[0:4], state[0])
	binary.BigEndian.PutUint32(compressResult[4:8], state[1])
	binary.BigEndian.PutUint32(compressResult[8:12], state[2])
	binary.BigEndian.PutUint32(compressResult[12:16], state[3])
	binary.BigEndian.PutUint32(compressResult[16:20], state[4])

	if compressResult == stdResult {
		t.Error("G関数（パディングなし）がsha1.Sum（パディングあり）と同じ結果 - これは誤り")
	}
}
