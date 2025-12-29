package base85

import (
	"encoding/ascii85"
	"testing"
)

var benchData = []byte("The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()")

func BenchmarkEncodeBase85(b *testing.B) {
	dst := make([]byte, RFC1924.EncodedLen(len(benchData)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RFC1924.Encode(dst, benchData)
	}
}

func BenchmarkDecodeBase85(b *testing.B) {
	encoded := RFC1924.EncodeToString(benchData)
	src := []byte(encoded)
	dst := make([]byte, RFC1924.DecodedLen(len(src)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = RFC1924.Decode(dst, src)
	}
}

func BenchmarkEncodeAscii85(b *testing.B) {
	dst := make([]byte, ascii85.MaxEncodedLen(len(benchData)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ascii85.Encode(dst, benchData)
	}
}

func BenchmarkDecodeAscii85(b *testing.B) {
	src := make([]byte, ascii85.MaxEncodedLen(len(benchData)))
	n := ascii85.Encode(src, benchData)
	src = src[:n]
	dst := make([]byte, len(benchData))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = ascii85.Decode(dst, src, true)
	}
}
