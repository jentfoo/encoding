package base85

import (
	"bytes"
	"encoding/ascii85"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ASCII85 alphabet for testing against standard library
// Characters '!' (33) through 'u' (117)
const ascii85Alphabet = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"

var ascii85Encoding = NewEncoding(ascii85Alphabet)

func TestEncodeToString(t *testing.T) {
	t.Parallel()

	// bytes for "日本語" without triggering gosmopolitan
	unicodeBytes := []byte{0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xe8, 0xaa, 0x9e}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"single_byte", []byte{0x01}},
		{"two_bytes", []byte{0x01, 0x02}},
		{"three_bytes", []byte{0x01, 0x02, 0x03}},
		{"four_bytes", []byte{0x01, 0x02, 0x03, 0x04}},
		{"five_bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"eight_bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"hello_world", []byte("Hello, World!")},
		{"binary_data", []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}},
		{"high_values", []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"mixed_content", []byte("Test\x00\x01\x02data")},
		{"unicode", unicodeBytes},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := ascii85Encoding.EncodeToString(tc.input)

			// verify via standard library decode
			dst := make([]byte, len(tc.input)+4)
			ndst, _, err := ascii85.Decode(dst, []byte(encoded), true)

			require.NoError(t, err)
			assert.Equal(t, tc.input, dst[:ndst])
		})
	}
}

func TestAppendEncode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix []byte
		input  []byte
	}{
		{"empty_prefix", nil, []byte("test")},
		{"with_prefix", []byte("prefix:"), []byte("data")},
		{"empty_input", []byte("prefix:"), []byte{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ascii85Encoding.AppendEncode(tc.prefix, tc.input)

			// verify prefix is preserved
			if tc.prefix != nil {
				assert.Equal(t, string(tc.prefix), string(result[:len(tc.prefix)]))
			}

			// extract encoded portion and decode
			encodedPortion := result[len(tc.prefix):]
			dst := make([]byte, len(tc.input)+4)
			ndst, _, err := ascii85.Decode(dst, encodedPortion, true)

			require.NoError(t, err)
			assert.Equal(t, tc.input, dst[:ndst])
		})
	}
}

func TestNewEncoder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  []byte
		writes []int // chunk sizes for multiple writes
	}{
		{"empty", []byte{}, nil},
		{"single_byte", []byte{0x01}, nil},
		{"four_bytes", []byte{0x01, 0x02, 0x03, 0x04}, nil},
		{"five_bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, nil},
		{"hello_world", []byte("Hello, World!"), nil},
		{"chunked_write", []byte("Hello, World!"), []int{3, 5, 5}},
		{"byte_by_byte", []byte("test"), []int{1, 1, 1, 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := NewEncoder(ascii85Encoding, &buf)

			if tc.writes == nil {
				// single write
				n, err := enc.Write(tc.input)
				require.NoError(t, err)
				assert.Equal(t, len(tc.input), n)
			} else {
				// multiple writes
				offset := 0
				for _, size := range tc.writes {
					end := offset + size
					if end > len(tc.input) {
						end = len(tc.input)
					}
					n, err := enc.Write(tc.input[offset:end])
					require.NoError(t, err)
					assert.Equal(t, end-offset, n)
					offset = end
				}
			}

			require.NoError(t, enc.Close())

			// verify via standard library decode
			encoded := buf.Bytes()
			dst := make([]byte, len(tc.input)+4)
			ndst, _, err := ascii85.Decode(dst, encoded, true)

			require.NoError(t, err)
			assert.Equal(t, tc.input, dst[:ndst])
		})
	}
}
