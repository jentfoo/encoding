package base85

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzEncode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{255})
	f.Add([]byte("Hello, World!"))
	f.Add([]byte("The quick brown fox jumps over the lazy dog"))

	// block boundary cases (base85 works in 4-byte blocks)
	f.Add([]byte{1, 2, 3, 4})          // exact block
	f.Add([]byte{1, 2, 3, 4, 5})       // one block + 1
	f.Add([]byte{1, 2, 3, 4, 5, 6})    // one block + 2
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7}) // one block + 3

	// partial blocks
	f.Add([]byte{1})
	f.Add([]byte{1, 2})
	f.Add([]byte{1, 2, 3})

	// all zeros and all ones
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255})

	// binary data patterns
	f.Add([]byte{0x00, 0x7F, 0x80, 0xFF})
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		encoded := RFC1924.EncodeToString(data) // should never panic

		// round-trip should recover original data
		decoded, err := RFC1924.DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, data, decoded)
	})
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{})

	// valid RFC1924 encoded strings
	f.Add([]byte("0"))          // partial block (invalid - too short)
	f.Add([]byte("00"))         // minimal valid partial block
	f.Add([]byte("0000000000")) // two full blocks worth

	// encoded "Hello"
	f.Add([]byte("BOu!rDZ"))

	// whitespace handling
	f.Add([]byte("BOu!r DZ"))
	f.Add([]byte("BOu!r\nDZ"))
	f.Add([]byte("BOu!r\tDZ"))
	f.Add([]byte("  BOu!rDZ  "))

	// invalid characters (should return error, not panic)
	f.Add([]byte("invalid\"chars"))
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte{0xFF, 0xFE, 0xFD})

	// boundary alphabet characters
	f.Add([]byte("0"))             // first alphabet char
	f.Add([]byte("~"))             // last alphabet char
	f.Add([]byte("09AZaz!#$%&()")) // mixed alphabet chars

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = RFC1924.DecodeString(string(data)) // should never panic (errors are acceptable)
	})
}

func FuzzEncodeWithPadding(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("test"))
	f.Add([]byte("hello world"))

	// partial blocks that need padding
	f.Add([]byte{1})
	f.Add([]byte{1, 2})
	f.Add([]byte{1, 2, 3})

	// exact blocks (no padding needed)
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	f.Fuzz(func(t *testing.T, data []byte) {
		// use '.' as padding since '=' is in RFC1924 alphabet
		enc := RFC1924.WithPadding('.')

		// encoding should never panic
		encoded := enc.EncodeToString(data)

		// with padding, length should always be multiple of 5
		if len(data) > 0 && len(encoded)%5 != 0 {
			t.Errorf("padded encoding length %d not multiple of 5", len(encoded))
		}

		// round-trip should recover original data
		decoded, err := enc.DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, data, decoded)
	})
}

func FuzzStreamRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add(make([]byte, 100))
	f.Add([]byte("The quick brown fox jumps over the lazy dog"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// encode using stream encoder
		var encoded bytes.Buffer
		encoder := NewEncoder(RFC1924, &encoded)
		_, err := encoder.Write(data)
		require.NoError(t, err)
		require.NoError(t, encoder.Close())

		// decode using stream decoder
		decoder := NewDecoder(RFC1924, &encoded)
		var decoded bytes.Buffer
		_, err = decoded.ReadFrom(decoder)
		require.NoError(t, err)
		assert.Equal(t, data, decoded.Bytes())
	})
}

func FuzzDecodeWithPadding(f *testing.F) {
	f.Add([]byte{})

	// use '.' as padding since '=' is in RFC1924 alphabet
	enc := RFC1924.WithPadding('.')

	// valid padded encodings
	f.Add([]byte("00..."))      // 1 byte padded
	f.Add([]byte("000.."))      // 2 bytes padded
	f.Add([]byte("0000."))      // 3 bytes padded
	f.Add([]byte("00000"))      // full block, no padding
	f.Add([]byte("0000000000")) // two full blocks
	f.Add([]byte("00000000..")) // one full + 2 bytes padded
	f.Add([]byte("BOu!rDZ.."))  // encoded "Hello" with padding

	// invalid padding patterns (should error, not panic)
	f.Add([]byte(".....")) // all padding
	f.Add([]byte("0....")) // only 1 data char
	f.Add([]byte("00.0.")) // padding in middle
	f.Add([]byte("...00")) // padding at start

	// mixed valid/invalid
	f.Add([]byte("00000.....")) // full block + all padding block
	f.Add([]byte{0x00, 0x01, '.', '.', '.'})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = enc.DecodeString(string(data)) // should never panic (errors are acceptable)
	})
}

func FuzzStreamRoundTripWithPadding(f *testing.F) {
	// various sizes to test buffering with padding
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, 2})
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add(make([]byte, 100))
	f.Add([]byte("The quick brown fox jumps over the lazy dog"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// use '.' as padding since '=' is in RFC1924 alphabet
		enc := RFC1924.WithPadding('.')

		// encode using stream encoder
		var encoded bytes.Buffer
		encoder := NewEncoder(enc, &encoded)
		_, err := encoder.Write(data)
		require.NoError(t, err)
		require.NoError(t, encoder.Close())

		// decode using stream decoder
		decoder := NewDecoder(enc, &encoded)
		var decoded bytes.Buffer
		_, err = decoded.ReadFrom(decoder)
		require.NoError(t, err)
		assert.Equal(t, data, decoded.Bytes())
	})
}
