package pkcs7

import (
	"bytes"
	"strings"
	"testing"
)

func TestBERLongFormLengthOverflowDoesNotPanic(t *testing.T) {
	tests := map[string][]byte{
		"uint64-max":      {0x04, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"over-max-int64":  {0x04, 0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"over-max-uint32": {0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00},
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := berToDERNoPanic(t, input)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestBERRejectsMalformedInputs(t *testing.T) {
	tests := map[string][]byte{
		"empty":                   {},
		"identifier-only":         {0x04},
		"truncated-high-tag":      {0x1f, 0x81},
		"primitive-indefinite":    {0x04, 0x80, 0x00, 0x00},
		"long-length-count":       {0x04, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"truncated-long-length":   {0x04, 0x82, 0x01},
		"length-exceeds-input":    {0x04, 0x82, 0x01, 0x00},
		"unterminated-indefinite": {0x30, 0x80, 0x04, 0x00},
		"malformed-child":         {0x30, 0x01, 0x04},
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := berToDERNoPanic(t, input)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestBERValidDefiniteAndIndefiniteRegression(t *testing.T) {
	tests := map[string]struct {
		input    []byte
		wantDER  []byte
		consumed int
	}{
		"definite": {
			input:    []byte{0x30, 0x03, 0x02, 0x01, 0x01, 0xde, 0xad},
			wantDER:  []byte{0x30, 0x03, 0x02, 0x01, 0x01},
			consumed: 5,
		},
		"indefinite": {
			input:    []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0xde, 0xad},
			wantDER:  []byte{0x30, 0x03, 0x02, 0x01, 0x01},
			consumed: 7,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, consumed, err := berToDER(test.input)
			if err != nil {
				t.Fatalf("berToDER: %v", err)
			}
			if !bytes.Equal(got, test.wantDER) {
				t.Fatalf("DER = %x, want %x", got, test.wantDER)
			}
			if consumed != test.consumed {
				t.Fatalf("consumed = %d, want %d", consumed, test.consumed)
			}
		})
	}
}

func TestBERLimits(t *testing.T) {
	t.Run("depth allows boundary", func(t *testing.T) {
		if _, _, err := berToDER(nestedIndefiniteBER(maxBERDepth)); err != nil {
			t.Fatalf("berToDER at depth limit: %v", err)
		}
	})
	t.Run("depth rejects excess", func(t *testing.T) {
		_, _, err := berToDER(nestedIndefiniteBER(maxBERDepth + 1))
		if err == nil || !strings.Contains(err.Error(), "nesting depth") {
			t.Fatalf("err = %v, want nesting-depth error", err)
		}
	})

	input := []byte{0x04, 0x02, 0xaa, 0xbb}
	for name, adjust := range map[string]func(*berLimits){
		"input":  func(l *berLimits) { l.inputSize = len(input) - 1 },
		"output": func(l *berLimits) { l.outputSize = len(input) - 1 },
		"work":   func(l *berLimits) { l.work = len(input) - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			limits := defaultBERLimits
			adjust(&limits)
			if _, _, err := berToDERWithLimits(input, limits); err == nil {
				t.Fatalf("expected %s limit error", name)
			}
		})
	}
}

func nestedIndefiniteBER(depth int) []byte {
	out := []byte{0x04, 0x00}
	for i := 1; i < depth; i++ {
		wrapped := make([]byte, 0, len(out)+4)
		wrapped = append(wrapped, 0x30, 0x80)
		wrapped = append(wrapped, out...)
		wrapped = append(wrapped, 0x00, 0x00)
		out = wrapped
	}
	return out
}

func FuzzBERToDERNoPanic(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x04, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00},
		{0x30, 0x03, 0x02, 0x01, 0x01},
		{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00},
		nestedIndefiniteBER(maxBERDepth + 1),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = berToDER(input)
		_, _ = ParseSignedData(input)
	})
}

func berToDERNoPanic(t *testing.T, input []byte) (der []byte, consumed int, err error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("berToDER panicked: %v", recovered)
		}
	}()
	return berToDER(input)
}
