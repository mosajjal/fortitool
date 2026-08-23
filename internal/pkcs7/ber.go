package pkcs7

import "fmt"

// Detached signature wrappers are small; these ceilings leave generous
// headroom while bounding recursive normalization and repeated copying.
const (
	maxBERInputSize  = 64 << 20
	maxDEROutputSize = 64 << 20
	maxBERDepth      = 64
	maxBERWork       = 256 << 20
)

type berLimits struct {
	inputSize  int
	outputSize int
	depth      int
	work       int
}

var defaultBERLimits = berLimits{
	inputSize:  maxBERInputSize,
	outputSize: maxDEROutputSize,
	depth:      maxBERDepth,
	work:       maxBERWork,
}

type berDecoder struct {
	limits berLimits
	work   int
}

// berToDER converts one top-level BER-encoded TLV into DER, i.e. it
// rewrites any BER indefinite-length constructed elements (identifier
// followed by a 0x80 length octet, terminated by an EOC 0x00 0x00 marker)
// into definite-length form. FortiOS .x signature files are emitted by
// OpenSSL with the outer ContentInfo SEQUENCE, its [0] explicit content
// wrapper, the SignedData SEQUENCE, and the certificates [0] IMPLICIT SET
// all using indefinite length -- Go's encoding/asn1 only accepts DER, so
// this preprocessing step is required before any asn1.Unmarshal call.
//
// It returns the normalized bytes for the single leading element and the
// number of input bytes consumed by it; trailing bytes (FortiOS appends a
// 16-byte "TNTF" footer after the ASN.1 blob) are left for the caller to
// ignore.
func berToDER(data []byte) ([]byte, int, error) {
	return berToDERWithLimits(data, defaultBERLimits)
}

func berToDERWithLimits(data []byte, limits berLimits) ([]byte, int, error) {
	if len(data) > limits.inputSize {
		return nil, 0, fmt.Errorf("BER input length %d exceeds limit %d", len(data), limits.inputSize)
	}
	decoder := berDecoder{limits: limits}
	return decoder.convert(data, 1)
}

func (d *berDecoder) convert(data []byte, depth int) ([]byte, int, error) {
	if depth > d.limits.depth {
		return nil, 0, fmt.Errorf("BER nesting depth exceeds limit %d", d.limits.depth)
	}
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("truncated BER element: need at least 2 bytes, got %d", len(data))
	}
	off := 0
	idStart := off
	b := data[off]
	off++
	if b&0x1F == 0x1F {
		for {
			if off >= len(data) {
				return nil, 0, fmt.Errorf("truncated multi-byte tag")
			}
			c := data[off]
			off++
			if c&0x80 == 0 {
				break
			}
		}
	}
	identifier := data[idStart:off]
	constructed := identifier[0]&0x20 != 0

	if off >= len(data) {
		return nil, 0, fmt.Errorf("truncated length octet")
	}
	lb := data[off]
	off++
	indefinite := false
	var length int
	switch {
	case lb == 0x80:
		indefinite = true
	case lb&0x80 == 0:
		length = int(lb)
	default:
		n := int(lb & 0x7F)
		if n == 0 || n > 8 || n > len(data)-off {
			return nil, 0, fmt.Errorf("bad long-form length octet count %d", n)
		}
		var encodedLength uint64
		for i := 0; i < n; i++ {
			encodedLength = encodedLength<<8 | uint64(data[off])
			off++
		}
		if encodedLength > uint64(len(data)-off) {
			return nil, 0, fmt.Errorf("definite length %d exceeds remaining %d bytes", encodedLength, len(data)-off)
		}
		length = int(encodedLength)
	}

	if indefinite {
		if !constructed {
			return nil, 0, fmt.Errorf("primitive element cannot use indefinite length")
		}
		var content []byte
		for {
			if len(data)-off >= 2 && data[off] == 0x00 && data[off+1] == 0x00 {
				off += 2
				break
			}
			if off >= len(data) {
				return nil, 0, fmt.Errorf("unterminated indefinite-length element")
			}
			child, n, err := d.convert(data[off:], depth+1)
			if err != nil {
				return nil, 0, fmt.Errorf("indefinite-length child at offset %d: %w", off, err)
			}
			content, err = d.appendContent(content, child)
			if err != nil {
				return nil, 0, err
			}
			off += n
		}
		out, err := d.makeTLV(identifier, content)
		return out, off, err
	}

	if length > len(data)-off {
		return nil, 0, fmt.Errorf("definite length %d exceeds remaining %d bytes", length, len(data)-off)
	}
	raw := data[off : off+length]
	off += length

	if !constructed {
		out, err := d.makeTLV(identifier, raw)
		return out, off, err
	}

	var content []byte
	for pos := 0; pos < len(raw); {
		child, n, err := d.convert(raw[pos:], depth+1)
		if err != nil {
			return nil, 0, fmt.Errorf("definite-length constructed child at offset %d: %w", pos, err)
		}
		content, err = d.appendContent(content, child)
		if err != nil {
			return nil, 0, err
		}
		pos += n
	}
	out, err := d.makeTLV(identifier, content)
	return out, off, err
}

func (d *berDecoder) appendContent(dst, src []byte) ([]byte, error) {
	if len(src) > d.limits.outputSize-len(dst) {
		return nil, fmt.Errorf("normalized DER content exceeds output limit %d", d.limits.outputSize)
	}
	if err := d.consumeWork(len(src)); err != nil {
		return nil, err
	}
	return append(dst, src...), nil
}

func (d *berDecoder) makeTLV(identifier, content []byte) ([]byte, error) {
	length := encodeDERLength(len(content))
	if len(identifier) > d.limits.outputSize-len(length) || len(content) > d.limits.outputSize-len(identifier)-len(length) {
		return nil, fmt.Errorf("normalized DER element exceeds output limit %d", d.limits.outputSize)
	}
	outLen := len(identifier) + len(length) + len(content)
	if err := d.consumeWork(outLen); err != nil {
		return nil, err
	}
	out := make([]byte, 0, outLen)
	out = append(out, identifier...)
	out = append(out, length...)
	out = append(out, content...)
	return out, nil
}

func (d *berDecoder) consumeWork(n int) error {
	if n > d.limits.work-d.work {
		return fmt.Errorf("BER normalization work exceeds limit %d", d.limits.work)
	}
	d.work += n
	return nil
}

func encodeDERLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xFF)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}
