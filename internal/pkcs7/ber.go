package pkcs7

import "fmt"

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
		if n == 0 || n > 8 || off+n > len(data) {
			return nil, 0, fmt.Errorf("bad long-form length octet count %d", n)
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(data[off])
			off++
		}
	}

	if indefinite {
		if !constructed {
			return nil, 0, fmt.Errorf("primitive element cannot use indefinite length")
		}
		var content []byte
		for {
			if off+2 <= len(data) && data[off] == 0x00 && data[off+1] == 0x00 {
				off += 2
				break
			}
			if off >= len(data) {
				return nil, 0, fmt.Errorf("unterminated indefinite-length element")
			}
			child, n, err := berToDER(data[off:])
			if err != nil {
				return nil, 0, fmt.Errorf("indefinite-length child at offset %d: %w", off, err)
			}
			content = append(content, child...)
			off += n
		}
		out := append(append([]byte{}, identifier...), encodeDERLength(len(content))...)
		out = append(out, content...)
		return out, off, nil
	}

	if off+length > len(data) {
		return nil, 0, fmt.Errorf("definite length %d exceeds remaining %d bytes", length, len(data)-off)
	}
	raw := data[off : off+length]
	off += length

	if !constructed {
		out := append(append([]byte{}, identifier...), encodeDERLength(length)...)
		out = append(out, raw...)
		return out, off, nil
	}

	var content []byte
	pos := 0
	for pos < len(raw) {
		child, n, err := berToDER(raw[pos:])
		if err != nil {
			return nil, 0, fmt.Errorf("definite-length constructed child at offset %d: %w", pos, err)
		}
		content = append(content, child...)
		pos += n
	}
	out := append(append([]byte{}, identifier...), encodeDERLength(len(content))...)
	out = append(out, content...)
	return out, off, nil
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
