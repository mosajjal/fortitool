package pkcs7

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
)

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

func hashOIDToHash(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	default:
		return 0
	}
}

// RFC 3370 section 3.2 requires NULL parameters for rsaEncryption;
// RFC 5754 section 3.2 requires SHA-2-with-RSA verifiers to accept both
// NULL and absent parameters even though senders use NULL.
func validateSignatureAlgorithm(oid asn1.ObjectIdentifier, parameters asn1.RawValue, digestHash crypto.Hash) error {
	switch {
	case oid.Equal(oidRSAEncryption):
		if !bytes.Equal(parameters.FullBytes, []byte{0x05, 0x00}) {
			return fmt.Errorf("RSA signature algorithm %s parameters must be NULL", oid)
		}
		return nil
	case oid.Equal(oidSHA256WithRSA), oid.Equal(oidSHA384WithRSA), oid.Equal(oidSHA512WithRSA):
		if len(parameters.FullBytes) != 0 && !bytes.Equal(parameters.FullBytes, []byte{0x05, 0x00}) {
			return fmt.Errorf("RSA signature algorithm %s parameters must be NULL or absent", oid)
		}
		signatureHash := signatureOIDHash(oid)
		if signatureHash != digestHash {
			return fmt.Errorf("signature algorithm %s does not match digest algorithm %s", oid, hashName(digestHash))
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature algorithm %s", oid)
	}
}

func signatureOIDHash(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return crypto.SHA256
	case oid.Equal(oidSHA384WithRSA):
		return crypto.SHA384
	case oid.Equal(oidSHA512WithRSA):
		return crypto.SHA512
	default:
		return 0
	}
}

func hashName(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	default:
		return "unsupported"
	}
}

func hashOIDName(oid asn1.ObjectIdentifier) string {
	if name := hashName(hashOIDToHash(oid)); name != "unsupported" {
		return name
	}
	return oid.String()
}

func sigOIDName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidRSAEncryption), oid.Equal(oidSHA256WithRSA),
		oid.Equal(oidSHA384WithRSA), oid.Equal(oidSHA512WithRSA):
		return "RSA"
	default:
		return oid.String()
	}
}
