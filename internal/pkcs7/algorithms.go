package pkcs7

import (
	"crypto"
	"encoding/asn1"
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
	case oid.Equal(oidSHA256), oid.Equal(oidSHA256WithRSA):
		return crypto.SHA256
	case oid.Equal(oidSHA384), oid.Equal(oidSHA384WithRSA):
		return crypto.SHA384
	case oid.Equal(oidSHA512), oid.Equal(oidSHA512WithRSA):
		return crypto.SHA512
	default:
		return 0
	}
}

func hashOIDName(oid asn1.ObjectIdentifier) string {
	switch hashOIDToHash(oid) {
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	default:
		return oid.String()
	}
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
