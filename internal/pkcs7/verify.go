package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
)

// VerifyResult is the outcome of checking one SignerInfo's signature.
type VerifyResult struct {
	Signer *SignerInfo
	Valid  bool
	Reason string
}

// VerifyDetached verifies every SignerInfo in sd against externally
// supplied content bytes (the detached payload, e.g. libips.so.new). It
// handles both PKCS#7 signing modes: the signature computed directly over
// the content digest, and the signature computed over the DER encoding of
// authenticatedAttributes (in which case a messageDigest attribute must
// itself equal the content digest). Returns one VerifyResult per signer,
// in the same order as sd.Signers.
func VerifyDetached(sd *SignedData, content []byte) []VerifyResult {
	results := make([]VerifyResult, len(sd.Signers))
	for i := range sd.Signers {
		results[i] = verifySigner(&sd.Signers[i], content)
	}
	return results
}

func verifySigner(si *SignerInfo, content []byte) VerifyResult {
	if si.digestHash == 0 {
		return VerifyResult{Signer: si, Reason: fmt.Sprintf("unsupported digest algorithm %s", si.DigestAlgorithm)}
	}
	if si.Certificate == nil {
		return VerifyResult{Signer: si, Reason: "no certificate for signer"}
	}
	pub, ok := si.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return VerifyResult{Signer: si, Reason: "signer certificate does not carry an RSA public key"}
	}

	var signedBytes []byte
	if si.authenticatedAttrs != nil {
		// RFC 2315 signs the DER re-encoding of authenticatedAttributes as
		// a genuine SET OF, not as the implicit [0]-tagged blob it appears
		// as in the SignerInfo. The captured raw bytes start with an
		// implicit-tag identifier octet (0xA0, low-tag-number context
		// class 0, constructed); swapping just that leading byte for 0x31
		// (SET, universal, constructed) reproduces the SET encoding that
		// was actually hashed, since DER length/content octets are
		// identical either way.
		rewritten := append([]byte{}, si.authenticatedAttrs...)
		rewritten[0] = 0x31

		attrsRV, _, err := readTLV(rewritten)
		if err != nil {
			return VerifyResult{Signer: si, Reason: fmt.Sprintf("re-parsing authenticatedAttributes: %v", err)}
		}
		msgDigest, err := findMessageDigest(attrsRV.Bytes)
		if err != nil {
			return VerifyResult{Signer: si, Reason: err.Error()}
		}
		contentDigest := hashSum(si.digestHash, content)
		if !bytes.Equal(msgDigest, contentDigest) {
			return VerifyResult{Signer: si, Reason: "messageDigest mismatch"}
		}
		signedBytes = rewritten
	} else {
		signedBytes = content
	}

	digest := hashSum(si.digestHash, signedBytes)
	if err := rsa.VerifyPKCS1v15(pub, si.digestHash, digest, si.encryptedDigest); err != nil {
		return VerifyResult{Signer: si, Reason: fmt.Sprintf("RSA signature invalid: %v", err)}
	}

	return VerifyResult{Signer: si, Valid: true}
}

func findMessageDigest(attrsBody []byte) ([]byte, error) {
	for rem := attrsBody; len(rem) > 0; {
		attrRV, r2, err := readTLV(rem)
		if err != nil {
			return nil, fmt.Errorf("reading authenticatedAttribute: %w", err)
		}
		rem = r2

		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}
		if _, err := asn1.Unmarshal(attrRV.FullBytes, &attr); err != nil {
			return nil, fmt.Errorf("parsing authenticatedAttribute: %w", err)
		}
		if !attr.Type.Equal(oidMessageDigest) {
			continue
		}
		var digest []byte
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &digest); err != nil {
			return nil, fmt.Errorf("parsing messageDigest attribute value: %w", err)
		}
		return digest, nil
	}
	return nil, fmt.Errorf("no messageDigest attribute present")
}

func hashSum(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	default:
		return nil
	}
}
