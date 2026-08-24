package pkcs7

import (
	"crypto"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestVerifyDetachedSupportedRSAAlgorithmIdentifiers(t *testing.T) {
	certDER, privateKey := buildTestCert(t)
	content := []byte("synthetic payload for RSA algorithm-identifier coverage")
	null := asn1.RawValue{Tag: asn1.TagNull}
	tests := []struct {
		name         string
		digestOID    asn1.ObjectIdentifier
		signatureOID asn1.ObjectIdentifier
		parameters   asn1.RawValue
		digestHash   crypto.Hash
	}{
		{"rsa-sha256", oidSHA256, oidRSAEncryption, null, crypto.SHA256},
		{"rsa-sha384", oidSHA384, oidRSAEncryption, null, crypto.SHA384},
		{"rsa-sha512", oidSHA512, oidRSAEncryption, null, crypto.SHA512},
		{"sha256-with-rsa-null", oidSHA256, oidSHA256WithRSA, null, crypto.SHA256},
		{"sha384-with-rsa-null", oidSHA384, oidSHA384WithRSA, null, crypto.SHA384},
		{"sha512-with-rsa-null", oidSHA512, oidSHA512WithRSA, null, crypto.SHA512},
		{"sha256-with-rsa-absent", oidSHA256, oidSHA256WithRSA, asn1.RawValue{}, crypto.SHA256},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der := buildSignedDataWithOptions(t, certDER, privateKey, content, signedDataOptions{
				digestOID:           test.digestOID,
				signatureOID:        test.signatureOID,
				signatureParameters: test.parameters,
				digestHash:          test.digestHash,
			})
			sd, err := ParseSignedData(der)
			if err != nil {
				t.Fatalf("ParseSignedData: %v", err)
			}
			results := VerifyDetached(sd, content)
			if len(results) != 1 || !results[0].Valid {
				t.Fatalf("expected valid signature, got %+v", results)
			}
		})
	}
}

func TestVerifyDetachedRejectsUnsupportedRSAAlgorithmIdentifiers(t *testing.T) {
	certDER, privateKey := buildTestCert(t)
	content := []byte("synthetic payload for rejected RSA algorithm identifiers")
	null := asn1.RawValue{Tag: asn1.TagNull}
	integer := asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte{1}}
	pssParameters := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}
	oidRSASSAPSS := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECDSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	tests := []struct {
		name         string
		digestOID    asn1.ObjectIdentifier
		signatureOID asn1.ObjectIdentifier
		parameters   asn1.RawValue
		digestHash   crypto.Hash
		wantReason   string
	}{
		{"rsa-parameters-absent", oidSHA256, oidRSAEncryption, asn1.RawValue{}, crypto.SHA256, "parameters must be NULL"},
		{"rsa-parameters-integer", oidSHA256, oidRSAEncryption, integer, crypto.SHA256, "parameters must be NULL"},
		{"combined-parameters-integer", oidSHA256, oidSHA256WithRSA, integer, crypto.SHA256, "parameters must be NULL or absent"},
		{"combined-digest-mismatch", oidSHA256, oidSHA384WithRSA, null, crypto.SHA256, "does not match digest algorithm"},
		{"unsupported-rsa-pss", oidSHA256, oidRSASSAPSS, pssParameters, crypto.SHA256, "unsupported signature algorithm"},
		{"non-rsa-signature", oidSHA256, oidECDSAWithSHA256, asn1.RawValue{}, crypto.SHA256, "unsupported signature algorithm"},
		{"signature-oid-as-digest", oidSHA256WithRSA, oidSHA256WithRSA, null, crypto.SHA256, "unsupported digest algorithm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der := buildSignedDataWithOptions(t, certDER, privateKey, content, signedDataOptions{
				digestOID:           test.digestOID,
				signatureOID:        test.signatureOID,
				signatureParameters: test.parameters,
				digestHash:          test.digestHash,
			})
			sd, err := ParseSignedData(der)
			if err != nil {
				t.Fatalf("ParseSignedData: %v", err)
			}
			results := VerifyDetached(sd, content)
			if len(results) != 1 || results[0].Valid {
				t.Fatalf("expected invalid signature, got %+v", results)
			}
			if !strings.Contains(results[0].Reason, test.wantReason) {
				t.Fatalf("reason = %q, want substring %q", results[0].Reason, test.wantReason)
			}
		})
	}
}
