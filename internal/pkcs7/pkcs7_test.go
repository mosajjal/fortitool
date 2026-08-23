package pkcs7

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// This test hand-builds a minimal PKCS#7 SignedData DER structure (no
// authenticatedAttributes -- the simpler of the two signing modes) around
// a locally-generated, throwaway self-signed certificate, so the parser
// and verifier are exercised without any real Fortinet signature data.

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for tmp := n; tmp > 0; tmp >>= 8 {
		b = append([]byte{byte(tmp & 0xFF)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func derTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLen(len(content))...), content...)
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return b
}

type algIdASN1 struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func buildTestCert(t *testing.T) (der []byte, priv *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC0FFEE),
		Subject:      pkix.Name{CommonName: "fortitool-test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der, priv
}

// buildSignedData assembles a ContentInfo/SignedData DER blob signing
// `content` directly (no authenticatedAttributes) with the given cert/key.
func buildSignedData(t *testing.T, certDER []byte, priv *rsa.PrivateKey, content []byte) []byte {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	digestAlgorithms := derTLV(0x31, marshal(t, algIdASN1{Algorithm: oidSHA256})) // SET OF
	innerContentInfo := marshal(t, struct{ ContentType asn1.ObjectIdentifier }{
		asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, // id-data
	})
	certificates := derTLV(0xA0, certDER) // [0] IMPLICIT SET OF Certificate

	issuerAndSerial := append(cert.RawIssuer, marshal(t, cert.SerialNumber)...)
	issuerAndSerialSeq := derTLV(0x30, issuerAndSerial)
	digAlg := marshal(t, algIdASN1{Algorithm: oidSHA256})
	sigAlg := marshal(t, algIdASN1{Algorithm: oidRSAEncryption})
	encDigest := marshal(t, sig)

	signerInfoBody := append([]byte{}, marshal(t, 1)...) // version
	signerInfoBody = append(signerInfoBody, issuerAndSerialSeq...)
	signerInfoBody = append(signerInfoBody, digAlg...)
	signerInfoBody = append(signerInfoBody, sigAlg...)
	signerInfoBody = append(signerInfoBody, encDigest...)
	signerInfo := derTLV(0x30, signerInfoBody)
	signerInfos := derTLV(0x31, signerInfo) // SET OF

	sdBody := append([]byte{}, marshal(t, 1)...) // version
	sdBody = append(sdBody, digestAlgorithms...)
	sdBody = append(sdBody, innerContentInfo...)
	sdBody = append(sdBody, certificates...)
	sdBody = append(sdBody, signerInfos...)
	signedData := derTLV(0x30, sdBody)

	explicitContent := derTLV(0xA0, signedData)
	ciBody := append([]byte{}, marshal(t, oidSignedData)...)
	ciBody = append(ciBody, explicitContent...)
	return derTLV(0x30, ciBody)
}

func TestParseAndVerifySignedData(t *testing.T) {
	certDER, priv := buildTestCert(t)
	content := []byte("fortitool synthetic payload for pkcs7 verification")
	der := buildSignedData(t, certDER, priv, content)

	sd, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(sd.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(sd.Certificates))
	}
	if len(sd.Signers) != 1 {
		t.Fatalf("got %d signers, want 1", len(sd.Signers))
	}
	if sd.Signers[0].DigestAlgorithm != "SHA-256" {
		t.Fatalf("digest algorithm = %q", sd.Signers[0].DigestAlgorithm)
	}
	if sd.Signers[0].Certificate == nil {
		t.Fatal("signer certificate did not resolve against SignedData.Certificates")
	}

	results := VerifyDetached(sd, content)
	if len(results) != 1 || !results[0].Valid {
		t.Fatalf("expected a valid signature, got %+v", results)
	}

	tamperedResults := VerifyDetached(sd, append(content, 'X'))
	if tamperedResults[0].Valid {
		t.Fatal("expected verification to fail against tampered content")
	}
}

func TestFindPackageIDs(t *testing.T) {
	payload := []byte("junk 06004000NIDS00105-000070059-2601051815 more junk 06004000MUDB00103-000010001-2501010101 tail")
	ids := FindPackageIDs(payload, 8)
	if len(ids) != 2 {
		t.Fatalf("got %d ids, want 2: %v", len(ids), ids)
	}
	for _, limit := range []int{0, -1} {
		if ids := FindPackageIDs(payload, limit); len(ids) != 0 {
			t.Fatalf("limit %d returned %d ids: %v", limit, len(ids), ids)
		}
	}
}
