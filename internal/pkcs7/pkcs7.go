// Package pkcs7 parses PKCS#7 (RFC 2315) SignedData structures and
// verifies detached signatures against them, replacing shell-outs to
// `openssl pkcs7`/`asn1parse`/`smime -verify`.
//
// FortiOS ships IPS/AV engines and rule databases as a payload file plus a
// detached ".x" signature wrapper (e.g. libips.so.new + libips.so.new.x).
// Each wrapper is typically dual-signed: SignedData.Certificates holds two
// independent chains (an internal Fortinet PKI chain and a public DigiCert
// code-signing chain) and SignedData.Signers holds one SignerInfo per
// chain.
//
// Verification here is a detached-signature integrity check only -- it
// confirms the signature validates against the enclosed certificate's
// public key and the supplied content, matching `openssl smime -verify
// -noverify`. It does not build or validate a trust chain to a root CA.
package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// SignedData is a parsed PKCS#7 SignedData structure.
type SignedData struct {
	DigestAlgorithms []string
	Certificates     []*x509.Certificate
	Signers          []SignerInfo
}

// SignerInfo is one signer entry from a SignedData's signerInfos set.
type SignerInfo struct {
	DigestAlgorithm    string
	SignatureAlgorithm string
	IssuerDN           string
	SerialNumber       string
	Certificate        *x509.Certificate

	digestHash          crypto.Hash
	signatureOID        asn1.ObjectIdentifier
	signatureParameters asn1.RawValue
	rawIssuer           []byte
	serial              *big.Int
	authenticatedAttrs  []byte // raw [0] IMPLICIT SET bytes, nil if absent
	encryptedDigest     []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// readTLV reads a single BER/DER TLV element off the front of data,
// returning it as a RawValue and the remaining bytes.
func readTLV(data []byte) (asn1.RawValue, []byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(data, &rv)
	if err != nil {
		return asn1.RawValue{}, nil, err
	}
	return rv, rest, nil
}

// ParseSignedData parses a DER-encoded (or BER-with-indefinite-lengths, as
// OpenSSL emits) PKCS#7 ContentInfo/SignedData blob -- a detached .x
// signature file's raw bytes.
func ParseSignedData(der []byte) (*SignedData, error) {
	normalized, _, err := berToDER(der)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: normalizing BER to DER: %w", err)
	}

	ciRV, _, err := readTLV(normalized)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading ContentInfo: %w", err)
	}
	oidRV, rest, err := readTLV(ciRV.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading contentType: %w", err)
	}
	var contentType asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(oidRV.FullBytes, &contentType); err != nil {
		return nil, fmt.Errorf("pkcs7: parsing contentType OID: %w", err)
	}
	if !contentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkcs7: not a SignedData blob (contentType %s)", contentType)
	}
	contentWrapRV, _, err := readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading [0] explicit content: %w", err)
	}

	sdRV, _, err := readTLV(contentWrapRV.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading SignedData SEQUENCE: %w", err)
	}
	body := sdRV.Bytes

	var version int
	body, err = asn1.Unmarshal(body, &version)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading SignedData.version: %w", err)
	}

	digestAlgsRV, body, err := readTLV(body)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading digestAlgorithms: %w", err)
	}
	var digestAlgorithms []string
	for rem := digestAlgsRV.Bytes; len(rem) > 0; {
		var ai algorithmIdentifier
		rem, err = asn1.Unmarshal(rem, &ai)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: reading digestAlgorithms entry: %w", err)
		}
		digestAlgorithms = append(digestAlgorithms, hashOIDName(ai.Algorithm))
	}

	// inner contentInfo (contentType pkcs7-data, no content since detached)
	_, body, err = readTLV(body)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading inner contentInfo: %w", err)
	}

	var certificates []*x509.Certificate
	if peekRV, peekRest, perr := readTLV(body); perr == nil && peekRV.Class == 2 && peekRV.Tag == 0 {
		for rem := peekRV.Bytes; len(rem) > 0; {
			certRV, r2, e2 := readTLV(rem)
			if e2 != nil {
				return nil, fmt.Errorf("pkcs7: reading certificate entry: %w", e2)
			}
			cert, e3 := x509.ParseCertificate(certRV.FullBytes)
			if e3 != nil {
				return nil, fmt.Errorf("pkcs7: parsing certificate: %w", e3)
			}
			certificates = append(certificates, cert)
			rem = r2
		}
		body = peekRest
	}

	// crls [1] IMPLICIT OPTIONAL -- not used by FortiOS .x files, skip if present
	if peekRV, peekRest, perr := readTLV(body); perr == nil && peekRV.Class == 2 && peekRV.Tag == 1 {
		body = peekRest
	}

	signerInfosRV, _, err := readTLV(body)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: reading signerInfos: %w", err)
	}

	var signers []SignerInfo
	for rem := signerInfosRV.Bytes; len(rem) > 0; {
		siRV, r2, e2 := readTLV(rem)
		if e2 != nil {
			return nil, fmt.Errorf("pkcs7: reading signerInfo entry: %w", e2)
		}
		si, e3 := parseSignerInfo(siRV.Bytes, certificates)
		if e3 != nil {
			return nil, fmt.Errorf("pkcs7: parsing signerInfo: %w", e3)
		}
		signers = append(signers, si)
		rem = r2
	}

	return &SignedData{
		DigestAlgorithms: digestAlgorithms,
		Certificates:     certificates,
		Signers:          signers,
	}, nil
}

func parseSignerInfo(body []byte, certificates []*x509.Certificate) (SignerInfo, error) {
	var version int
	body, err := asn1.Unmarshal(body, &version)
	if err != nil {
		return SignerInfo{}, fmt.Errorf("reading version: %w", err)
	}

	issRV, body, err := readTLV(body)
	if err != nil {
		return SignerInfo{}, fmt.Errorf("reading issuerAndSerialNumber: %w", err)
	}
	issuerNameRV, issRest, err := readTLV(issRV.Bytes)
	if err != nil {
		return SignerInfo{}, fmt.Errorf("reading issuer name: %w", err)
	}
	var serial *big.Int
	if _, err := asn1.Unmarshal(issRest, &serial); err != nil {
		return SignerInfo{}, fmt.Errorf("reading serialNumber: %w", err)
	}

	var digAlg algorithmIdentifier
	body, err = asn1.Unmarshal(body, &digAlg)
	if err != nil {
		return SignerInfo{}, fmt.Errorf("reading digestAlgorithm: %w", err)
	}

	var authAttrs []byte
	if peekRV, peekRest, perr := readTLV(body); perr == nil && peekRV.Class == 2 && peekRV.Tag == 0 {
		authAttrs = append([]byte{}, peekRV.FullBytes...)
		body = peekRest
	}

	var sigAlg algorithmIdentifier
	body, err = asn1.Unmarshal(body, &sigAlg)
	if err != nil {
		return SignerInfo{}, fmt.Errorf("reading digestEncryptionAlgorithm: %w", err)
	}

	var encryptedDigest []byte
	if _, err := asn1.Unmarshal(body, &encryptedDigest); err != nil {
		return SignerInfo{}, fmt.Errorf("reading encryptedDigest: %w", err)
	}
	// any trailing unauthenticatedAttributes [1] are not needed for
	// integrity verification and are left unparsed.

	var name pkix.Name
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(issuerNameRV.FullBytes, &rdn); err == nil {
		name.FillFromRDNSequence(&rdn)
	}

	si := SignerInfo{
		DigestAlgorithm:     hashOIDName(digAlg.Algorithm),
		SignatureAlgorithm:  sigOIDName(sigAlg.Algorithm),
		IssuerDN:            name.String(),
		SerialNumber:        fmt.Sprintf("%X", serial),
		digestHash:          hashOIDToHash(digAlg.Algorithm),
		signatureOID:        sigAlg.Algorithm,
		signatureParameters: sigAlg.Parameters,
		rawIssuer:           issuerNameRV.FullBytes,
		serial:              serial,
		authenticatedAttrs:  authAttrs,
		encryptedDigest:     encryptedDigest,
	}

	// SignerInfo identifies its certificate by issuerAndSerialNumber, not
	// by embedding it -- resolve it against SignedData.Certificates by
	// comparing raw issuer-name DER bytes (RawIssuer) and serial, since
	// formatting-based pkix.Name comparisons are unreliable.
	for _, cert := range certificates {
		if bytes.Equal(cert.RawIssuer, si.rawIssuer) && cert.SerialNumber.Cmp(si.serial) == 0 {
			si.Certificate = cert
			break
		}
	}

	return si, nil
}
