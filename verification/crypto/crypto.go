// Package crypto implements common crypto operations used to verify TDX quotes.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// VerifyECDSASignature verifies an ECDSA signature was signed
// using the public key of the provided signing certificate.
func VerifyECDSASignature(publicKey crypto.PublicKey, data, signature []byte) error {
	signingKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("signing cert public key is not an ECDSA key")
	}
	if len(signature) != 64 {
		return fmt.Errorf("invalid ECDSA signature: expected 64 bytes but got %d bytes", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	toVerify := sha256.Sum256(data)
	if !ecdsa.Verify(signingKey, toVerify[:], r, s) {
		return errors.New("failed to verify signature using ECDSA public key")
	}
	return nil
}

// ParsePEMCertificateChain parses a certificate chain from a PEM-encoded byte slice.
func ParsePEMCertificateChain(certChainPEM []byte) ([]*x509.Certificate, error) {
	var signingChain []*x509.Certificate
	for block, rest := pem.Decode([]byte(certChainPEM)); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate from PEM: %w", err)
		}

		signingChain = append(signingChain, cert)
	}
	return signingChain, nil
}
