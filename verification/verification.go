/*
# Intel TDX Quote Verification

This package provides a simple interface to verify Intel TDX quotes.

TODO: Verify the following statement is true:
Since functions in this package communicate with Intel's PCS,
you must have a valid Intel Attestation Service API key to use this package.

Attestation of a TDX attestation statement follows these steps:

  - Retrieve TDX collateral from Intel's PCS.

    This includes the PCK CRL chain, TCB Info, QE Identity information, and Intel's Root CA CRL.

  - Verify enclave PCK cert chain using PCK CRL chain, Root CA CRL, and trusted Root CA.

  - Verify TCB Info using TCB Signing Cert, Root CA CRL, and trusted Root CA

  - Verify QE Identity using TCB Signing Cert, Root CA CRL, and trusted Root CA

  - Verify quote using PCK Cert, PCK CRL chain, TCB Info, and QE Identity
*/
package verification

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/edgelesssys/go-tdx-qpl/verification/pcs"
	"github.com/edgelesssys/go-tdx-qpl/verification/types"
)

// TDXVerifier is used to verify TDX quotes.
type TDXVerifier struct {
	pcsClient *pcs.TrustedServicesClient
}

// New creates a new TDXVerifier.
func New() (*TDXVerifier, error) {
	pcsClient, err := pcs.New()
	if err != nil {
		return nil, err
	}
	return &TDXVerifier{pcsClient: pcsClient}, nil
}

// VerifyQuote verifies a TDX quote.
//
// This is the high level API function that handles retrieval of TDX collateral from Intel's PCS.
// Use [*TDXVerifier.VerifyQuote] and [*TDXVerifier.VerifyPCKCert] if you want to handle collateral retrieval and verification yourself.
func (v *TDXVerifier) Verify(ctx context.Context, rawQuote []byte) error {
	quote, err := types.ParseQuote(rawQuote)
	if err != nil {
		return fmt.Errorf("parsing TDX quote: %w", err)
	}

	pckCert, err := parsePCKCertChain(quote)
	if err != nil {
		return fmt.Errorf("parsing PCK certificate chain: %w", err)
	}
	pckCrl, pckIntermediateCert, err := v.pcsClient.GetPCKCRL(ctx)
	if err != nil {
		return fmt.Errorf("getting PCK CRL: %w", err)
	}

	if err := v.VerifyPCKCert(pckCert, pckIntermediateCert, pckCrl); err != nil {
		return fmt.Errorf("verifying PCK certificate: %w", err)
	}

	fmspc, err := getFMSPCExtension(pckCert)
	if err != nil {
		return fmt.Errorf("getting FMSPC extension from PCK certificate: %w", err)
	}

	tcbInfo, err := v.pcsClient.GetTCBInfo(ctx, fmspc)
	if err != nil {
		return fmt.Errorf("getting TCB Info: %w", err)
	}

	qeIdentity, err := v.pcsClient.GetQEIdentity(ctx)
	if err != nil {
		return fmt.Errorf("getting QE Identity: %w", err)
	}

	if err := v.VerifyQuote(quote, pckCert, tcbInfo, qeIdentity); err != nil {
		return fmt.Errorf("verifying TDX quote: %w", err)
	}
	return nil
}

// VerifyQuote verifies the TDX quote using the PCK certificate, TCB Info, and QE Identity.
func (v *TDXVerifier) VerifyQuote(quote types.SGXQuote4, pckCert *x509.Certificate, tcbInfo types.TCBInfo, qeIdentity types.QEIdentity) error {
	// TODO: implement
	return nil
}

// VerifyPCKCert verifies the PCK certificate was not revoked and is signed by pckCA.
// The pckCA certificate is assumed to be trusted and should be verified by the caller using a trusted root CA.
func (v *TDXVerifier) VerifyPCKCert(pckCert, pckCA *x509.Certificate, pckCRL *x509.RevocationList) error {
	// check if PCK cert is revoked
	for _, crlEntry := range pckCRL.RevokedCertificates {
		if crlEntry.SerialNumber.Cmp(pckCert.SerialNumber) == 0 {
			return errors.New("checking PCK certificate validity: certificate revoked by CRL")
		}
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(pckCA) // intermediate cert is trusted
	if _, err := pckCert.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
		return fmt.Errorf("verifying PCK certificate: %w", err)
	}

	return nil
}

// parsePCKCertChain parses the PEM-encoded PCK certificate from a TDX quote.
// The Quote should contain a certificate chain with 3 certificates: PCK, PCK Intermediate, and Root CA.
// We assume the PCK certificate is the first certificate in the chain.
func parsePCKCertChain(quote types.SGXQuote4) (*x509.Certificate, error) {
	qeReport, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
	if !ok {
		return nil, errors.New("invalid QEReportCertificationData data type in quote")
	}
	certChainPEM, ok := qeReport.CertificationData.Data.([]byte)
	if !ok {
		return nil, errors.New("invalid PCK certification data type in quote")
	}

	var certChain []*x509.Certificate
	for block, rest := pem.Decode([]byte(certChainPEM)); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate from PEM: %w", err)
		}

		certChain = append(certChain, cert)
	}
	if len(certChain) != 3 {
		return nil, fmt.Errorf("PCK certificate chain must have 3 certificates, got %d", len(certChain))
	}

	return certChain[0], nil
}

func getFMSPCExtension(cert *x509.Certificate) ([6]byte, error) {
	var sgxExtension []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(types.SGXCertExtensionOID) {
			sgxExtension = ext.Value
			break
		}
	}
	if len(sgxExtension) == 0 {
		return [6]byte{}, errors.New("no SGX extension found in certificate")
	}

	var extensions types.SGXExtensions
	if _, err := asn1.Unmarshal(sgxExtension, &extensions); err != nil {
		return [6]byte{}, fmt.Errorf("unmarshaling SGX extension: %w", err)
	}

	if len(extensions.FMSPC.FMSPC) != 6 {
		return [6]byte{}, fmt.Errorf("invalid FMSPC length: %d", len(extensions.FMSPC.FMSPC))
	}

	return [6]byte(extensions.FMSPC.FMSPC), nil
}
