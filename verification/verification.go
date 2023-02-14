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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/edgelesssys/go-tdx-qpl/verification/crypto"
	"github.com/edgelesssys/go-tdx-qpl/verification/pcs"
	"github.com/edgelesssys/go-tdx-qpl/verification/types"
)

const (
	tcbInfoMinVersion = 3
	identityVersion   = 2
	identityTDXID     = "TD_QE"
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
	pckCrl, pckIntermediateCert, err := v.pcsClient.GetPCKCRL(ctx, pcs.TDXPlatform) // TODO: Get platform type from quote
	if err != nil {
		return fmt.Errorf("getting PCK CRL: %w", err)
	}

	if err := v.VerifyPCKCert(pckCert, pckIntermediateCert, pckCrl); err != nil {
		return fmt.Errorf("verifying PCK certificate: %w", err)
	}

	ext, err := types.ParsePCKSGXExtensions(pckCert)
	if err != nil {
		return fmt.Errorf("getting TEE extensions from PCK certificate: %w", err)
	}

	tcbInfo, err := v.pcsClient.GetTCBInfo(ctx, ext.FMSPC)
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
	// 4.1.2.4.9
	if tcbInfo.Version >= tcbInfoMinVersion {
		if tcbInfo.ID != types.TCBInfoTDXID {
			return fmt.Errorf("TCBInfo was generated for a different TEE: expected %s, got %s", types.TCBInfoTDXID, tcbInfo.ID)
		}
		if quote.Header.TEEType != types.TEETypeTDX {
			return fmt.Errorf("given quote is not a TDX quote: expected TEE type %x, got %x", types.TEETypeTDX, quote.Header.TEEType)
		}
	} else {
		return fmt.Errorf("TCBInfo version %d is not valid for TDX TEE", tcbInfo.Version)
	}

	// 4.1.2.4.10
	// get pck cert extensions and verify using TCB Info
	ext, err := types.ParsePCKSGXExtensions(pckCert)
	if err != nil {
		return fmt.Errorf("getting TEE extensions from PCK certificate: %w", err)
	}

	if !bytes.Equal(ext.FMSPC[:], tcbInfo.FMSPC[:]) {
		return fmt.Errorf("FMSPC in PCK certificate (%x) does not match FMSPC in TCB Info (%x)", ext.FMSPC, tcbInfo.FMSPC)
	}
	if !bytes.Equal(ext.PCEID[:], tcbInfo.PCEID[:]) {
		return fmt.Errorf("PCEID in PCK certificate (%x) does not match PCEID in TCB Info (%x)", ext.PCEID, tcbInfo.PCEID)
	}

	// TODO: Check what this function does in the Intel code (and implement it)
	// verifyCertificationData()

	// 4.1.2.4.11
	// verify TDX module
	if !bytes.Equal(quote.Body.MRSIGNERSEAM[:], tcbInfo.TDXModule.MRSigner[:]) {
		return fmt.Errorf("MRSigner in TDX module (%x) does not match MRSigner in TCB Info (%x)", quote.Body.MRSIGNERSEAM, tcbInfo.TDXModule.MRSigner)
	}
	maskedAttributes := quote.Body.SEAMAttributes & tcbInfo.TDXModule.AttributesMask
	if maskedAttributes != tcbInfo.TDXModule.Attributes {
		return fmt.Errorf("masked SEAMAttributes in TDX module (%x) does not match SEAMAttributes in TCB Info (%x)", maskedAttributes, tcbInfo.TDXModule.Attributes)
	}

	// 4.1.2.4.12
	// verify QE Report
	qeReport, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
	if !ok {
		return errors.New("invalid QEReportCertificationData in quote")
	}
	enclaveReport := qeReport.EnclaveReport.Marshal()
	if err := crypto.VerifyECDSASignature(pckCert.PublicKey, enclaveReport[:], qeReport.Signature[:]); err != nil {
		return fmt.Errorf("verifying QE report signature: %w", err)
	}

	// 4.1.2.4.13
	concatSHA256 := sha256.Sum256(append(quote.Signature.PublicKey[:], qeReport.QEAuthData.Data...))
	if !bytes.Equal(qeReport.EnclaveReport.ReportData[:32], concatSHA256[:]) {
		return errors.New("QE report data does not match QE authentication data")
	}

	// 4.1.2.4.14
	// verify QE Identity
	if qeIdentity.Version != identityVersion {
		return fmt.Errorf("QE Identity version %d is not valid for TDX TEE", qeIdentity.Version)
	}
	if qeIdentity.ID != identityTDXID {
		return fmt.Errorf("QE Identity was generated for a different TEE: expected %s, got %s", identityTDXID, qeIdentity.ID)
	}

	// 4.1.2.4.15
	// TODO: Check what this function does in Intel's code and implement it
	// verifyQEIdentityStatus()

	// 4.1.2.4.16
	// verify quote signature
	publicKey := quote.Signature.PublicKey // This key is called attestKey in Intel's code.
	headerBytes := quote.Header.Marshal()
	reportBytes := quote.Body.Marshal()
	toVerify := append(headerBytes[:], reportBytes[:]...) // Quote header + TDReport

	// It's crypto time!
	key := new(ecdsa.PublicKey)
	key.Curve = elliptic.P256()

	// construct the key manually...
	key.X = new(big.Int).SetBytes(publicKey[:32])
	key.Y = new(big.Int).SetBytes(publicKey[32:64])

	if err := crypto.VerifyECDSASignature(key, toVerify, quote.Signature.Signature[:]); err != nil {
		return fmt.Errorf("verifying quote signature: %w", err)
	}

	//  4.1.2.4.17
	// check TCB level
	// TODO: implement this

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

	certChain, err := crypto.ParsePEMCertificateChain(certChainPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing PCK certificate chain: %w", err)
	}
	if len(certChain) != 3 {
		return nil, fmt.Errorf("PCK certificate chain must have 3 certificates, got %d", len(certChain))
	}

	return certChain[0], nil
}
