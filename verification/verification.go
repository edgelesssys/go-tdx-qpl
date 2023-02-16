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
	"github.com/edgelesssys/go-tdx-qpl/verification/status"
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
// TODO: Return VerificationError
func (v *TDXVerifier) VerifyQuote(quote types.SGXQuote4, pckCert *x509.Certificate, tcbInfo types.TCBInfo, qeIdentity types.QEIdentity) error {
	// 4.1.2.4.9
	if tcbInfo.Version >= tcbInfoMinVersion {
		if tcbInfo.ID != types.TCBInfoTDXID {
			return &VerificationError{
				fmt.Errorf("TCBInfo was generated for a different TEE: expected %s, got %s", types.TCBInfoTDXID, tcbInfo.ID),
				status.TCB_INFO_MISMATCH,
			}
		}
		if quote.Header.TEEType != types.TEETypeTDX {
			return &VerificationError{
				fmt.Errorf("given quote is not a TDX quote: expected TEE type %x, got %x", types.TEETypeTDX, quote.Header.TEEType),
				status.TCB_INFO_MISMATCH,
			}
		}
	} else {
		return &VerificationError{fmt.Errorf("TCBInfo version %d is not valid for TDX TEE", tcbInfo.Version), status.TCB_INFO_MISMATCH}
	}

	// 4.1.2.4.10
	// Get pck cert extensions and verify using TCB Info
	ext, err := types.ParsePCKSGXExtensions(pckCert)
	if err != nil {
		return &VerificationError{fmt.Errorf("getting TEE extensions from PCK certificate: %w", err), status.INVALID_PCK_CERT}
	}

	if !bytes.Equal(ext.FMSPC[:], tcbInfo.FMSPC[:]) {
		return &VerificationError{
			fmt.Errorf("FMSPC in PCK certificate (%x) does not match FMSPC in TCB Info (%x)", ext.FMSPC, tcbInfo.FMSPC),
			status.TCB_INFO_MISMATCH,
		}
	}
	if !bytes.Equal(ext.PCEID[:], tcbInfo.PCEID[:]) {
		return &VerificationError{
			fmt.Errorf("PCEID in PCK certificate (%x) does not match PCEID in TCB Info (%x)", ext.PCEID, tcbInfo.PCEID),
			status.TCB_INFO_MISMATCH,
		}
	}

	// At this point Intel checks that the actual size of the quote's certification data matches the size reported in ParsedDataSize
	// Since we already do this when parsing the quote, we skip this step
	// TODO: Perform this check

	// 4.1.2.4.11
	// verify TDX module
	if !bytes.Equal(quote.Body.MRSIGNERSEAM[:], tcbInfo.TDXModule.MRSigner[:]) {
		return &VerificationError{
			fmt.Errorf("MRSigner in TDX module (%x) does not match MRSigner in TCB Info (%x)", quote.Body.MRSIGNERSEAM, tcbInfo.TDXModule.MRSigner),
			status.TDX_MODULE_MISMATCH,
		}
	}
	maskedAttributes := quote.Body.SEAMAttributes & tcbInfo.TDXModule.AttributesMask
	if maskedAttributes != tcbInfo.TDXModule.Attributes {
		return &VerificationError{
			fmt.Errorf("masked SEAMAttributes in TDX module (%x) does not match SEAMAttributes in TCB Info (%x)", maskedAttributes, tcbInfo.TDXModule.Attributes),
			status.TDX_MODULE_MISMATCH,
		}
	}

	// 4.1.2.4.12
	// Verify QE Report
	qeReport, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
	if !ok {
		return &VerificationError{errors.New("invalid QEReportCertificationData in quote"), status.INVALID_QE_REPORT_DATA}
	}
	enclaveReport := qeReport.EnclaveReport.Marshal()
	if err := crypto.VerifyECDSASignature(pckCert.PublicKey, enclaveReport[:], qeReport.Signature[:]); err != nil {
		return &VerificationError{fmt.Errorf("verifying QE report signature: %w", err), status.INVALID_QE_REPORT_SIGNATURE}
	}

	// 4.1.2.4.13
	concatSHA256 := sha256.Sum256(append(quote.Signature.PublicKey[:], qeReport.QEAuthData.Data...))
	if !bytes.Equal(qeReport.EnclaveReport.ReportData[:32], concatSHA256[:]) {
		return &VerificationError{errors.New("QE report data does not match QE authentication data"), status.INVALID_QE_REPORT_DATA}
	}

	// 4.1.2.4.14
	// Verify QE Identity, this step is conditional in Intel's code depending on if qeIdentity is set or not
	// Since we only care about TDX verification, we will always verify the QE Identity
	if qeIdentity.Version != identityVersion {
		return &VerificationError{
			fmt.Errorf("QE Identity version %d is not valid for TDX TEE", qeIdentity.Version),
			status.QE_IDENTITY_MISMATCH,
		}
	}
	if qeIdentity.ID != identityTDXID {
		return &VerificationError{
			fmt.Errorf("QE Identity was generated for a different TEE: expected %s, got %s", identityTDXID, qeIdentity.ID),
			status.QE_IDENTITY_MISMATCH,
		}
	}

	// 4.1.2.4.15
	qeIdentityStatus := v.verifyQEIdentityStatus(qeIdentity, qeReport.EnclaveReport)
	switch qeIdentityStatus {
	case status.SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT:
		return &VerificationError{errors.New("unsupported quote format"), status.UNSUPPORTED_QUOTE_FORMAT}
	case status.SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT,
		status.SGX_ENCLAVE_IDENTITY_INVALID,
		status.SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION:
		return &VerificationError{errors.New("unsupported QE Identity version"), status.UNSUPPORTED_QE_IDENTITY_FORMAT}
	case status.SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH,
		status.SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH,
		status.SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH,
		status.SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH:
		return &VerificationError{errors.New("QE Identity mismatch"), status.QE_IDENTITY_MISMATCH}
	}

	// 4.1.2.4.16
	// Verify quote signature
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
		return &VerificationError{fmt.Errorf("verifying quote signature: %w", err), status.INVALID_QUOTE_SIGNATURE}
	}

	//  4.1.2.4.17
	// Check TCB level of quote and converge with QE Identity status
	tcbLevelStatus, err := v.checkTCBLevel(tcbInfo, ext, quote)
	if err != nil {
		return &VerificationError{fmt.Errorf("checking TCB level: %w", err), tcbLevelStatus}
	}

	if tcbStatus := status.ConvergeTCBStatus(tcbLevelStatus, qeIdentityStatus); tcbStatus != status.OK {
		return &VerificationError{errors.New("TCB level check failed"), tcbStatus}
	}

	return nil
}

// VerifyPCKCert verifies the PCK certificate was not revoked and is signed by pckCA.
// The pckCA certificate is assumed to be trusted and should be verified by the caller using a trusted root CA.
func (v *TDXVerifier) VerifyPCKCert(pckCert, pckCA *x509.Certificate, pckCRL *x509.RevocationList) error {
	// Check if PCK cert is revoked
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

// verifyQEIdentityStatus verifies the EnclaveReport QE Identity against the QE Identity.
func (v *TDXVerifier) verifyQEIdentityStatus(enclaveIdentity types.QEIdentity, report types.EnclaveReport) status.Status {
	/// 4.1.2.9.5
	if (report.MiscSelect & enclaveIdentity.MiscSelectMask) != enclaveIdentity.MiscSelect {
		return status.SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH
	}

	// 4.1.2.9.6
	if !bytes.Equal(applyMask(report.Attributes[:], enclaveIdentity.AttributesMask[:]), enclaveIdentity.Attributes[:]) {
		return status.SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH
	}

	// 4.1.2.9.7
	if !bytes.Equal(report.MRSIGNER[:], enclaveIdentity.MRSigner[:]) {
		return status.SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH
	}

	// 4.1.2.9.8
	if report.ISVProdID != enclaveIdentity.ISVProdID {
		return status.SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH
	}

	// 4.1.2.9.9 & 4.1.2.9.10
	enclaveIdentityStatus := enclaveIdentity.GetTCBStatus(report.ISVSVN)
	if enclaveIdentityStatus != status.UpToDate {
		if enclaveIdentityStatus == status.Revoked {
			return status.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED
		}
		return status.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
	}

	return status.OK
}

// checkTCBLevel checks the TCB level of the quote and PCK cert against the TCB Info.
func (v *TDXVerifier) checkTCBLevel(tcbInfo types.TCBInfo, pckExtensions types.SGXExtensions, quote types.SGXQuote4) (status.Status, error) {
	// 4.1.2.4.17.1 & 4.1.2.4.17.2
	tcbLevel, err := v.getMatchingTCBLevel(tcbInfo, pckExtensions, quote)
	if err != nil {
		return status.TCB_NOT_SUPPORTED, err
	}

	if tcbInfo.Version >= tcbInfoMinVersion &&
		tcbInfo.ID == types.TCBInfoTDXID &&
		tcbLevel.TCB.TDXTCBComponents[1].SVN != quote.Body.TCBSVN[1] {
		return status.TCB_INFO_MISMATCH, fmt.Errorf(
			"SVNs at index 1 in TDX TCB Component SVN (%x) and in TEE TCB SVNs array (%x) do not match",
			tcbLevel.TCB.TDXTCBComponents[1].SVN, quote.Body.TCBSVN[1],
		)
	}

	// Intel does some debug log printing here that we skip

	// Check TCB status and return the appropriate status code
	if tcbInfo.Version > 1 && tcbLevel.TCBStatus == status.OutOfDateConfigurationNeeded {
		return status.TCB_OUT_OF_DATE_CONFIGURATION_NEEDED, nil
	}

	switch tcbLevel.TCBStatus {
	case status.OutOfDate:
		return status.TCB_OUT_OF_DATE, nil
	case status.Revoked:
		return status.TCB_REVOKED, nil
	case status.ConfigurationNeeded:
		return status.TCB_CONFIGURATION_NEEDED, nil
	case status.ConfigurationAndSWHardeningNeeded:
		return status.TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED, nil
	case status.UpToDate:
		return status.OK, nil
	case status.SWHardeningNeeded:
		return status.TCB_SW_HARDENING_NEEDED, nil
	default:
		return status.TCB_UNRECOGNIZED_STATUS, fmt.Errorf("unrecognized TCB status: %s", tcbLevel.TCBStatus)
	}
}

// getMatchingTCBLevel returns the TCB level that matches the quote's TCB level.
func (v *TDXVerifier) getMatchingTCBLevel(tcbInfo types.TCBInfo, pckExtensions types.SGXExtensions, quote types.SGXQuote4) (types.TCBLevel, error) {
	for _, tcb := range tcbInfo.TCBLevels {
		if isTCBHigherOrEqual(tcb.TCB.SGXTCBComponents, pckExtensions.TCB.TCBSVN) &&
			pckExtensions.TCB.PCESVN >= uint32(tcb.TCB.PCESVN) {

			if tcbInfo.Version >= tcbInfoMinVersion &&
				tcbInfo.ID == types.TCBInfoTDXID &&
				quote.Header.TEEType == types.TEETypeTDX {
				if isTCBHigherOrEqual(tcb.TCB.TDXTCBComponents, pckExtensions.TCB.TCBSVN) {
					return tcb, nil
				}
			}
			return tcb, nil
		}
	}

	return types.TCBLevel{}, errors.New("no matching TCB level found")
}

// VerificationError wraps an error with a TCB status code.
type VerificationError struct {
	Err    error
	Status status.Status
}

// Error returns the error message.
func (e *VerificationError) Error() string {
	return fmt.Sprintf("quote verification failed: TCB Status %d: %s", e.Status, e.Err.Error())
}

// Unwrap returns the underlying error.
func (e *VerificationError) Unwrap() error {
	return e.Err
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

// isTCBHigherOrEqual checks if the SVN of a TCB Component is higher or equal to the given SVN's.
func isTCBHigherOrEqual(tcb [16]types.TCBComponent, tcbSVN [16]int) bool {
	for idx, svn := range tcbSVN {
		if uint8(svn) < tcb[idx].SVN {
			return false
		}
	}
	return true
}

// applyMask applies a mask to a byte slice.
func applyMask(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] & b[i]
	}
	return result
}
