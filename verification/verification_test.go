package verification

import (
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	fuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/edgelesssys/go-tdx-qpl/verification/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyQuote(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	quote, err := types.ParseQuote(blobs.TDXQuote())
	require.NoError(err)

	pckCert, err := parsePCKCertChain(quote)
	require.NoError(err)

	var tcbInfo struct {
		TCBInfo types.TCBInfo `json:"tcbInfo"`
	}
	require.NoError(json.Unmarshal(blobs.TCBInfoJSON, &tcbInfo))
	var qeIdentity struct {
		QEIdentity types.QEIdentity `json:"enclaveIdentity"`
	}
	require.NoError(json.Unmarshal(blobs.QEIdentityJSON, &qeIdentity))

	// Verify the quote
	verifier := TDXVerifier{}
	err = verifier.verifyQuote(quote, pckCert, tcbInfo.TCBInfo, qeIdentity.QEIdentity)
	assert.NoError(err)
}

func TestVerifyPCKCert(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	quote, err := types.ParseQuote(blobs.TDXQuote())
	require.NoError(err)

	pckCert, err := parsePCKCertChain(quote)
	require.NoError(err)

	// Verify the PCK certificate
	verifier := TDXVerifier{}
	err = verifier.verifyPCKCert(pckCert, blobs.CRLSigningCert(), blobs.PCKCRL())
	assert.NoError(err)
}

func FuzzVerifyQuote_All(f *testing.F) {
	_, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	f.Add(blobs.TDXQuote())
	f.Fuzz(func(t *testing.T, a []byte) {
		target := types.SGXQuote4{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}

		runVerifyTest(t, target, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_SGXQuote4Header(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	header := quote.Header.Marshal()
	f.Add(header[:])
	f.Fuzz(func(t *testing.T, a []byte) {
		target := types.SGXQuote4Header{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}
		quote.Header = target

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_SGXReport2(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	report := quote.Body.Marshal()
	f.Add(report[:])
	f.Fuzz(func(t *testing.T, a []byte) {
		target := types.SGXReport2{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}
		quote.Body = target

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_ECDSASignature(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	f.Add(quote.Signature.Signature[:])
	f.Fuzz(func(t *testing.T, a []byte) {
		target := [64]byte{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}
		quote.Signature.Signature = target

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_ECDSAPublicKey(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	f.Add(quote.Signature.PublicKey[:])
	f.Fuzz(func(t *testing.T, a []byte) {
		target := [64]byte{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}
		quote.Signature.PublicKey = target

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_EnclaveReport(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	f.Fuzz(func(t *testing.T, a []byte) {
		target := types.EnclaveReport{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}
		report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
		require.True(t, ok)
		report.EnclaveReport = target
		quote.Signature.CertificationData.Data = report

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_QEReportSignature(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
	require.True(f, ok)
	f.Add(report.Signature[:])
	f.Fuzz(func(t *testing.T, a []byte) {
		target := [64]byte{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}
		report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
		require.True(t, ok)
		report.Signature = target
		quote.Signature.CertificationData.Data = report

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_QEReportAuthData(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
	require.True(f, ok)
	f.Add(report.QEAuthData.Data)
	f.Fuzz(func(t *testing.T, a []byte) {
		target := types.QEAuthData{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}

		// Limit the size of the data to 65535 bytes e.g. max size of a uint16
		if len(target.Data) > 65535 {
			return
		}

		report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
		require.True(t, ok)

		// Our Go code does not require ParsedDataSize for quote verification,
		// but we want to avoid failing tests due to this field being different
		// from the expected quote, so we set it manually.
		target.ParsedDataSize = uint16(len(target.Data))
		report.QEAuthData = target
		quote.Signature.CertificationData.Data = report

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func FuzzVerifyQuote_QEReportCertificationData(f *testing.F) {
	quote, pckCert, tcbInfo, qeIdentity := setupQuote(require.New(f))
	report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
	require.True(f, ok)
	data, ok := report.CertificationData.Data.([]byte)
	require.True(f, ok)
	f.Add(data)
	f.Fuzz(func(t *testing.T, a []byte) {
		target := types.CertificationData{}
		fuzzConsumer := fuzzheaders.NewConsumer(a)
		err := fuzzConsumer.GenerateStruct(&target)
		if err != nil {
			return
		}

		report, ok := quote.Signature.CertificationData.Data.(types.QEReportCertificationData)
		require.True(t, ok)
		report.CertificationData = target
		quote.Signature.CertificationData.Data = report

		runVerifyTest(t, quote, pckCert, tcbInfo, qeIdentity)
	})
}

func runVerifyTest(
	t *testing.T, quote types.SGXQuote4, pckCert *x509.Certificate,
	tcbInfo types.TCBInfo, qeIdentity types.QEIdentity,
) {
	require := require.New(t)

	// Verify the quote
	verifier := TDXVerifier{}
	err := verifier.verifyQuote(quote, pckCert, tcbInfo, qeIdentity)
	if err != nil {
		verifiyErr := &VerificationError{}
		require.ErrorAs(err, &verifiyErr)
		return
	}

	originalQuote, err := types.ParseQuote(blobs.TDXQuote())
	require.NoError(err)

	require.True(reflect.DeepEqual(quote, originalQuote), "TDXVerifier verification successful on a modified quote")
}

func setupQuote(require *require.Assertions) (types.SGXQuote4, *x509.Certificate, types.TCBInfo, types.QEIdentity) {
	quote, err := types.ParseQuote(blobs.TDXQuote())
	require.NoError(err)

	pckCert, err := parsePCKCertChain(quote)
	require.NoError(err)

	var tcbInfo struct {
		TCBInfo types.TCBInfo `json:"tcbInfo"`
	}
	require.NoError(json.Unmarshal(blobs.TCBInfoJSON, &tcbInfo))
	var qeIdentity struct {
		QEIdentity types.QEIdentity `json:"enclaveIdentity"`
	}
	require.NoError(json.Unmarshal(blobs.QEIdentityJSON, &qeIdentity))

	return quote, pckCert, tcbInfo.TCBInfo, qeIdentity.QEIdentity
}
