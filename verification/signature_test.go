package verification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"os"
	"testing"
)

/*
	This is a collection of verification snippets which we later can use to build the full verification.
	This is mainly done to understand how the crypto works.
*/

// 4.1.2.4.16
// Use given public key & signature over SGXQuote4Header + SGXReport2.
func TestQuoteSignatureVerificationBasic(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote, err := os.ReadFile("../blobs/quote")
	require.NoError(err)

	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	signature := parsedQuote.Signature.Signature
	publicKey := parsedQuote.Signature.PublicKey // This key is called attestKey in Intel's code.
	toVerify := sha256.Sum256(rawQuote[:632])    // Quote header + TDReport

	// It's crypto time!
	key := &ecdsa.PublicKey{}
	key.Curve = elliptic.P256()

	// Either construct the key manually...
	// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteVerification/QVL/Src/AttestationLibrary/src/OpensslHelpers/KeyUtils.cpp#L63
	x := big.Int{}
	y := big.Int{}
	x.SetBytes(publicKey[:32])
	y.SetBytes(publicKey[32:64])
	key.X = &x
	key.Y = &y

	// Or use this one trick Go does not want you to know!
	// elliptic.Unmarshal expects the input to be *65* bytes for our curve.
	// We only have 64 bytes. So, what's the extra byte?
	// Well, apparently to look like valid ASN.1, you need to prepend a 0x04 (OCTET STRING).

	// key.X, key.Y = elliptic.Unmarshal(key, append([]byte{0x04}, publicKey[:]...))

	assert.NotNil(key.X)
	assert.NotNil(key.Y)

	// However, the ASN.1 trick does not seem to work for ecdsa.VerifyASN1.
	// The function seems to expect an ASN.1 SEQUENCE.
	// No idea what that looks like... but Intel does this: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteVerification/QVL/Src/AttestationLibrary/src/OpensslHelpers/SignatureVerification.cpp#L76
	// So let's do the same here, too.
	r := big.Int{}
	s := big.Int{}
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:64])

	verified := ecdsa.Verify(key, toVerify[:], &r, &s)
	assert.True(verified)
}

// 4.1.2.4.13
// Then, the public key from above is verified/authenticated over the QEReportCertificationData.
// A hash over the AttestKey and the QEAuthData is added as report data to the QE EnclaveReport, which then is signed with the PCK (?).
func TestQEReportAttestKeyReportDataConcat(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote, err := os.ReadFile("../blobs/quote")
	require.NoError(err)

	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	qeReport := parsedQuote.Signature.CertificationData.Data.(QEReportCertificationData)

	attestKeyData := parsedQuote.Signature.PublicKey
	qeAuthData := qeReport.QEAuthData.Data
	concat := append(attestKeyData[:], qeAuthData...)
	concatSHA256 := sha256.Sum256(concat)

	assert.Equal(concatSHA256[:], qeReport.EnclaveReport.ReportData[:32])
}