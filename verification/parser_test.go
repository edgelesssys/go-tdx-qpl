package verification

import (
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseQuote(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote, err := os.ReadFile("../blobs/quote")
	require.NoError(err)

	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	// Check TDReport data
	reportData := parsedQuote.Body.ReportData
	cleanReportData := strings.ReplaceAll(string(reportData[:]), "\x00", "")
	assert.Equal("Hello from Edgeless Systems!", cleanReportData)

	// Check hard-coded MRSIGNER
	qeReport := parsedQuote.Signature.CertificationData.Data.(QEReportCertificationData)
	assert.EqualValues(strings.ToLower("DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5"), hex.EncodeToString(qeReport.EnclaveReport.MRSIGNER[:]))

	// Check QEAuthData
	expectedData := make([]byte, 32)
	for i := 0; i < 32; i++ {
		expectedData[i] = byte(i)
	}
	assert.Equal(expectedData, qeReport.QEAuthData.Data)

	// Check if PEM chain is valid
	pemChain := qeReport.CertificationData.Data.([]byte)
	block, rest := pem.Decode(pemChain)
	assert.NotEmpty(block)
	assert.NotEmpty(rest)
	block, rest = pem.Decode(rest)
	assert.NotEmpty(block)
	assert.NotEmpty(rest)
	block, rest = pem.Decode(rest)
	assert.NotEmpty(block)
	assert.Equal([]byte{0x0}, rest) // C terminated string with 0x0 byte
}

func FuzzParseQuote(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		assert := assert.New(t)
		quote, err := ParseQuote(a)
		// This assumption is, of course, not very useful since there could be a seemingly valid input.
		// But we mainly care about panics for now.
		assert.Empty(quote)
		assert.Error(err)
	})
}

func FuzzParseSignature(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		assert := assert.New(t)
		quote, err := parseSignature(a)
		// This assumption is, of course, not very useful since there could be a seemingly valid input.
		// But we mainly care about panics for now.
		assert.Empty(quote)
		assert.Error(err)
	})
}

func FuzzParseQEReportCertificationData(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		assert := assert.New(t)
		quote, err := parseQEReportCertificationData(a)
		// This assumption is, of course, not very useful since there could be a seemingly valid input.
		// But we mainly care about panics for now.
		assert.Empty(quote)
		assert.Error(err)
	})
}

func FuzzParseQEReportInnerCertificationData(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		assert := assert.New(t)
		quote, err := parseQEReportInnerCertificationData(a)
		// This assumption is, of course, not very useful since there could be a seemingly valid input.
		// But we mainly care about panics for now.
		assert.Empty(quote)
		assert.Error(err)
	})
}
