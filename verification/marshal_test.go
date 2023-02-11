package verification

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestSerializeEnclaveReport(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote, err := os.ReadFile("../blobs/quote")
	require.NoError(err)

	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	qeReport := parsedQuote.Signature.CertificationData.Data.(QEReportCertificationData)
	enclaveReport := qeReport.EnclaveReport
	assert.EqualValues(rawQuote[770:1154], enclaveReport.Marshal())
}
