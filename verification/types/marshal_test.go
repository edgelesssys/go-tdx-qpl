package types

import (
	"testing"

	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalEnclaveReport(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote := blobs.TDXQuote()
	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	qeReport := parsedQuote.Signature.CertificationData.Data.(QEReportCertificationData)
	enclaveReport := qeReport.EnclaveReport
	assert.EqualValues(rawQuote[770:1154], enclaveReport.Marshal())
}

func TestMarshalQuotev4Header(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote := blobs.TDXQuote()
	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	quoteHeader := parsedQuote.Header
	assert.EqualValues(rawQuote[0:48], quoteHeader.Marshal())
}

func TestMarshalSGXReport4(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	rawQuote := blobs.TDXQuote()

	parsedQuote, err := ParseQuote(rawQuote)
	require.NoError(err)

	sgxReport2 := parsedQuote.Body
	assert.EqualValues(rawQuote[48:632], sgxReport2.Marshal())
}
