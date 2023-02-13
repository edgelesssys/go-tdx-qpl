package pcs

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

const (
	testTCBInfoJSON    = `{"tcbInfo":{"id":"TDX","version":3,"issueDate":"2023-02-13T12:16:46Z","nextUpdate":"2023-03-15T12:16:46Z","fmspc":"00806f050000","pceId":"0000","tcbType":0,"tcbEvaluationDataNumber":14,"tdxModule":{"mrsigner":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","attributes":"0000000000000000","attributesMask":"FFFFFFFFFFFFFFFF"},"tcbLevels":[{"tcb":{"sgxtcbcomponents":[{"svn":5,"category":"BIOS","type":"Early Microcode Update"},{"svn":5,"category":"OS/VMM","type":"SGX Late Microcode Update"},{"svn":13,"category":"OS/VMM","type":"TXT SINIT"},{"svn":2,"category":"BIOS"},{"svn":3,"category":"BIOS"},{"svn":1,"category":"BIOS"},{"svn":0},{"svn":3,"category":"OS/VMM","type":"SEAMLDR ACM"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":11,"tdxtcbcomponents":[{"svn":3,"category":"OS/VMM","type":"TDX Module"},{"svn":0,"category":"OS/VMM","type":"TDX Module"},{"svn":5,"category":"OS/VMM","type":"TDX Late Microcode Update"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}]},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"sgxtcbcomponents":[{"svn":5,"category":"BIOS","type":"Early Microcode Update"},{"svn":5,"category":"OS/VMM","type":"SGX Late Microcode Update"},{"svn":13,"category":"OS/VMM","type":"TXT SINIT"},{"svn":2,"category":"BIOS"},{"svn":3,"category":"BIOS"},{"svn":1,"category":"BIOS"},{"svn":0},{"svn":3,"category":"OS/VMM","type":"SEAMLDR ACM"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}],"pcesvn":5,"tdxtcbcomponents":[{"svn":3,"category":"OS/VMM","type":"TDX Module"},{"svn":0,"category":"OS/VMM","type":"TDX Module"},{"svn":5,"category":"OS/VMM","type":"TDX Late Microcode Update"},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0},{"svn":0}]},"tcbDate":"2018-01-04T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00106","INTEL-SA-00115","INTEL-SA-00135","INTEL-SA-00203","INTEL-SA-00220","INTEL-SA-00233","INTEL-SA-00270","INTEL-SA-00293","INTEL-SA-00320","INTEL-SA-00329","INTEL-SA-00381","INTEL-SA-00389","INTEL-SA-00477"]}]},"signature":"2982cdbaff03eccf79af180eb35a04fe8b7afd23b6ac564bdb1ce186831831235b26549e062a727cd647252ce21af28a603a8e494dccc4073c360389bd8864a0"}`
	testQEIdentityJSON = `{"enclaveIdentity":{"id":"TD_QE","version":2,"issueDate":"2023-02-13T12:16:46Z","nextUpdate":"2023-03-15T12:16:46Z","tcbEvaluationDataNumber":14,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"11000000000000000000000000000000","attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","mrsigner":"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5","isvprodid":2,"tcbLevels":[{"tcb":{"isvsvn":4},"tcbDate":"2022-11-09T00:00:00Z","tcbStatus":"UpToDate"}]},"signature":"f9e4fdf2d8a8dd5c950cea3a10d2add9745154b1a3d5a7ba49e530bc6875da685610ebbb0cd8e3401866ce634101593f19e8a8cc0f725d06f3f5d0d3c5c880ba"}`
	testPCKCRLBase64   = `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`
	testTCBSigningCert = "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n"
	testCRLSigningCert = "-----BEGIN CERTIFICATE-----\nMIICljCCAj2gAwIBAgIVAJVvXc29G+HpQEnJ1PQzzgFXC95UMAoGCCqGSM49BAMC\nMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD\nb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw\nCQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHAxIjAg\nBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVs\nIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex\nCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENSB/7t21lXSO\n2Cuzpxw74eJB72EyDGgW5rXCtx2tVTLq6hKk6z+UiRZCnqR7psOvgqFeSxlmTlJl\neTmi2WYz3qOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBS\nBgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2Vy\ndmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUlW9d\nzb0b4elAScnU9DPOAVcL3lQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwCgYIKoZIzj0EAwIDRwAwRAIgXsVki0w+i6VYGW3UF/22uaXe0YJDj1Ue\nnA+TjD1ai5cCICYb1SAmD5xkfTVpvo4UoyiSYxrDWLmUR4CI9NKyfPN+\n-----END CERTIFICATE-----\n"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGetPCKCRL(t *testing.T) {
	assert := assert.New(t)
	client := &TrustedServicesClient{
		api: &fakeAPI{},
	}

	crl, intermediateCert, err := client.GetPCKCRL(context.Background())
	assert.NoError(err)
	assert.NotNil(crl)
	assert.NotNil(intermediateCert)
}

func TestGetTCBInfo(t *testing.T) {
	assert := assert.New(t)
	client := &TrustedServicesClient{
		api: &fakeAPI{},
	}

	tcbInfo, err := client.GetTCBInfo(context.Background(), [6]byte{0x00, 0x80, 0x6F, 0x05, 0x00, 0x00})
	assert.NoError(err)
	assert.NotNil(tcbInfo)
}

func TestGetQEIdentity(t *testing.T) {
	assert := assert.New(t)
	client := &TrustedServicesClient{
		api: &fakeAPI{},
	}

	qeIdentity, err := client.GetQEIdentity(context.Background())
	assert.NoError(err)
	assert.NotNil(qeIdentity)
}

type fakeAPI struct{}

func (f *fakeAPI) getFromPCS(_ context.Context, uri *url.URL, _ string) ([]byte, *x509.Certificate, error) {
	signingCertPEM, _ := pem.Decode([]byte(testTCBSigningCert))
	signingCert, err := x509.ParseCertificate(signingCertPEM.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pckSigningCertPEM, _ := pem.Decode([]byte(testCRLSigningCert))
	pckSigningCert, err := x509.ParseCertificate(pckSigningCertPEM.Bytes)
	if err != nil {
		return nil, nil, err
	}

	switch {
	case strings.Contains(uri.Path, pckcrlPath):
		crl, err := base64.StdEncoding.DecodeString(testPCKCRLBase64)
		if err != nil {
			return nil, nil, err
		}
		return crl, pckSigningCert, nil
	case strings.Contains(uri.Path, tcbPath):
		return []byte(testTCBInfoJSON), signingCert, nil
	case strings.Contains(uri.Path, qePath):
		return []byte(testQEIdentityJSON), signingCert, nil
	default:
		return nil, nil, fmt.Errorf("unexpected path: %s", uri.Path)
	}
}
