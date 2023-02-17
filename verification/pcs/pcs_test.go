package pcs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGetPCKCRL(t *testing.T) {
	assert := assert.New(t)
	client := &TrustedServicesClient{
		api: &fakeAPI{},
	}

	crl, intermediateCert, err := client.GetPCKCRL(context.Background(), TDXPlatform)
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
	signingCertPEM, _ := pem.Decode(blobs.TCBSigningCertPEM)
	signingCert, err := x509.ParseCertificate(signingCertPEM.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pckSigningCertPEM, _ := pem.Decode(blobs.CRLSigningCertPEM)
	pckSigningCert, err := x509.ParseCertificate(pckSigningCertPEM.Bytes)
	if err != nil {
		return nil, nil, err
	}

	switch {
	case strings.Contains(uri.Path, pckcrlPath):
		return blobs.PCKCRLDER(), pckSigningCert, nil
	case strings.Contains(uri.Path, tcbPath):
		return []byte(blobs.TCBInfoJSON), signingCert, nil
	case strings.Contains(uri.Path, qePath):
		return []byte(blobs.QEIdentityJSON), signingCert, nil
	default:
		return nil, nil, fmt.Errorf("unexpected path: %s", uri.Path)
	}
}
