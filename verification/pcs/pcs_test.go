package pcs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/edgelesssys/go-tdx-qpl/blobs"
	"github.com/edgelesssys/go-tdx-qpl/verification/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	testclock "k8s.io/utils/clock/testing"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestGetPCKCRL(t *testing.T) {
	assert := assert.New(t)
	client := &TrustedServicesClient{
		api:   &fakeAPI{},
		clock: testclock.NewFakeClock(blobs.PCSIssueDate),
	}

	crl, intermediateCert, err := client.GetPCKCRL(context.Background(), TDXPlatform)
	assert.NoError(err)
	assert.NotNil(crl)
	assert.NotNil(intermediateCert)
}

func TestGetTCBInfo(t *testing.T) {
	testCases := map[string]struct {
		api     *fakeAPI
		time    time.Time
		wantErr bool
	}{
		"success": {
			api:  &fakeAPI{tcbInfoJSON: blobs.TCBInfoJSON},
			time: blobs.PCSIssueDate,
		},
		"pcs error": {
			api: &fakeAPI{
				tcbInfoJSON: blobs.TCBInfoJSON,
				requestErr:  errors.New("failed"),
			},
			time:    blobs.PCSIssueDate,
			wantErr: true,
		},
		"tcb info expired": {
			api:     &fakeAPI{tcbInfoJSON: blobs.TCBInfoJSON},
			time:    blobs.PCSIssueDate.Add(24 * 356 * 50 * time.Hour), // 50 years later
			wantErr: true,
		},
		"tcb info not yet valid": {
			api:     &fakeAPI{tcbInfoJSON: blobs.TCBInfoJSON},
			time:    time.Time{},
			wantErr: true,
		},
		"tcb info invalid json": {
			api:     &fakeAPI{tcbInfoJSON: []byte("invalid json")},
			time:    blobs.PCSIssueDate,
			wantErr: true,
		},
		"tcb info invalid signature": {
			api: &fakeAPI{tcbInfoJSON: func() []byte {
				require := require.New(t)

				var tcbInfo struct {
					TCBInfo   pcsJSONBody `json:"tcbInfo"`
					Signature string      `json:"signature"`
				}
				require.NoError(json.Unmarshal(blobs.TCBInfoJSON, &tcbInfo))
				tcbInfo.Signature = "00000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111"
				tcbInfoJSON, err := json.Marshal(tcbInfo)
				require.NoError(err)
				return tcbInfoJSON
			}()},
			time:    blobs.PCSIssueDate,
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			client := &TrustedServicesClient{
				api:   tc.api,
				clock: testclock.NewFakeClock(tc.time),
			}

			tcbInfo, err := client.GetTCBInfo(context.Background(), [6]byte{0x00, 0x80, 0x6F, 0x05, 0x00, 0x00})
			if tc.wantErr {
				assert.Error(err)
				return
			}

			assert.NoError(err)
			assert.NotEmpty(tcbInfo)
		})
	}
}

func TestGetQEIdentity(t *testing.T) {
	testCases := map[string]struct {
		api     *fakeAPI
		time    time.Time
		wantErr bool
	}{
		"success": {
			api:  &fakeAPI{qeIdentityJSON: blobs.QEIdentityJSON},
			time: blobs.PCSIssueDate,
		},
		"pcs error": {
			api: &fakeAPI{
				qeIdentityJSON: blobs.QEIdentityJSON,
				requestErr:     errors.New("failed"),
			},
			time:    blobs.PCSIssueDate,
			wantErr: true,
		},
		"tcb info expired": {
			api:     &fakeAPI{qeIdentityJSON: blobs.QEIdentityJSON},
			time:    blobs.PCSIssueDate.Add(24 * 356 * 50 * time.Hour), // 50 years later
			wantErr: true,
		},
		"tcb info not yet valid": {
			api:     &fakeAPI{qeIdentityJSON: blobs.QEIdentityJSON},
			time:    time.Time{},
			wantErr: true,
		},
		"tcb info invalid json": {
			api:     &fakeAPI{qeIdentityJSON: []byte("invalid json")},
			time:    blobs.PCSIssueDate,
			wantErr: true,
		},
		"tcb info invalid signature": {
			api: &fakeAPI{qeIdentityJSON: func() []byte {
				require := require.New(t)

				var qeIdentity struct {
					TCBInfo   pcsJSONBody `json:"enclaveIdentity"`
					Signature string      `json:"signature"`
				}
				require.NoError(json.Unmarshal(blobs.TCBInfoJSON, &qeIdentity))
				qeIdentity.Signature = "00000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111"
				qeIdentityJSON, err := json.Marshal(qeIdentity)
				require.NoError(err)
				return qeIdentityJSON
			}()},
			time:    blobs.PCSIssueDate,
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			client := &TrustedServicesClient{
				api:   tc.api,
				clock: testclock.NewFakeClock(tc.time),
			}

			qeIdentity, err := client.GetQEIdentity(context.Background())
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.NotNil(qeIdentity)
		})
	}
}

type fakeAPI struct {
	tcbInfoJSON    []byte
	qeIdentityJSON []byte
	requestErr     error
}

func (f *fakeAPI) getFromPCS(_ context.Context, uri *url.URL, _ string) ([]byte, *x509.Certificate, error) {
	if f.requestErr != nil {
		return nil, nil, f.requestErr
	}

	signingCert := crypto.MustParsePEMCertificate(blobs.TCBSigningCertPEM)
	pckSigningCert := crypto.MustParsePEMCertificate(blobs.CRLSigningCertPEM)

	switch {
	case strings.Contains(uri.Path, pckcrlPath):
		return blobs.PCKCRLDER(), pckSigningCert, nil
	case strings.Contains(uri.Path, tcbPath):
		return f.tcbInfoJSON, signingCert, nil
	case strings.Contains(uri.Path, qePath):
		return f.qeIdentityJSON, signingCert, nil
	default:
		return nil, nil, fmt.Errorf("unexpected path: %s", uri.Path)
	}
}
