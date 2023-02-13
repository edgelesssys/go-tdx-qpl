/*
Package pcs provides functions to retrieve information from Intel's PCS.

The following information is retrieved from the PCS:
  - TCB Info
  - PCK CRL and PCK CA certificate
  - QE Identity

The retrieved data is verified using the Intel SGX/TDX certificate hierarchy:

	    	                 ┌───────────────┐
	    	                 │ Intel Root CA │
	    	                 └───────┬───────┘
	    	                         │
	    	                       Signs
	    	                         │
	        ┌────────────────────────┼───────────────────────┐────────────────────────┐
	        │                        │                       │                        │
	        ▼                        ▼                       ▼                        ▼
	┌───────────────┐      ┌──────────────────┐      ┌──────────────────┐       ┌───────────────────┐
	│  PCK CA Cert  │◄──┐  │ TCB Signing Cert │◄──┐  │ QE  Signing Cert │◄──┬───┤ Intel Root CA CRL │
	└───────┬───────┘   │  └──────────────────┘   │  └──────────────────┘   │   └───────────────────┘
		    │           │                         │                         │
	      Signs         └─────────────────────────└─────────────────────────┘
	        │                                                          Revokes
	        ├────────────────────┐
	        │                    │
	        ▼                    ▼
	  ┌──────────┐          ┌─────────┐
	  │ PCK Cert │◄─────────┤ PCK CRL │
	  └──────────┘  Revokes └─────────┘

Intel Root CA is hard-coded in this package, and used to verify the PCK CA certificate, the TCB Signing certificate,
QE Identity certificate, as well as the Intel Root CA CRL.

PCK CA certificate, TCB Signing certificate, and QE Identity are used to verify the PCK CRL, TCB Info, and QE Identity respectively.
They are returned as part of the response header when retrieving the PCK certificate, TCB Info, and QE Identity from the PCS.
*/
package pcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/edgelesssys/go-tdx-qpl/verification/types"
)

// TODO:
// 		Add custom marshaling for types.TCBInfo and types.QEIdentity structs

const (
	// rootCA is the PEM encoded Intel SGX/TDX Root CA Certificate.
	rootCA = "-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n"
	// rootCACRLURL is the URL for Intel's Root CA CRL.
	rootCACRLURL = "https://certificates.trustedservices.intel.com:443/IntelSGXRootCA.der"
	// baseURL is the URL for Intel's PCS.
	baseURL = "api.trustedservices.intel.com:443"
	// sgxAPI is the API to use when retrieving SGX information from Intel's PCS.
	sgxAPI = "sgx"
	// tdxAPI is the API to use when retrieving TDX information from Intel's PCS.
	tdxAPI = "tdx"
	// requestType is the type of request to make to Intel's PCS.
	requestType = "certification"
	// apiVersion is the version of the PCS API to use.
	apiVersion = "v4"
	// pckcrlPath is the path to the PCK CRL chain.
	pckcrlPath = "pckcrl"
	// pckcrlQuery is the query to use when retrieving the PCK CRL chain.
	pckcrlQuery = "ca=platform&encoding=der"
	// pckcrlHeader is a header containing the PCK CRL issuer chain.
	pckcrlHeader = "Sgx-Pck-Crl-Issuer-Chain"
	// qePath is the path to the QE Identity information.
	qePath = "qe/identity"
	// qeHeader is a header containing the QE Identity issuer chain.
	qeHeader = "Sgx-Enclave-Identity-Issuer-Chain"
	// tcbPath is the path to the TCB Info.
	tcbPath = "tcb"
	// tcbQuery is the query to use when retrieving the TCB Info.
	tcbQuery = "fmspc"
	// tcbHeader is a header containing the TCB Info issuer chain.
	tcbHeader = "Tcb-Info-Issuer-Chain"
)

type pcsAPI interface {
	getFromPCS(ctx context.Context, uri *url.URL, certHeader string, retry bool) (json []byte, signingCert *x509.Certificate, err error)
}

// TrustedServicesClient is a client for Intel's PCS.
type TrustedServicesClient struct {
	api pcsAPI
}

// New returns a new TrustedServicesClient.
func New() (*TrustedServicesClient, error) {
	block, _ := pem.Decode([]byte(rootCA))
	rootCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing root CA: %w", err)
	}

	return &TrustedServicesClient{
		api: &pcsAPIClient{
			rootCA: rootCA,
			client: http.DefaultClient,
		},
	}, nil
}

// GetPCKCRL retrieves the PCK CRL chain and PCK CA cert from Intel's PCS.
func (t *TrustedServicesClient) GetPCKCRL(ctx context.Context) (*x509.RevocationList, *x509.Certificate, error) {
	url := getPCSURL(sgxAPI, pckcrlPath)
	url.RawQuery = pckcrlQuery
	pckCRLRaw, pckCACert, err := t.api.getFromPCS(ctx, url, pckcrlHeader, true)
	if err != nil {
		return nil, nil, fmt.Errorf("getting PCK CRL from PCS: %w", err)
	}

	pckCRL, err := x509.ParseRevocationList(pckCRLRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PCK CRL from DER: %w", err)
	}

	if err := pckCRL.CheckSignatureFrom(pckCACert); err != nil {
		return nil, nil, fmt.Errorf("verifying PCK CRL signature using PCK CA certificate: %w", err)
	}

	return pckCRL, pckCACert, nil
}

// GetTCBInfo retrieves the TCB Info from Intel's PCS for a given Family-Model-Stepping-Platform-CustomSKU (FMSPC).
func (t *TrustedServicesClient) GetTCBInfo(ctx context.Context, fmspc [6]byte) (types.TCBInfo, error) {
	url := getPCSURL(tdxAPI, tcbPath)
	query := url.Query()
	query.Set(tcbQuery, fmt.Sprintf("%x", fmspc))
	url.RawQuery = query.Encode()

	pcsResponseRaw, tcbSigningCert, err := t.api.getFromPCS(ctx, url, tcbHeader, true)
	if err != nil {
		return types.TCBInfo{}, fmt.Errorf("getting TCB Info from PCS: %w", err)
	}

	var pcsResponse struct {
		TCBInfo   pcsJSONBody `json:"tcbInfo"`
		Signature string      `json:"signature"`
	}
	if err := json.Unmarshal(pcsResponseRaw, &pcsResponse); err != nil {
		return types.TCBInfo{}, fmt.Errorf("unmarshaling TCB Info: %w", err)
	}

	signature, err := hex.DecodeString(pcsResponse.Signature)
	if err != nil {
		return types.TCBInfo{}, fmt.Errorf("decoding TCB Info signature: %w", err)
	}

	if err := verifyPCSSignature(tcbSigningCert, pcsResponse.TCBInfo, signature); err != nil {
		return types.TCBInfo{}, fmt.Errorf("verifying TCB Info signature: %w", err)
	}

	var tcbInfo types.TCBInfo
	if err := json.Unmarshal(pcsResponse.TCBInfo, &tcbInfo); err != nil {
		return types.TCBInfo{}, fmt.Errorf("unmarshaling TCB Info: %w", err)
	}

	return tcbInfo, nil
}

// GetQEIdentity retrieves the QE Identity from Intel's PCS.
func (t *TrustedServicesClient) GetQEIdentity(ctx context.Context) (types.QEIdentity, error) {
	url := getPCSURL(tdxAPI, qePath)
	pcsResponseRaw, qeSigningCert, err := t.api.getFromPCS(ctx, url, qeHeader, true)
	if err != nil {
		return types.QEIdentity{}, fmt.Errorf("getting QE Identity from PCS: %w", err)
	}

	// unmarshal to intermediate struct to verify signature
	var pcsResponse struct {
		QEIdentity pcsJSONBody `json:"enclaveIdentity"`
		Signature  string      `json:"signature"`
	}
	if err := json.Unmarshal(pcsResponseRaw, &pcsResponse); err != nil {
		return types.QEIdentity{}, fmt.Errorf("unmarshaling PCS response: %w", err)
	}

	signature, err := hex.DecodeString(pcsResponse.Signature)
	if err != nil {
		return types.QEIdentity{}, fmt.Errorf("decoding QE Identity signature: %w", err)
	}

	if err := verifyPCSSignature(qeSigningCert, pcsResponse.QEIdentity, signature); err != nil {
		return types.QEIdentity{}, fmt.Errorf("verifying QE Identity signature: %w", err)
	}

	var qeIdentity types.QEIdentity
	if err := json.Unmarshal(pcsResponse.QEIdentity, &qeIdentity); err != nil {
		return types.QEIdentity{}, fmt.Errorf("unmarshaling QE Identity: %w", err)
	}

	return qeIdentity, nil
}

type pcsAPIClient struct {
	rootCA *x509.Certificate
	client *http.Client
}

// getRootCACRL retrieves the Root CA CRL from Intel's PCS.
func (c *pcsAPIClient) getRootCACRL(ctx context.Context) (*x509.RevocationList, error) {
	url, err := url.Parse(rootCACRLURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Root CA CRL URL: %w", err)
	}

	rootCACRLRaw, _, err := c.getFromPCS(ctx, url, "", true)
	if err != nil {
		return nil, fmt.Errorf("getting Root CA CRL from PCS: %w", err)
	}

	rootCACRL, err := x509.ParseRevocationList(rootCACRLRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing Root CA CRL from DER: %w", err)
	}

	return rootCACRL, nil
}

// getFromPCS sends a request to Intel's PCS and returns the data,
// and the sgining certificate chain in the responses header if it exists.
// If retry is true, it will retry the request if the response is 429.
func (c *pcsAPIClient) getFromPCS(
	ctx context.Context, uri *url.URL, certHeader string, retry bool,
) (json []byte, signingCert *x509.Certificate, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sending request: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusTooManyRequests:
		// we have been rate limited
		// check Retry-After header and wait if the timeout is less than 10 seconds
		retryAfter := resp.Header.Get("Retry-After")
		retryAfterSeconds, err := strconv.Atoi(retryAfter)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing Retry-After header: %w", err)
		}
		if retryAfterSeconds < 10 && retry {
			time.Sleep(time.Second * time.Duration(retryAfterSeconds))
			return c.getFromPCS(ctx, uri, certHeader, false)
		} else {
			return nil, nil, fmt.Errorf("request failed: too many requests: timeout for %d seconds", retryAfterSeconds)
		}
	default:
		return nil, nil, fmt.Errorf("request failed with status %s: %s", resp.Status, http.StatusText(resp.StatusCode))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading response: %w", err)
	}
	defer resp.Body.Close()

	var intermediateCert *x509.Certificate
	if certHeader != "" {
		signingChain, err := issuerChainFromCertHeader(resp.Header.Get(certHeader))
		if err != nil {
			return nil, nil, fmt.Errorf("getting signing chain from response header: %w", err)
		}
		intermediateCert, err = c.verifyChain(ctx, signingChain)
		if err != nil {
			return nil, nil, fmt.Errorf("verifying cert header signature chain: %w", err)
		}
	}

	return respBody, intermediateCert, nil
}

// verifyChain checks the certificates in a given chain.
// This function expects the chain to be part of Intel's SGX/TDX certificate hierarchy.
// We expect the chain to be of length 2, where one of the certificates is the root CA certificate.
// We verify the root certificate in the chain matches the expected root CA certificate of the TrustedServicesClient,
// and that the intermediate CA certificate of the chain is signed by this CA and not revoked by the Root CA CRL.
func (c *pcsAPIClient) verifyChain(ctx context.Context, chain []*x509.Certificate) (*x509.Certificate, error) {
	if len(chain) != 2 {
		return nil, fmt.Errorf("unexpected number of certificates in chain: expected 2, got: %d", len(chain))
	}

	// get the intermediate CA certificate from the chain
	intermediateCACert := chain[0]
	if chain[1].SerialNumber.Cmp(c.rootCA.SerialNumber) != 0 {
		if chain[0].SerialNumber.Cmp(c.rootCA.SerialNumber) != 0 {
			return nil, errors.New("chain does not contain expected root CA certificate")
		}
		intermediateCACert = chain[1]
	}

	rootCRL, err := c.getRootCACRL(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting root CRL: %w", err)
	}

	if rootCRL.NextUpdate.Before(time.Now()) {
		return nil, errors.New("root CRL has expired")
	}
	if rootCRL.ThisUpdate.After(time.Now()) {
		return nil, errors.New("root CRL is not yet valid")
	}
	if err := rootCRL.CheckSignatureFrom(c.rootCA); err != nil {
		return nil, fmt.Errorf("checking root CRL signature: %w", err)
	}

	// Check if intermediate certificate was revoked by the PCK CRL.
	for _, revoked := range rootCRL.RevokedCertificates {
		if intermediateCACert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return nil, fmt.Errorf("certificate %s has been revoked by the root CRL", intermediateCACert.SerialNumber)
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(c.rootCA)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := intermediateCACert.Verify(opts); err != nil {
		return nil, fmt.Errorf("checking certificate signature: %w", err)
	}

	return intermediateCACert, nil
}

// issuerChainFromCertHeader parses a certificate chain from a PCS response header.
// Intel's PCS returns the signing chain in the response header as a PEM encoded string.
// The chain contains the root certificate and one intermediate certificate.
func issuerChainFromCertHeader(header string) ([]*x509.Certificate, error) {
	certChain, err := url.QueryUnescape(header)
	if err != nil {
		return nil, fmt.Errorf("decoding certificate chain from PCS response header: %w", err)
	}

	var signingChain []*x509.Certificate
	for block, rest := pem.Decode([]byte(certChain)); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate from PEM: %w", err)
		}

		signingChain = append(signingChain, cert)
	}
	return signingChain, nil
}

// getPCSURL returns a URL to connect to the PCS for the given path.
func getPCSURL(apiType, requestPath string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   baseURL,
		Path:   path.Join(apiType, requestType, apiVersion, requestPath),
	}
}

// verifyPCSSignature verifies the signature of a PCS response
// using the public key of the provided signing certificate.
func verifyPCSSignature(signingCert *x509.Certificate, data, signature []byte) error {
	if signingCert == nil {
		return errors.New("no signing cert provided")
	}
	signingKey, ok := signingCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("signing cert public key is not an ECDSA key")
	}
	if len(signature) != 64 {
		return fmt.Errorf("invalid ECDSA signature: expected 64 bytes but got %d bytes", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	toVerify := sha256.Sum256(data)
	if !ecdsa.Verify(signingKey, toVerify[:], r, s) {
		return errors.New("failed to verify signature using ECDSA public key")
	}
	return nil
}

// pcsJSONBody is used to unmarshal the response body of a PCS JSON into a byte slice.
// This is necessary because we need to verify the signature of the response body.
type pcsJSONBody []byte

func (b *pcsJSONBody) UnmarshalJSON(data []byte) error {
	*b = data
	return nil
}
