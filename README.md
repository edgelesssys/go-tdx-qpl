# TDX Quote Provider Library

To generate and verify Intel SGX/TDX quotes, Intel provides a [Quote Provider Library (QPL)](https://github.com/intel/SGXDataCenterAttestationPrimitives).
This library comes in two parts:

1. Quote Generation

    Generate an SGX/TDX quote using Intel's secure processor.

2. Quote Verification

    Verify a quote issued by an SGX/TDX TEE

This repo provides a simple Go library to enable these features.

## Quote Verification

To verify a quote, we first have to retrieve a collateral from Intel's Provisioning Certification Service (PCS).
Using this collateral we can verify a quote.

### Attestation flow

1. Verify enclave PCK cert chain using PCK CRL chain, Root CA CRL, and trusted Root CA.

    PCK cert chain is the PCK cert and the PCK signing chain

    PCK CRL and Root CA CRL is retrieved from PCS

2. Verify TCB Info using TCB Signing Cert, Root CA CRL, and trusted Root CA

    1. Verify the TCB signing cert signs the TCB Info JSON, verify the signing cert is signed Root CA and has not been revoked by Root CA CRL
    2. Make sure the signing cert was used to sign the TCB Info JSON

3. Verify QE Identity using TCB Signing Cert, Root CA CRL, and trusted Root CA

    1. Verify TCB Signing cert is valid under Root CA CRL and trusted Root CA
    2. Check that the TCB Signing Cert signs the QE Identity

4. Verify quote using PCK Cert, PCK CRL chain, TCB Info, and QE Identity

### TDX collateral retrieval from PCS

A TDX collateral consists of a PCK CRL chain, TCB Info for the FMSPC of the TDX platform, Quoting Enclave Identity information, Intel SGX Root CA CRL.
All of which we can retrieve from the PCS:

* Get API version

    TDX is supported in PCS API v3 and onward. We pin v4.

* Get PCK CRL chain

    Retrieve using: `https://api.trustedservices.intel.com:443/sgx/certification/v4/pckcrl?ca=platform&encoding=der`

    The CRL needs to be verified and used to check if the PCK certificate was revoked at some point

* Get TCB Info

    Retrieve using: `https://api.trustedservices.intel.com:443/tdx/certification/v4/tcb?fmspc={value from platform cert}`

    The `fmspc` value is a 6 Byte value from the PCK cert and identified by the OID `1.2.840.113741.1.13.1.4`

* Get QE Identity

    Retrieve from `https://api.trustedservices.intel.com:443/tdx/certification/v4/qe/identity`

    The retrieved data is used for simple equality check from Intel reported values against values reported by the TDX quoting enclave.

    This verifies the TDX quoting enclave is up to date with the specs reported by Intel.
    We may want to allow configuration of accepted TCB errors.

* Get Root CA CRL

    Retrieve from `https://certificates.trustedservices.intel.com:443/IntelSGXRootCA.der`

    Use CRL to PCK CRL chain? -> Need to check what this is actually used for.

### SGX/TDX quote verification flow

Inputs:

* SGX/TDX Quote -> From enclave
* PCK Cert -> From enclave
* CRL -> From PCS
* TCB Info JSON -> From PCS
* Enclave Identity (QE) -> From PCS

Verification flow:

1. Check PCK Cert contains the "SGX PCK Certificate" string (Is this different for TDX)
2. Verify CRL Issuer and PCK Cert Issuer are the same
3. Check if PCK Cert was revoked using the provided CRL
4. Check TCB Info version for TDX/SGX header
5. Verify PCK Cert Family-Model-Stepping-Platform-CustomSKU (FMSPC) and Provisioning-Certification-Enclave (PCE) ID match the one report in TCB Info
6. Verify some TDX properties of TCB Info:
    1. Compare MR Signer from TDX Module in TCB Info to the one reported in the quote's TD report
    2. Verify Seam attributes from Quote match attributes from TDX Module in TCB Info by applying a mask from TDX Module on quote's seam attributes
7. Verify SHA256 ECDSA Signature of quote using the public key from PCK Cert
8. Create sha256 digest of quote Attestation Key and QE Auth Data and verify it matches the Report Data in the quote's QE Report
9. If Enclave Identity is set, use it to verify the quote's QE Report
    1. Check if enclave identity miscSelect with mask applied matches the one in enclave report
    2. Check if enclave identity attributes with mask applied matches the on in enclave report
    3. Check if MR Signer of identity matches the one in enclave report
    4. Check if Product ID and Security Version Number of identity matches the one in enclave report
    5. Verify that TCB Status of identity is UpToDate
10. Use the quote's public key to verify the quote's signature and signed data
11. Check the TCB Level
12. If enclave Identity is set, verify its TCB level

## 3rdparty licenses

This project is based on code from [Intel(R) Software Guard Extensions Data Center Attestation Primitives](https://github.com/intel/SGXDataCenterAttestationPrimitives), which is licensed under the [BSD license](3rdparty/SGXDataCenterAttestationPrimitives/License.txt).
