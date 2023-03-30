# TDX Quote Provider Library

To generate and verify Intel SGX/TDX quotes, Intel provides a [Quote Provider Library (QPL)](https://github.com/intel/SGXDataCenterAttestationPrimitives).
This library comes in two parts:

1. Quote Generation

    Generate an SGX/TDX quote using Intel's secure processor.

2. Quote Verification

    Verify a quote issued by an SGX/TDX TEE

This repo provides a simple Go library to enable these features and is used by [Constellation](https://github.com/edgelesssys/constellation) to enable TDX attestation.

## Restrictions
- The current version is based on [DCAP 1.15](https://github.com/intel/SGXDataCenterAttestationPrimitives/releases/tag/DCAP_1.15). 
It has been tested with the kernel and libraries from the tdx-tools release [2023ww01](https://github.com/intel/tdx-tools/releases/tag/2023ww01).
Given that the UAPI for TDX is yet to be finished and upstreamed, newer versions might not be supported.

- This library only supports a subset of the PCS API v4. SGX and other versions of the API are not supported and currently out of scope.

In case you encounter any issues despite the known restrictions, feel free to open [an issue](https://github.com/edgelesssys/go-tdx-qpl/issues/new/choose).

## Examples
An example quote can be found [here](blobs/quote). Other example and test data can also be found in the [`blobs`](blobs) dictionary, or alternatively directly from [Intel's DCAP repo](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteVerification/QVL/Src/AttestationApp/sampleData/tdx).

### Quote generation
Take a look at the [*generate*](testing/generate/main.go) example.

### Quote verification
Take a look at the [*verify*](testing/verify/main.go) example. 

## 3rdparty licenses

This project is based on code from [Intel(R) Software Guard Extensions Data Center Attestation Primitives](https://github.com/intel/SGXDataCenterAttestationPrimitives), which is licensed under the [BSD license](3rdparty/SGXDataCenterAttestationPrimitives/License.txt).
