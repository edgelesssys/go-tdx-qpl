/*
# TDX Attestation Data Types

This package contains data types and parsing functions used for TDX attestation.

## TDX Quote Format

	To give a *rough* understanding of how a TDX quote is formed see the graphic below:


	                                ┌──────────────────────────┐                           ┌─────────────────────────┐
	                                │                          │                           │                         │
	                                │                          ▼                           │                         ▼
	        SGXQuote4               │                 ECDSA256QuoteV4Data                  │            QEReportCertificationData
	        ParseQuote              │                   parseSignature                     │          parseQEReportCertificationData
	┌─────────────────────────┐     │     ┌───────────────────────────────────────────┐    │     ┌─────────────────────────────────────┐
	│     SGXQuote4Header     │     │     │                Signature                  │    │     │                                     │
	│       (48 bytes)        │     │     │                (64 bytes)                 │    │     │                                     │
	├─────────────────────────┤     │     ├───────────────────────────────────────────┤    │     │            EnclaveReport            │
	│                         │     │     │                PublicKey                  │    │     │             (384 bytes)             │
	│       SGXREPORT2        │     │     │                (64 bytes)                 │    │     │                                     │
	│       (TDREPORT)        │     │     ├───────────────────────────────────────────┤    │     │                                     │
	│       (584 bytes)       │     │     │             CertificationData             │    │     ├─────────────────────────────────────┤
	│                         │     │     │ ┌───────────────────────────────────────┐ │    │     │             Signature               │
	│                         │     │     │ │                 Type                  │ │    │     │             (64 bytes)              │
	├─────────────────────────┤     │     │ │               (2 bytes)               │ │    │     ├─────────────────────────────────────┤
	│     SignatureLength     │     │     │ │                                       │ │    │     │             QEAuthData              │
	│        (4 bytes)        │     │     │ │               type == 6               │ │    │     │  ┌────────────────────────────────┐ │
	├─────────────────────────┤     │     │ │  PCK_ID_QE_REPORT_CERTIFICATION_DATA  │ │    │     │  │        ParsedDataSize          │ │
	│                         │     │     │ │                                       │ │    │     │  │           (4 bytes)            │ │
	│                         │     │     │ ├───────────────────────────────────────┤ │    │     │  ├────────────────────────────────┤ │
	│                         │     │     │ │            ParsedDataSize             │ │    │     │  │             Data               │ │
	│                         │     │     │ │               (4 bytes)               │ │    │     │  │          (variable)            │ │
	│       Signature         │     │     │ ├───────────────────────────────────────┤ │    │     │  └────────────────────────────────┘ │
	│ ECDSA256QuoteV4AuthData │     │     │ │                 Data                  │ │    │     │                                     │
	│       (variable)        ├─────┘     │ │              (variable)               │ │    │     ├─────────────────────────────────────┤
	│                         │           │ │                                       │ │    │     │          CertificationData          │
	│                         │           │ │        QEReportCertificationData      ├─┼────┘     │ parseQEReportInnerCertificationData │
	│                         │           │ │                                       │ │          │                                     │
	│                         │           │ └───────────────────────────────────────┘ │          │ ┌─────────────────────────────────┐ │
	│                         │           │                                           │          │ │              Type               │ │
	└─────────────────────────┘           └───────────────────────────────────────────┘          │ │            (2 bytes)            │ │
	                                                                                             │ │                                 │ │
	                                                                                             │ │            type == 5            │ │
	                                                                                             │ │      PCK_ID_PCK_CERT_CHAIN      │ │
	                                                                                             │ ├─────────────────────────────────┤ │
	                                                                                             │ │         ParsedDataSize          │ │
	                                                                                             │ │            (4 bytes)            │ │
	                                                                                             │ ├─────────────────────────────────┤ │
	                                                                                             │ │              Data               │ │
	                                                                                             │ │            (variable)           │ │
	                                                                                             │ │                                 │ │
	                                                                                             │ │            []byte               │ │
	                                                                                             │ │   (contains a PEM certificate)  │ │
	                                                                                             │ │      terminated with \0 byte    │ │
	                                                                                             │ │                                 │ │
	                                                                                             │ └─────────────────────────────────┘ │
	                                                                                             │                                     │
	                                                                                             └─────────────────────────────────────┘
*/
package types
