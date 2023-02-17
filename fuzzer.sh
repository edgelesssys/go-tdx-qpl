#!/usr/bin/bash

FUZZ_TIME_SECONDS=${FUZZ_TIME_SECONDS:="100"}

fuzz_time=$((FUZZ_TIME_SECONDS / 9))
echo "Fuzzing TDX Quote Verification code"
echo "Fuzzing time per test: ${fuzz_time} seconds"


go test -v -fuzz=FuzzVerifyQuote_SGXQuote4Header -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_SGXReport2 -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_ECDSASignature -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_ECDSAPublicKey -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_EnclaveReport -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_QEReportSignature -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_QEReportAuthData -fuzztime="${fuzz_time}"s ./verification
go test -v -fuzz=FuzzVerifyQuote_QEReportCertificationData -fuzztime="${fuzz_time}"s ./verification
