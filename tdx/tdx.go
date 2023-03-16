// Package TDX provides functionality to interact with the Intel TDX guest device.
package tdx

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/vtolstov/go-ioctl"
	"golang.org/x/sys/unix"
)

const (
	// GuestDevice is the path to the TDX guest device.
	GuestDevice = "/dev/tdx-guest"
	// tdxQuoteType is the type of quote to request.
	tdxQuoteType = uint32(2)
	// requestBufferSize is the size of the quote request buffer.
	// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/71557c7d1d869b6bd6f95566c051cbd098549509/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L103
	requestBufferSize = 4 * 4 * 1024
)

// QGS message types: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/09666b3b14147145232ea4f28d85762ca5da3c5d/QuoteGeneration/quote_wrapper/qgs_msg_lib/inc/qgs_msg_lib.h#L63-L69
const (
	qgsGetQuoteRequestType = iota
	qgsGetQuoteResponseType
	qgsGetCollateralRequestType
	qgsGetCollateralResponseType
)

// IOCTL calls for quote generation
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L53-L56
var (
	requestReport = ioctl.IOWR('T', 0x01, 8)
	requestQuote  = ioctl.IOR('T', 0x02, 8)
	extendRTMR    = ioctl.IOWR('T', 0x03, 8)
)

// device is a handle to the TDX guest device.
type device interface {
	Fd() uintptr
}

// ExtendRTMR extends the RTMR with the given data.
func ExtendRTMR(tdx device, extendData []byte, index uint8) error {
	extendDataHash := sha512.Sum384(extendData)
	extendEvent := extendRTMREvent{
		algoID:       5, // HASH_ALGO_SHA384 -> linux/include/uapi/linux/hash_info.h
		digest:       &extendDataHash,
		digestLength: 48,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), extendRTMR, uintptr(unsafe.Pointer(&extendEvent))); errno != 0 {
		return fmt.Errorf("extending RTMR: %w", errno)
	}
	return nil
}

// ReadMeasurements reads the MRTD and RTMRs of a TDX guest.
func ReadMeasurements(tdx device) ([5][48]byte, error) {
	// TDX does not support directly reading RTMRs
	// Instead, create a new report with zeroed user data,
	// and read the RTMRs and MRTD from the report
	report, err := createReport(tdx, [64]byte{0x00})
	if err != nil {
		return [5][48]byte{}, fmt.Errorf("creating report: %w", err)
	}

	// MRTD is located at offset 528 in the report
	// RTMRs start at offset 720 in the report
	// All measurements are 48 bytes long
	measurements := [5][48]byte{
		[48]byte(report[528:576]), // MRTD
		[48]byte(report[720:768]), // RTMR0
		[48]byte(report[768:816]), // RTMR1
		[48]byte(report[816:864]), // RTMR2
		[48]byte(report[864:912]), // RTMR3
	}

	return measurements, nil
}

// GenerateQuote generates a TDX quote for the given user data.
// User Data may not be longer than 64 bytes.
func GenerateQuote(tdx device, userData []byte) ([]byte, error) {
	if len(userData) > 64 {
		return nil, fmt.Errorf("user data must not be longer than 64 bytes, received %d bytes", len(userData))
	}

	var reportData [64]byte
	copy(reportData[:], userData)
	tdReport, err := createReport(tdx, reportData)
	if err != nil {
		return nil, fmt.Errorf("creating report: %w", err)
	}

	qgsGetQuoteRequest := qgsGetQuoteRequestMessage{
		reportSize:      1024, // cannot be 0
		selectedIDSize:  0,
		idListSize:      0,
		reportAndIDList: uintptr(unsafe.Pointer(&tdReport)),
	}

	messageSize := uint32(unsafe.Sizeof(qgsGetQuoteRequest)) + qgsGetQuoteRequest.reportSize

	qgsGetQuestRequestHeader := qgsMessageHeader{
		majorVersion: 1,
		minorVersion: 0,
		messageType:  qgsGetQuoteRequestType,
		size:         messageSize, // sizeof request message + report size (1024) + idListSize (we set it to 0 since it's not required)
	}
	qgsGetQuoteRequest.header = qgsGetQuestRequestHeader

	var ioctlQuoteRequestData [16360]byte
	messageSizePrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(messageSizePrefix, messageSize)

	copy(ioctlQuoteRequestData[0:3], messageSizePrefix)
	copy(ioctlQuoteRequestData[4:], tdReport[:])

	ioctlQuoteRequestHeader := quoteRequestHeader{
		version:      1,
		status:       0,
		inputLength:  4 + messageSize, // TDREPORT is 1024 bytes long.
		outputLength: 0,
		data:         &ioctlQuoteRequestData,
	}

	ioctlQuoteRequest := quoteRequest{
		blob:   uintptr(unsafe.Pointer(&ioctlQuoteRequestHeader)),
		length: requestBufferSize,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), requestQuote, uintptr(unsafe.Pointer(&ioctlQuoteRequest))); errno != 0 {
		return nil, fmt.Errorf("generating quote: %w", errno)
	}

	fmt.Println("Are we still alive?")

	fmt.Printf("qgsGetQuestRequest: %+v", qgsGetQuoteRequest)
	fmt.Printf("qgsGetQuestRequestHeader: %+v", qgsGetQuestRequestHeader)
	fmt.Printf("ioctlQuoteRequest: %+v", ioctlQuoteRequest)
	fmt.Printf("ioctlQuoteRequestHeader: %+v", ioctlQuoteRequestHeader)

	wtf := *ioctlQuoteRequestHeader.data

	return wtf[:], nil
}

func createReport(tdx device, reportData [64]byte) ([1024]byte, error) {
	var tdReport [1024]byte
	reportRequest := reportRequest{
		subtype:          0,
		reportData:       &reportData,
		reportDataLength: 64,
		tdReport:         &tdReport,
		tdReportLength:   1024,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, tdx.Fd(), requestReport, uintptr(unsafe.Pointer(&reportRequest))); errno != 0 {
		return [1024]byte{}, fmt.Errorf("creating TDX report: %w", errno)
	}
	return tdReport, nil
}

// extendRTMREvent is the structure used to extend RTMRs in TDX.
// Based on the kernel patch we got to implement RTMRs for kernel 5.19.
type extendRTMREvent struct {
	algoID       uint8
	digest       *[48]byte
	digestLength uint32
}

/*
reportRequest is the structure used to create TDX reports.

Taken from pytdxmeasure:

	#
	# Reference: Structure of tdx_report_req
	#
	# struct tdx_report_req {
	#        __u8  subtype;
	#        __u64 reportdata;
	#        __u32 rpd_len;
	#        __u64 tdreport;
	#        __u32 tdr_len;
	# };
	#
*/
type reportRequest struct {
	subtype          uint8
	reportData       *[64]byte
	reportDataLength uint32
	tdReport         *[1024]byte
	tdReportLength   uint32
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/71557c7d1d869b6bd6f95566c051cbd098549509/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L84-L95
type quoteRequestHeader struct {
	version      uint64
	status       uint64
	inputLength  uint32
	outputLength uint32
	data         *[16360]byte // Intel defines this as "__u64 data[0]" but uses malloc to reserve more memory underneath.
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L82-L86
type quoteRequest struct {
	blob   uintptr
	length uintptr // size_t / uint64_t
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/09666b3b14147145232ea4f28d85762ca5da3c5d/QuoteGeneration/quote_wrapper/qgs_msg_lib/inc/qgs_msg_lib.h#L71-L77
type qgsMessageHeader struct {
	majorVersion uint16
	minorVersion uint16
	messageType  uint32 // type but this is a reserved word in Go
	size         uint32 // size of the whole message, include this header, in byte
	errorCode    uint32
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/09666b3b14147145232ea4f28d85762ca5da3c5d/QuoteGeneration/quote_wrapper/qgs_msg_lib/inc/qgs_msg_lib.h#L79-L84
type qgsGetQuoteRequestMessage struct {
	header          qgsMessageHeader
	reportSize      uint32  // cannot be 0
	selectedIDSize  uint32  // can be 0
	idListSize      uint32  // can be 0
	reportAndIDList uintptr // some byte array that holds the report
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/09666b3b14147145232ea4f28d85762ca5da3c5d/QuoteGeneration/quote_wrapper/qgs_msg_lib/inc/qgs_msg_lib.h#L86-L91
type qgsGetQuoteResponseMessage struct {
	header         qgsMessageHeader
	selectedIDSize uint32
	quoteSize      uint32
	idAndQuote     uintptr // some byte array that holds the selected id followed by the quote
}
