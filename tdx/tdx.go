// Package TDX provides functionality to interact with the Intel TDX guest device.
package tdx

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/edgelesssys/go-tdx-qpl/tdx/tdxproto"
	"github.com/vtolstov/go-ioctl"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// guestDevice is the path to the TDX guest device.
const guestDevice = "/dev/tdx-guest"

// tdxQuoteType is the type of quote to request.
const tdxQuoteType = uint32(2)

// IOCTL calls for quote generation
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L53-L56
var (
	requestReport = ioctl.IOWR('T', 0x01, 8)
	requestQuote  = ioctl.IOR('T', 0x02, 8)
)

// extendRTMR is a call to extend TDX RTMRs.
// Intel frequently changes this value, so we pin it to IOWR and 0x03 and patch their patchset.
var extendRTMR = ioctl.IOWR('T', 0x03, 8)

// tdxReportUUID is a UUID to request TDX quotes.
// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.h#L70
var tdxReportUUID = []*tdxproto.UUID{{
	Value: []byte{0xe8, 0x6c, 0x04, 0x6e, 0x8c, 0xc4, 0x4d, 0x95, 0x81, 0x73, 0xfc, 0x43, 0xc1, 0xfa, 0x4f, 0x3f},
}}

// Handle is a handle to the TDX guest device.
type Handle struct {
	device *os.File
}

// Open opens the TDX guest device and returns a handle to it.
func Open() (*Handle, error) {
	device, err := os.Open(guestDevice)
	if err != nil {
		return nil, err
	}

	return &Handle{
		device: device,
	}, nil
}

// Close closes the handle to the TDX guest device.
func (h *Handle) Close() error {
	return h.device.Close()
}

// ExtendRTMR extends the RTMR with the given data.
func (h *Handle) ExtendRTMR(extendData []byte, index uint8) error {
	extendDataHash := sha512.Sum384(extendData)
	extendEvent := tdxExtendRTMREvent{
		algoID:       5, // HASH_ALGO_SHA384 -> linux/include/uapi/linux/hash_info.h
		digest:       &extendDataHash,
		digestLength: 48,
	}

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, h.device.Fd(), extendRTMR, uintptr(unsafe.Pointer(&extendEvent))); errno != 0 {
		return fmt.Errorf("extending RTMR: %w", errno)
	}
	return nil
}

// GenerateQuote generates a TDX quote for the given user data.
func (h *Handle) GenerateQuote(userData []byte) ([]byte, error) {
	if len(userData) > 64 {
		return nil, fmt.Errorf("user data must not be longer than 64 bytes, received %d bytes", len(userData))
	}
	tdReport, err := h.createReport([64]byte(userData))
	if err != nil {
		return nil, fmt.Errorf("creating report: %w", err)
	}

	getQuoteRequest := tdxproto.Request_GetQuoteRequest{
		Report: tdReport,
		IdList: tdxReportUUID,
	}

	quoteType := tdxQuoteType
	quoteRequest := tdxproto.Request{
		Type: &quoteType,
		Msg:  &tdxproto.Request_GetQuoteRequest_{GetQuoteRequest: &getQuoteRequest},
	}
	serializedQuoteRequest, err := proto.Marshal(&quoteRequest)
	if err != nil {
		return nil, fmt.Errorf("marshaling quote request: %w", err)
	}

	var transferLength [4]byte
	binary.BigEndian.PutUint32(transferLength[:], uint32(len(serializedQuoteRequest)))

	transferLengthUint32 := [4]byte{transferLength[0], transferLength[1], transferLength[2], transferLength[3]}

	var protobufData [4*4*1024 - 28]byte
	copy(protobufData[:], serializedQuoteRequest)
	quoteRequestWrapper := tdxRequestQuoteWrapper{
		version:     1,
		status:      0,
		inputLength: 4 + uint32(len(serializedQuoteRequest)),
		// outputLength:   uint32(unsafe.Sizeof(tdxRequestQuoteWrapper{})) - 24,
		outputLength:   16384 - 24,
		transferLength: transferLengthUint32,
		protobufData:   protobufData,
	}

	outerWrapper := tdxRequestQuoteOuterWrapper{
		blob:   uintptr(unsafe.Pointer(&quoteRequestWrapper)),
		length: unsafe.Sizeof(quoteRequestWrapper),
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, h.device.Fd(), requestQuote, uintptr(unsafe.Pointer(&outerWrapper))); errno != 0 {
		return nil, fmt.Errorf("generating quote: %w", errno)
	}

	var quoteResponse tdxproto.Response
	if err := proto.Unmarshal(quoteRequestWrapper.protobufData[:quoteRequestWrapper.outputLength-4], &quoteResponse); err != nil {
		return nil, err
	}

	return quoteResponse.GetGetQuoteResponse().Quote, nil
}

func (h *Handle) createReport(reportData [64]byte) ([]byte, error) {
	var tdReport [1024]byte
	reportRequest := tdxReportRequest{
		subtype:          0,
		reportData:       &reportData,
		reportDataLength: 64,
		tdReport:         &tdReport,
		tdReportLength:   1024,
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, h.device.Fd(), requestReport, uintptr(unsafe.Pointer(&reportRequest))); errno != 0 {
		return nil, fmt.Errorf("creating TDX report: %w", errno)
	}
	return tdReport[:], nil
}

// Based on the kernel patch we got to implement RTMRs for kernel 5.19
type tdxExtendRTMREvent struct {
	algoID       uint8
	digest       *[48]byte
	digestLength uint32
}

/*
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

This is also likely somewhere in the kernel patches Intel shipped for us for the TDX Linux 5.19 development kernel.
*/
type tdxReportRequest struct {
	subtype          uint8
	reportData       *[64]byte
	reportDataLength uint32
	tdReport         *[1024]byte
	tdReportLength   uint32
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L70-L80
type tdxRequestQuoteWrapper struct {
	version        uint64
	status         uint64
	inputLength    uint32
	outputLength   uint32
	transferLength [4]byte             // BIG-ENDIAN
	protobufData   [4*4*1024 - 28]byte // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/qgs/qgs.message.proto
}

// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/c057b236790834cf7e547ebf90da91c53c7ed7f9/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c#L82-L86
type tdxRequestQuoteOuterWrapper struct {
	blob   uintptr
	length uintptr // size_t / uint64_t
}
