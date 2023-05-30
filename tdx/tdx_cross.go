//go:build !linux
// +build !linux

package tdx

import "errors"

// ExtendRTMR extends the RTMR with the given data.
func ExtendRTMR(_ device, _ []byte, _ uint8) error {
	return errors.New("extending rtmrs is only supported on linux")
}

// ReadMeasurements reads the MRTD and RTMRs of a TDX guest.
func ReadMeasurements(_ device) ([5][48]byte, error) {
	return [5][48]byte{}, errors.New("reading measurements is only supported on linux")
}

// GenerateQuote generates a TDX quote for the given user data.
// User Data may not be longer than 64 bytes.
func GenerateQuote(tdx device, userData []byte) ([]byte, error) {
	return nil, errors.New("generating quote is only supported on linux")
}
