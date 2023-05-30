// Package TDX provides functionality to interact with the Intel TDX guest device.
package tdx

// GuestDevice is the path to the TDX guest device.
const GuestDevice = "/dev/tdx-guest"

// device is a handle to the TDX guest device.
type device interface {
	Fd() uintptr
}
