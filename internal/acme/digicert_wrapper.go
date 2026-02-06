package acme

import (
	"fmt"
)

// NewDigiCertProvider creates a new DigiCert provider instance
// This function is available without build tags and will return an error
// if the digicert build tag is not enabled
func NewDigiCertProvider(config DigiCertConfig) (interface{}, error) {
	return nil, fmt.Errorf("DigiCert provider not available - build with digicert tag: go build -tags digicert")
}

// NewDigiCertACMEProvider creates a new DigiCert ACME provider instance
// This function is available without build tags and will return an error
// if the digicert build tag is not enabled
func NewDigiCertACMEProvider(config DigiCertEABConfig) (interface{}, error) {
	return nil, fmt.Errorf("DigiCert ACME provider not available - build with digicert tag: go build -tags digicert")
}
