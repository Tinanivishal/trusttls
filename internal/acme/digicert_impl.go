//go:build digicert
// +build digicert

package acme

// NewDigiCertProvider creates a new DigiCert provider instance
func NewDigiCertProvider(config DigiCertConfig) interface{} {
	return NewDigiCertProviderImpl(config)
}

// NewDigiCertACMEProvider creates a new DigiCert ACME provider instance
func NewDigiCertACMEProvider(config DigiCertEABConfig) (interface{}, error) {
	return NewDigiCertACMEProviderImpl(config)
}
