package acme

// DigiCertConfig holds configuration for DigiCert API integration
type DigiCertConfig struct {
	ServerURL       string
	HMACID          string
	HMACKey         string
	APIKey          string
	AccountID       string
	OrganizationID  string
}

// DigiCertEABConfig holds configuration for DigiCert ACME with External Account Binding
type DigiCertEABConfig struct {
	ServerURL   string
	EABKID      string
	EABHMACKey  string
	Email       string
	KeyType     string
	KeySize     int
	BaseDir     string
}
