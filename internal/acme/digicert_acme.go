//go:build digicert
// +build digicert

package acme

import (
	"crypto"
	// "crypto/ecdsa"
	// "crypto/elliptic"
	// "crypto/rand"
	// "crypto/rsa"
	// "crypto/x509"
	// "crypto/x509/pkix"
	// "encoding/pem"
	"fmt"
	"net/http"
	// "strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type DigiCertEABConfig struct {
	ServerURL   string
	EABKID      string
	EABHMACKey  string
	Email       string
	KeyType     string
	KeySize     int
	BaseDir     string
}

type digicertUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *digicertUser) GetEmail() string                        { return u.Email }
func (u *digicertUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *digicertUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type DigiCertACMEProvider struct {
	client *lego.Client
	opts   DigiCertEABConfig
}

func NewDigiCertACMEProvider(opts DigiCertEABConfig) (*DigiCertACMEProvider, error) {
	if opts.EABKID == "" || opts.EABHMACKey == "" {
		return nil, fmt.Errorf("EAB KID and HMAC key required")
	}
	if opts.KeyType == "" { opts.KeyType = "rsa" }
	if opts.KeySize == 0 { 
		if opts.KeyType == "rsa" { opts.KeySize = 2048 } else { opts.KeySize = 256 } 
	}

	priv, err := generateKey(opts.KeyType, opts.KeySize)
	if err != nil { return nil, err }
	
	user := &digicertUser{ Email: opts.Email, key: priv }

	config := lego.NewConfig(user)
	config.CADirURL = opts.ServerURL
	config.UserAgent = "trusttls/1.0"
	config.HTTPClient = &http.Client{ Timeout: 30 * time.Second }

	client, err := lego.NewClient(config)
	if err != nil { return nil, err }

	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "")); err != nil {
		return nil, fmt.Errorf("set http01 provider: %w", err)
	}

	eab := &registration.ExternalAccountBinding{
		KID:     opts.EABKID,
		HMACKey: opts.EABHMACKey,
	}

	reg, err := client.Registration.RegisterWithEAB(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
		ExternalAccountBinding: eab,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register with EAB: %w", err)
	}
	user.Registration = reg

	return &DigiCertACMEProvider{ client: client, opts: opts }, nil
}

func (p *DigiCertACMEProvider) ObtainCertificate(domains []string) (*certificate.Resource, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain required")
	}

	req := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	cert, err := p.client.Certificate.Obtain(req)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	return cert, nil
}
