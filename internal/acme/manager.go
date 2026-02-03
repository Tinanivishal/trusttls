package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/trustctl/trusttls/internal/acme/webrootprovider"
)

const (
	LetsEncryptProd    = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Options struct {
	Email   string
	Server  string
	KeyType string // rsa|ecdsa
	KeySize int    // rsa bits or ecdsa curve bits (256/384)
	BaseDir string
}

type Manager struct {
	client *lego.Client
	opts   Options
}

// user implements lego User interface
 type user struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

func NewManager(opts Options) (*Manager, error) {
	if opts.Email == "" || opts.Server == "" { return nil, errors.New("email and server required") }
	if opts.KeyType == "" { opts.KeyType = "rsa" }
	if opts.KeySize == 0 { if opts.KeyType == "rsa" { opts.KeySize = 2048 } else { opts.KeySize = 256 } }

	priv, err := generateKey(opts.KeyType, opts.KeySize)
	if err != nil { return nil, err }
	u := &user{ Email: opts.Email, key: priv }

	config := lego.NewConfig(u)
	config.CADirURL = opts.Server
	config.UserAgent = "trusttls/1.0"
	config.HTTPClient = &http.Client{ Timeout: 30 * time.Second }

	client, err := lego.NewClient(config)
	if err != nil { return nil, err }

	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "")); err != nil {
		return nil, fmt.Errorf("set http01 provider: %w", err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil && !alreadyRegistered(err) {
		return nil, err
	}
	u.Registration = reg
	return &Manager{ client: client, opts: opts }, nil
}

func alreadyRegistered(err error) bool {
    if err == nil { return false }
    msg := err.Error()
    // Common indicators that the account already exists
    if strings.Contains(msg, "already registered") { return true }
    if strings.Contains(msg, "urn:ietf:params:acme:error:accountAlreadyExists") { return true }
    return false
}

// ObtainHTTP01 obtains a certificate for domains using HTTP-01 via a webroot path.
func (m *Manager) ObtainHTTP01(domains []string, webroot string) (*certificate.Resource, error) {
	provider := webrootprovider.New(webroot)
	if err := m.client.Challenge.SetHTTP01Provider(provider); err != nil { return nil, err }
	req := certificate.ObtainRequest{ Domains: domains, Bundle: true }
	return m.client.Certificate.Obtain(req)
}

func generateKey(kind string, size int) (crypto.PrivateKey, error) {
	switch kind {
	case "rsa":
		if size < 2048 { size = 2048 }
		return rsa.GenerateKey(rand.Reader, size)
	case "ecdsa":
		var curve elliptic.Curve
		switch size {
		case 384:
			curve = elliptic.P384()
		default:
			curve = elliptic.P256()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, fmt.Errorf("unknown key type: %s", kind)
	}
}

func MarshalPrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}), nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil { return nil, err }
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
