package acme

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

type DigiCertConfig struct {
	ServerURL       string
	HMACID          string
	HMACKey         string
	APIKey          string
	AccountID       string
	OrganizationID  string
}

type DigiCertProvider struct {
	config DigiCertConfig
	client *http.Client
}

type DigiCertOrderRequest struct {
	Certificate struct {
		CommonName      string   `json:"common_name"`
		DNSNames        []string `json:"dns_names"`
		SignatureHash   string   `json:"signature_hash"`
		KeySize         int      `json:"key_size"`
		OrganizationID  string   `json:"organization_id,omitempty"`
		CSR             string   `json:"csr,omitempty"`
	} `json:"certificate"`
	ValidityYears int `json:"validity_years"`
}

type DigiCertOrderResponse struct {
	OrderID    string `json:"id"`
	Status     string `json:"status"`
	Certificate struct {
		ID string `json:"id"`
	} `json:"certificate"`
}

type DigiCertCertificate struct {
	ID               string    `json:"id"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expires_at"`
	ServerCert       string    `json:"server_cert"`
	IntermediateCert string    `json:"intermediate_cert"`
	PrivateKey       string    `json:"private_key,omitempty"`
}

type DigiCertDCVMethod struct {
	Type   string `json:"type"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

func NewDigiCertProvider(config DigiCertConfig) *DigiCertProvider {
	return &DigiCertProvider{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *DigiCertProvider) ObtainCertificate(domains []string) (*certificate.Resource, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain required")
	}

	// Generate private key and CSR
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	csr, err := p.generateCSR(domains[0], domains, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Create order with CSR
	orderReq := DigiCertOrderRequest{
		ValidityYears: 1,
	}
	orderReq.Certificate.CommonName = domains[0]
	orderReq.Certificate.DNSNames = domains
	orderReq.Certificate.SignatureHash = "sha256"
	orderReq.Certificate.KeySize = 2048
	orderReq.Certificate.CSR = csr
	if p.config.OrganizationID != "" {
		orderReq.Certificate.OrganizationID = p.config.OrganizationID
	}

	orderResp, err := p.createOrder(orderReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}

	// Handle DCV (Domain Control Validation)
	if err := p.handleDCV(orderResp.OrderID, domains[0]); err != nil {
		return nil, fmt.Errorf("failed to handle DCV: %w", err)
	}

	// Wait for certificate to be issued
	cert, err := p.waitForCertificate(orderResp.OrderID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Marshal private key to PEM
	privKeyPEM := MarshalPrivateKeyToPEM(privateKey)

	return &certificate.Resource{
		Domain:            domains[0],
		Certificate:       []byte(cert.ServerCert),
		PrivateKey:        privKeyPEM,
		IssuerCertificate: []byte(cert.IntermediateCert),
	}, nil
}

func (p *DigiCertProvider) generateCSR(commonName string, dnsNames []string, privateKey *rsa.PrivateKey) (string, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:    dnsNames,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return string(csrPEM), nil
}

func (p *DigiCertProvider) createOrder(req DigiCertOrderRequest) (*DigiCertOrderResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", p.config.ServerURL+"/certificates", nil)
	if err != nil {
		return nil, err
	}

	p.signRequest(httpReq, body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Body = io.NopCloser(bytes.NewReader(body))

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var orderResp DigiCertOrderResponse
	if err := json.NewDecoder(resp.Body).Decode(&orderResp); err != nil {
		return nil, err
	}

	return &orderResp, nil
}

func (p *DigiCertProvider) handleDCV(orderID, domain string) error {
	// Get DCV details
	httpReq, err := http.NewRequest("GET", p.config.ServerURL+"/certificates/"+orderID+"/dcv", nil)
	if err != nil {
		return err
	}

	p.signRequest(httpReq, nil)
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get DCV details: %d", resp.StatusCode)
	}

	var dcvMethods []DigiCertDCVMethod
	if err := json.NewDecoder(resp.Body).Decode(&dcvMethods); err != nil {
		return err
	}

	// Find HTTP-01 DCV method
	var httpDCV *DigiCertDCVMethod
	for _, method := range dcvMethods {
		if method.Type == "http" {
			httpDCV = &method
			break
		}
	}

	if httpDCV == nil {
		return fmt.Errorf("HTTP DCV method not available")
	}

	// For HTTP-01, we would typically place a file at .well-known/acme-challenge/
	// Since this is DigiCert, the token might be different
	fmt.Printf("DCV token: %s\n", httpDCV.Token)
	fmt.Printf("Please place this token in your webroot for domain validation\n")

	return nil
}

func (p *DigiCertProvider) waitForCertificate(orderID string) (*DigiCertCertificate, error) {
	for i := 0; i < 30; i++ { // Wait up to 5 minutes
		cert, err := p.getCertificate(orderID)
		if err != nil {
			return nil, err
		}

		if cert.Status == "issued" {
			return cert, nil
		} else if cert.Status == "failed" {
			return nil, fmt.Errorf("certificate issuance failed")
		}

		time.Sleep(10 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for certificate")
}

func (p *DigiCertProvider) getCertificate(orderID string) (*DigiCertCertificate, error) {
	httpReq, err := http.NewRequest("GET", p.config.ServerURL+"/certificates/"+orderID, nil)
	if err != nil {
		return nil, err
	}

	p.signRequest(httpReq, nil)
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var cert DigiCertCertificate
	if err := json.NewDecoder(resp.Body).Decode(&cert); err != nil {
		return nil, err
	}

	return &cert, nil
}

func (p *DigiCertProvider) signRequest(req *http.Request, body []byte) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	// Create signature string
	var sigString string
	if body != nil {
		sigString = fmt.Sprintf("%s\n%s\n%s", req.Method, req.URL.Path, string(body))
	} else {
		sigString = fmt.Sprintf("%s\n%s", req.Method, req.URL.Path)
	}

	// Create HMAC signature
	h := hmac.New(sha256.New, []byte(p.config.HMACKey))
	h.Write([]byte(sigString))
	signature := hex.EncodeToString(h.Sum(nil))

	// Set headers
	req.Header.Set("X-DC-DEVKEY", p.config.APIKey)
	req.Header.Set("X-DC-TIMESTAMP", timestamp)
	req.Header.Set("X-DC-SIGNATURE", signature)
	if p.config.HMACID != "" {
		req.Header.Set("X-DC-HMAC-ID", p.config.HMACID)
	}
}
