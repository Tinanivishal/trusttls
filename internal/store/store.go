package store

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certificate"
)

func DefaultBaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil { return "/var/lib/trusttls" }
	return filepath.Join(home, ".trusttls")
}

func ensureDir(p string, perm os.FileMode) error {
	if err := os.MkdirAll(p, perm); err != nil { return err }
	return os.Chmod(p, perm)
}

func SaveCertificate(baseDir, domain string, cert *certificate.Resource) (string, error) {
	dir := filepath.Join(baseDir, "live", domain)
	if err := ensureDir(dir, 0700); err != nil { return "", err }
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), cert.Certificate, 0600); err != nil { return "", err }
	if err := os.WriteFile(filepath.Join(dir, "chain.pem"), cert.IssuerCertificate, 0600); err != nil { return "", err }
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), append(cert.Certificate, cert.IssuerCertificate...), 0600); err != nil { return "", err }
	if len(cert.PrivateKey) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), cert.PrivateKey, 0600); err != nil { return "", err }
	}
	latest := filepath.Join(baseDir, "archive", domain, time.Now().Format("20060102-150405"))
	if err := ensureDir(latest, 0700); err != nil { return "", err }
	_ = os.WriteFile(filepath.Join(latest, "cert.pem"), cert.Certificate, 0600)
	_ = os.WriteFile(filepath.Join(latest, "chain.pem"), cert.IssuerCertificate, 0600)
	_ = os.WriteFile(filepath.Join(latest, "fullchain.pem"), append(cert.Certificate, cert.IssuerCertificate...), 0600)
	_ = os.WriteFile(filepath.Join(latest, "privkey.pem"), cert.PrivateKey, 0600)
	return dir, nil
}

func LoadCertPaths(baseDir, domain string) (cert, key, chain, fullchain string) {
	dir := filepath.Join(baseDir, "live", domain)
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "privkey.pem"), filepath.Join(dir, "chain.pem"), filepath.Join(dir, "fullchain.pem")
}

func ParseCertExpiry(pemBytes []byte) (time.Time, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil { return time.Time{}, fmt.Errorf("no pem block") }
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil { return time.Time{}, err }
	return c.NotAfter, nil
}
