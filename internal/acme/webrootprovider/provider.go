package webrootprovider

import (
	"fmt"
	"os"
	"path/filepath"
)

// Provider implements lego's HTTP-01 challenge provider by writing files into a webroot.
// It creates files at <webroot>/.well-known/acme-challenge/<token> with the key authorization content.
 type Provider struct {
	Root string
}

func New(root string) *Provider { return &Provider{Root: root} }

func (p *Provider) Present(domain, token, keyAuth string) error {
	if p.Root == "" { return fmt.Errorf("webroot is empty") }
	dir := filepath.Join(p.Root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0755); err != nil { return err }
	path := filepath.Join(dir, token)
	return os.WriteFile(path, []byte(keyAuth), 0644)
}

func (p *Provider) CleanUp(domain, token, keyAuth string) error {
	dir := filepath.Join(p.Root, ".well-known", "acme-challenge")
	path := filepath.Join(dir, token)
	_ = os.Remove(path)
	return nil
}
