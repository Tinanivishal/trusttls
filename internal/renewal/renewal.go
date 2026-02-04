package renewal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trustctl/trusttls/internal/acme"
	"github.com/trustctl/trusttls/internal/store"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Domain    string   `yaml:"domain"`
	Email     string   `yaml:"email"`
	Server    string   `yaml:"server"`
	Method    string   `yaml:"method"`   // http-01|dns-01|digicert
	Webroot   string   `yaml:"webroot"`  // for http-01
	DNSPlugin string   `yaml:"dns_plugin"`
	KeyType   string   `yaml:"key_type"`
	KeySize   int      `yaml:"key_size"`
	Targets   []string `yaml:"targets"` // apache|nginx
	BaseDir   string   `yaml:"base_dir"`
	Provider  string   `yaml:"provider"`  // letsencrypt|digicert
}

func dir() string {
	return filepath.Join(store.DefaultBaseDir(), "renewal")
}

func ensureDir() error {
	return os.MkdirAll(dir(), 0700)
}

func configPath(domain string) string {
	return filepath.Join(dir(), domain+".yaml")
}

func Save(cfg Config) error {
	if cfg.Domain == "" { return errors.New("domain required") }
	if cfg.BaseDir == "" { cfg.BaseDir = store.DefaultBaseDir() }
	if err := ensureDir(); err != nil { return err }
	b, err := yaml.Marshal(&cfg)
	if err != nil { return err }
	return os.WriteFile(configPath(cfg.Domain), b, 0600)
}

func load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil { return c, err }
	if err := yaml.Unmarshal(b, &c); err != nil { return c, err }
	if c.BaseDir == "" { c.BaseDir = store.DefaultBaseDir() }
	return c, nil
}

func due(domain string) bool {
	certPath, _, _, _ := store.LoadCertPaths(store.DefaultBaseDir(), domain)
	b, err := os.ReadFile(certPath)
	if err != nil { return true }
	exp, err := store.ParseCertExpiry(b)
	if err != nil { return true }
	return time.Until(exp) < 30*24*time.Hour
}

func renewOne(c Config, verbose bool) error {
	accountManager := store.NewAccountManager(c.BaseDir)
	
	switch c.Provider {
	case "digicert":
		digiCertConfig, err := accountManager.GetDigiCertConfig(c.Email)
		if err != nil {
			return fmt.Errorf("failed to load DigiCert credentials: %w", err)
		}
		
		provider := acme.NewDigiCertProvider(*digiCertConfig)
		cert, err := provider.ObtainCertificate([]string{c.Domain})
		if err != nil {
			return err
		}
		if _, err := store.SaveCertificate(c.BaseDir, c.Domain, cert); err != nil {
			return err
		}
		if verbose {
			fmt.Printf("renewed %s via DigiCert\n", c.Domain)
		}
		
	case "letsencrypt", "":
		if c.Method != "http-01" {
			return fmt.Errorf("unsupported method: %s", c.Method)
		}
		m, err := acme.NewManager(acme.Options{
			Email:   c.Email,
			Server:  c.Server,
			KeyType: c.KeyType,
			KeySize: c.KeySize,
			BaseDir: c.BaseDir,
		})
		if err != nil {
			return err
		}
		cert, err := m.ObtainHTTP01([]string{c.Domain}, c.Webroot)
		if err != nil {
			return err
		}
		if _, err := store.SaveCertificate(c.BaseDir, c.Domain, cert); err != nil {
			return err
		}
		if verbose {
			fmt.Printf("renewed %s via Let's Encrypt\n", c.Domain)
		}
		
	default:
		return fmt.Errorf("unsupported provider: %s", c.Provider)
	}
	
	return nil
}

func RunAll(verbose bool) error {
	if err := ensureDir(); err != nil { return err }
	var errs []string
	_ = filepath.WalkDir(dir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil { return nil }
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") { return nil }
		cfg, e := load(path)
		if e != nil { errs = append(errs, fmt.Sprintf("%s: %v", d.Name(), e)); return nil }
		if !due(cfg.Domain) { return nil }
		if e := renewOne(cfg, verbose); e != nil { errs = append(errs, fmt.Sprintf("%s: %v", cfg.Domain, e)) }
		return nil
	})
	if len(errs) > 0 { return fmt.Errorf("some renewals failed: %s", strings.Join(errs, "; ")) }
	return nil
}
