package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trustctl/trusttls/internal/acme"
	"github.com/trustctl/trusttls/internal/osutil"
	"github.com/trustctl/trusttls/internal/plugins/apache"
	"github.com/trustctl/trusttls/internal/plugins/nginx"
	"github.com/trustctl/trusttls/internal/renewal"
	"github.com/trustctl/trusttls/internal/store"
)

var certonlyCmd = &cobra.Command{
	Use:   "certonly",
	Short: "Obtain a certificate without installing it",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" { domain, _ = cmd.Flags().GetString("website") }
		email, _ := cmd.Flags().GetString("email")
		if email == "" { email, _ = cmd.Flags().GetString("contact") }
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		staging, _ := cmd.Flags().GetBool("staging")
		server, _ := cmd.Flags().GetString("server")
		webroot, _ := cmd.Flags().GetString("webroot")
		if webroot == "" { webroot, _ = cmd.Flags().GetString("web-root") }
		if domain == "" || email == "" {
			return fmt.Errorf("domain and email are required")
		}
		if server == "" {
			if staging {
				server = acme.LetsEncryptStaging
			} else {
				server = acme.LetsEncryptProd
			}
		}
		if webroot == "" {
			wr := detectWebroot(domain)
			if wr == "" {
				return fmt.Errorf("webroot not found for %s; pass --webroot explicitly or ensure Apache/Nginx vhost:80 exists", domain)
			}
			webroot = wr
		}

		storeDir := store.DefaultBaseDir()
		m, err := acme.NewManager(acme.Options{
			Email:    email,
			Server:   server,
			KeyType:  keyType,
			KeySize:  keySize,
			BaseDir:  storeDir,
		})
		if err != nil {
			return err
		}
		cert, err := m.ObtainHTTP01([]string{domain}, webroot)
		if err != nil {
			return err
		}
		path, err := store.SaveCertificate(storeDir, domain, cert)
		if err != nil {
			return err
		}
		fmt.Printf("Certificate obtained and stored at %s\n", path)

		// Save renewal configuration
		_ = renewal.Save(renewal.Config{
			Domain:  domain,
			Email:   email,
			Server:  server,
			Method:  "http-01",
			Webroot: webroot,
			KeyType: keyType,
			KeySize: keySize,
			Targets: []string{},
			BaseDir: storeDir,
		})
		return nil
	},
}

func detectWebroot(domain string) string {
	if p := apache.DetectWebroot(domain); p != "" {
		return p
	}
	if p := nginx.DetectWebroot(domain); p != "" {
		return p
	}
	if osutil.IsMac() {
		c := []string{"/Library/WebServer/Documents", "/usr/local/var/www"}
		for _, p := range c {
			if osutil.DirExists(p) { return p }
		}
	}
	return ""
}

func init() {
	rootCmd.AddCommand(certonlyCmd)
	certonlyCmd.Flags().String("domain", "", "Domain name (same as --website)")
	certonlyCmd.Flags().String("website", "", "Website name (domain)")
	certonlyCmd.Flags().String("email", "", "Contact email (same as --contact)")
	certonlyCmd.Flags().String("contact", "", "Contact email")
	certonlyCmd.Flags().String("key-type", "rsa", "Key algorithm: rsa or ecdsa")
	certonlyCmd.Flags().Int("key-size", 2048, "Key size for rsa or curve bits (256/384) for ecdsa")
	certonlyCmd.Flags().Bool("staging", false, "Use Let's Encrypt staging CA")
	certonlyCmd.Flags().String("server", "", "ACME directory URL; overrides --staging")
	certonlyCmd.Flags().String("webroot", "", "Explicit webroot for HTTP-01 (same as --web-root)")
	certonlyCmd.Flags().String("web-root", "", "Explicit webroot for HTTP-01")
}
