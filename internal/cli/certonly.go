package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trustctl/trusttls/internal/acme"
	"github.com/trustctl/trusttls/internal/osutil"
	"github.com/trustctl/trusttls/internal/plugins/apache"
	"github.com/trustctl/trusttls/internal/plugins/nginx"
	"github.com/trustctl/trusttls/internal/renewal"
	"github.com/trustctl/trusttls/internal/store"
)

var certonlyCmd = &cobra.Command{
	Use:   "get-cert",
	Short: "Get an SSL certificate for your website",
	Long: `
Get an SSL certificate without installing it automatically.

This command obtains a certificate from your chosen provider and saves it
to your local system. You can then manually install it wherever needed.

Perfect for:
• Testing certificate generation
• Custom installation setups  
• Learning how SSL certificates work
• Backup certificate generation

Example:
  trusttls get-cert --domain example.com --email admin@example.com
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		if domain == "" { domain, _ = cmd.Flags().GetString("website") }
		email, _ := cmd.Flags().GetString("email")
		if email == "" { email, _ = cmd.Flags().GetString("contact") }
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		testMode, _ := cmd.Flags().GetBool("test-mode")
		server, _ := cmd.Flags().GetString("server")
		webroot, _ := cmd.Flags().GetString("webroot")
		if webroot == "" { webroot, _ = cmd.Flags().GetString("web-root") }
		
		if domain == "" || email == "" {
			return fmt.Errorf("website domain and email address are required")
		}
		
		if server == "" {
			if testMode {
				server = acme.LetsEncryptStaging
			} else {
				server = acme.LetsEncryptProd
			}
		}
		
		if webroot == "" {
			wr := detectWebroot(domain)
			if wr == "" {
				return fmt.Errorf("website folder not found for %s; please specify --webroot or ensure Apache/Nginx is configured", domain)
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
		fmt.Printf("🎉 SSL certificate successfully obtained!\n")
		fmt.Printf("📁 Certificate saved to: %s\n", path)
		fmt.Printf("🌐 Domain: %s\n", domain)
		fmt.Printf("📧 Email: %s\n", email)
		fmt.Printf("💡 Next steps:\n")
		fmt.Printf("   • Install the certificate files on your web server\n")
		fmt.Printf("   • Set up automatic renewal with: trusttls renew\n")
		fmt.Printf("   • Test your SSL setup at: https://www.ssllabs.com/ssltest/\n")

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
	certonlyCmd.Flags().String("domain", "", "Your website domain name (e.g., example.com)")
	certonlyCmd.Flags().String("website", "", "Your website domain name (same as --domain)")
	certonlyCmd.Flags().String("email", "", "Your email address for certificate notifications")
	certonlyCmd.Flags().String("contact", "", "Your email address (same as --email)")
	certonlyCmd.Flags().String("key-type", "rsa", "Encryption key type: rsa (recommended) or ecdsa")
	certonlyCmd.Flags().Int("key-size", 2048, "Key strength: 2048 or 4096 for RSA, 256 or 384 for ECDSA")
	certonlyCmd.Flags().Bool("test-mode", false, "Use test environment (won't issue real certificates)")
	certonlyCmd.Flags().String("server", "", "Custom certificate provider URL")
	certonlyCmd.Flags().String("webroot", "", "Website folder for validation (e.g., /var/www/html)")
	certonlyCmd.Flags().String("web-root", "", "Website folder for validation (same as --webroot)")
}
