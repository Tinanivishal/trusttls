package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trustctl/trusttls/internal/acme"
	"github.com/trustctl/trusttls/internal/renewal"
	"github.com/trustctl/trusttls/internal/plugins/apache"
	"github.com/trustctl/trusttls/internal/plugins/nginx"
	"github.com/trustctl/trusttls/internal/store"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Obtain and install a certificate into Apache or Nginx",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		email, _ := cmd.Flags().GetString("email")
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		staging, _ := cmd.Flags().GetBool("staging")
		server, _ := cmd.Flags().GetString("server")
		target, _ := cmd.Flags().GetString("target")
		assumeYes, _ := cmd.Flags().GetBool("yes")
		if domain == "" || email == "" {
			return fmt.Errorf("domain and email are required")
		}
		if server == "" {
			if staging { server = acme.LetsEncryptStaging } else { server = acme.LetsEncryptProd }
		}
		storeDir := store.DefaultBaseDir()
		m, err := acme.NewManager(acme.Options{ Email: email, Server: server, KeyType: keyType, KeySize: keySize, BaseDir: storeDir })
		if err != nil { return err }

		var installer Installer
		var chosen string
		if target == "" {
			if apache.Available() { installer = apache.NewInstaller(storeDir, assumeYes); chosen = "apache" }
			if installer == nil && nginx.Available() { installer = nginx.NewInstaller(storeDir, assumeYes); chosen = "nginx" }
		} else if target == "apache" {
			if !apache.Available() { return fmt.Errorf("apache not detected") }
			installer = apache.NewInstaller(storeDir, assumeYes); chosen = "apache"
		} else if target == "nginx" {
			if !nginx.Available() { return fmt.Errorf("nginx not detected") }
			installer = nginx.NewInstaller(storeDir, assumeYes); chosen = "nginx"
		} else {
			return fmt.Errorf("unknown target: %s", target)
		}
		if installer == nil {
			return fmt.Errorf("no supported web server detected; specify --target=apache|nginx")
		}

		wr := installer.Webroot(domain)
		if wr == "" { return fmt.Errorf("could not detect webroot for %s", domain) }
		cert, err := m.ObtainHTTP01([]string{domain}, wr)
		if err != nil { return err }
		if _, err := store.SaveCertificate(storeDir, domain, cert); err != nil { return err }
		if err := installer.Install(domain); err != nil { return err }

		// Save renewal configuration with chosen target
		_ = renewal.Save(renewal.Config{
			Domain:  domain,
			Email:   email,
			Server:  server,
			Method:  "http-01",
			Webroot: wr,
			KeyType: keyType,
			KeySize: keySize,
			Targets: []string{chosen},
			BaseDir: storeDir,
		})
		return nil
	},
}

type Installer interface {
	Webroot(domain string) string
	Install(domain string) error
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().String("domain", "", "Domain to issue certificate for")
	installCmd.Flags().String("email", "", "Account email")
	installCmd.Flags().String("key-type", "rsa", "Key algorithm: rsa or ecdsa")
	installCmd.Flags().Int("key-size", 2048, "Key size for rsa or curve bits (256/384) for ecdsa")
	installCmd.Flags().Bool("staging", false, "Use Let's Encrypt staging CA")
	installCmd.Flags().String("server", "", "ACME directory URL; overrides --staging")
	installCmd.Flags().String("target", "", "Install target: apache or nginx; auto-detect if empty")
	installCmd.Flags().Bool("yes", false, "Assume yes when prompting to modify vhost files")
}
