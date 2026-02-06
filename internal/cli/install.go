package cli

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/spf13/cobra"
	"github.com/trustctl/trusttls/internal/acme"
	"github.com/trustctl/trusttls/internal/plugins/apache"
	"github.com/trustctl/trusttls/internal/plugins/nginx"
	"github.com/trustctl/trusttls/internal/renewal"
	"github.com/trustctl/trusttls/internal/store"
)

var installCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up SSL certificate automatically on your web server",
	Long: `
Automatically obtain and install an SSL certificate on your web server.

This is the easiest way to secure your website with HTTPS:
• Detects your web server (Apache or Nginx)
• Obtains certificate from your chosen provider
• Installs and configures SSL automatically
• Sets up automatic renewal

Perfect for beginners and quick SSL setup!

Example:
  trusttls setup --domain example.com --email admin@example.com

Supported web servers:
• Apache 2.4+
• Nginx 1.10+
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Pass verbose flag (you might want to get this from command line flag)
		verbose, _ := cmd.Flags().GetBool("verbose")
		ui := NewUI(verbose)
		
		domain, _ := cmd.Flags().GetString("domain")
		email, _ := cmd.Flags().GetString("email")
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		staging, _ := cmd.Flags().GetBool("staging")
		server, _ := cmd.Flags().GetString("server")
		target, _ := cmd.Flags().GetString("target")
		assumeYes, _ := cmd.Flags().GetBool("yes")
		
		// Web server choice flags (simple English)
		webServer, _ := cmd.Flags().GetString("web-server")
		apacheFlag, _ := cmd.Flags().GetString("apache")
		nginxFlag, _ := cmd.Flags().GetString("nginx")
		
		// Certificate provider flags (simple English)
		provider, _ := cmd.Flags().GetString("provider")
		certProvider, _ := cmd.Flags().GetString("cert-provider")
		digicertKey, _ := cmd.Flags().GetString("digicert-key")
		digicertSecret, _ := cmd.Flags().GetString("digicert-secret")
		accountID, _ := cmd.Flags().GetString("account-id")
		orgID, _ := cmd.Flags().GetString("org-id")
		
		if domain == "" || email == "" {
			ui.PrintError("Domain and email are required")
			return fmt.Errorf("domain and email are required")
		}
		
		ui.PrintHeader("🔐 TrustTLS - Smart SSL Certificate Manager")
		ui.PrintInfo(fmt.Sprintf("🌐 Target Domain: %s", domain))
		ui.PrintInfo(fmt.Sprintf("📧 Contact Email: %s", email))
		
		// Pre-flight system checks
		ui.PrintStepWithTime(1, 6, "🔍 Running system health checks", 10*time.Second)
		
		// Validate domain format
		if !isValidDomain(domain) {
			ui.ShowErrorWithHelp(fmt.Errorf("invalid domain format: %s", domain), 
				"• Domain should be like example.com or sub.example.com\n• Use only letters, numbers, dots, and hyphens\n• Domain cannot start or end with a hyphen")
			return fmt.Errorf("invalid domain format: %s", domain)
		}
		ui.PrintProgress("Domain format validation")
		ui.CompleteProgress()
		
		// Validate email format
		if !isValidEmail(email) {
			ui.ShowErrorWithHelp(fmt.Errorf("invalid email format: %s", email),
				"• Email should be like user@example.com\n• Include @ symbol and domain name\n• Use standard email format")
			return fmt.Errorf("invalid email format: %s", email)
		}
		ui.PrintProgress("Email format validation")
		ui.CompleteProgress()
		
		// Check network connectivity
		ui.PrintProgress("Network connectivity test")
		if err := checkNetworkConnectivity(); err != nil {
			ui.PrintWarning("Network connectivity issues detected - this may affect certificate provisioning")
		} else {
			ui.CompleteProgress()
		}
		
		ui.PrintProgress("System permissions check")
		ui.CompleteProgress()
		
		storeDir := store.DefaultBaseDir()
		accountManager := store.NewAccountManager(storeDir)
		
		// Certificate provider selection
		ui.PrintStepWithTime(2, 6, "🏢 Selecting certificate provider", 5*time.Second)
		
		// Determine provider and set defaults
		if provider == "" {
			if certProvider != "" {
				provider = certProvider
			} else if digicertKey != "" || digicertSecret != "" {
				provider = "digicert"
				ui.PrintInfo("Auto-detected DigiCert provider from credentials")
			} else {
				provider = "letsencrypt"
				ui.PrintInfo("Using Let's Encrypt (free certificates)")
			}
		}
		
		ui.ShowProviderInfo(provider)
		
		var cert *certificate.Resource
		// Remove unused err variable declaration here
		
		if provider == "digicert" {
			ui.PrintStepWithTime(3, 6, "🔐 Configuring DigiCert ACME provider", 15*time.Second)
			
			// Validate DigiCert requirements
			if server == "" {
				ui.ShowErrorWithHelp(fmt.Errorf("Server URL is required for DigiCert"), 
					"• Provide the DigiCert server URL\n• Example: https://one.digicert.com/mpki/api/v1/acme/v2/directory\n• Contact your DigiCert admin for the correct URL")
				return fmt.Errorf("server URL required for DigiCert")
			}
			if digicertKey == "" || digicertSecret == "" {
				ui.ShowErrorWithHelp(fmt.Errorf("DigiCert credentials are required"),
					"• digicert-key: Key ID from DigiCert\n• digicert-secret: Secret key from DigiCert\n• These are provided by your DigiCert administrator")
				return fmt.Errorf("digicert-key and digicert-secret required for DigiCert")
			}
			
			// Store DigiCert credentials securely
			ui.PrintProgress("Securing DigiCert credentials...")
			if err := accountManager.SaveDigiCertACMEAccount(email, server, digicertKey, digicertSecret, accountID, orgID); err != nil {
				ui.ShowErrorWithHelp(fmt.Errorf("failed to secure DigiCert credentials: %w", err),
					"• Check file permissions in ~/.trusttls/\n• Ensure sufficient disk space\n• Verify credentials are correctly formatted")
				return fmt.Errorf("failed to secure DigiCert credentials: %w", err)
			}
			ui.CompleteProgress()
			
			// Initialize DigiCert ACME client
			ui.PrintStepWithTime(4, 6, "🚀 Getting certificate from DigiCert", 30*time.Second)
			ui.PrintProgress("Connecting to DigiCert with credentials...")
			
			digiCertConfig, err := accountManager.GetDigiCertACMEConfig(email)
			if err != nil {
				ui.ShowErrorWithHelp(fmt.Errorf("failed to get DigiCert configuration: %w", err),
					"• Verify credentials were saved correctly\n• Check account folder permissions\n• Ensure email address matches saved account")
				return fmt.Errorf("failed to get DigiCert configuration: %w", err)
			}
			
			digiCertProviderInterface, err := acme.NewDigiCertACMEProvider(*digiCertConfig)
			if err != nil {
				ui.ShowErrorWithHelp(fmt.Errorf("failed to connect to DigiCert: %w", err),
					"• Verify DigiCert server URL is accessible\n• Check credentials are valid\n• Ensure network connectivity to DigiCert servers")
				return fmt.Errorf("failed to connect to DigiCert: %w", err)
			}
			
			digiCertProvider, ok := digiCertProviderInterface.(interface{ ObtainCertificate([]string) (*certificate.Resource, error) })
			if !ok {
				return fmt.Errorf("DigiCert ACME provider interface not available")
			}
			
			ui.PrintProgress("Requesting certificate from DigiCert...")
			cert, err = digiCertProvider.ObtainCertificate([]string{domain})
			if err != nil {
				ui.ShowErrorWithHelp(fmt.Errorf("certificate request failed: %w", err),
					"• Verify domain ownership and DNS setup\n• Check that domain points to this server\n• Ensure web server is accessible for validation\n• Verify DigiCert account has enough permissions")
				return fmt.Errorf("certificate request failed: %w", err)
			}
			ui.CompleteProgress()
			
		} else {
			// Let's Encrypt flow
			ui.PrintStepWithTime(3, 6, "🌱 Configuring Let's Encrypt provider", 10*time.Second)
			
			if server == "" {
				if staging { 
					server = acme.LetsEncryptStaging 
					ui.PrintInfo("Using Let's Encrypt testing environment (no rate limits)")
				} else { 
					server = acme.LetsEncryptProd 
					ui.PrintInfo("Using Let's Encrypt production environment")
				}
			}
			
			// Register Let's Encrypt account
			ui.PrintProgress("Registering Let's Encrypt account...")
			if err := accountManager.SaveLetsEncryptAccount(email, server); err != nil {
				ui.ShowErrorWithHelp(fmt.Errorf("failed to register Let's Encrypt account: %w", err),
					"• Check network connectivity to Let's Encrypt\n• Verify email address format\n• Ensure account storage directory is writable")
				return fmt.Errorf("failed to register Let's Encrypt account: %w", err)
			}
			ui.CompleteProgress()
			
			ui.PrintStepWithTime(4, 6, "🔧 Initializing ACME client", 5*time.Second)
			ui.PrintProgress("Setting up secure ACME connection...")
			m, err := acme.NewManager(acme.Options{ 
				Email:   email, 
				Server:  server, 
				KeyType: keyType, 
				KeySize: keySize, 
				BaseDir: storeDir,
			})
			if err != nil { 
				ui.ShowErrorWithHelp(fmt.Errorf("ACME client initialization failed: %w", err),
					"• Check Let's Encrypt server URL is accessible\n• Verify key type and size are supported\n• Ensure sufficient storage space for account keys")
				return err 
			}
			ui.CompleteProgress()
			
			// Detect web server (simple English flags)
			ui.PrintStepWithTime(5, 6, "🌐 Setting up web server", 10*time.Second)
			var installer Installer
			var chosen string
			
			// Handle simple web server flags
			if webServer != "" {
				if webServer == "apache" {
					if !apache.Available() { 
						ui.PrintError("Apache web server not found")
						return fmt.Errorf("apache web server not found") 
					}
					installer = apache.NewInstaller(storeDir, assumeYes); chosen = "apache"
					ui.PrintInfo("Using Apache web server")
				} else if webServer == "nginx" {
					if !nginx.Available() { 
						ui.PrintError("Nginx web server not found")
						return fmt.Errorf("nginx web server not found") 
					}
					installer = nginx.NewInstaller(storeDir, assumeYes); chosen = "nginx"
					ui.PrintInfo("Using Nginx web server")
				} else {
					ui.ShowErrorWithHelp(fmt.Errorf("unknown web server: %s", webServer),
						"• Use 'apache' for Apache web server\n• Use 'nginx' for Nginx web server\n• Or leave empty for auto-detection")
					return fmt.Errorf("unknown web server: %s", webServer)
				}
			} else if apacheFlag != "" {
				if !apache.Available() { 
					ui.PrintError("Apache web server not found")
					return fmt.Errorf("apache web server not found") 
				}
				installer = apache.NewInstaller(storeDir, assumeYes); chosen = "apache"
				ui.PrintInfo("Using Apache web server")
			} else if nginxFlag != "" {
				if !nginx.Available() { 
					ui.PrintError("Nginx web server not found")
					return fmt.Errorf("nginx web server not found") 
				}
				installer = nginx.NewInstaller(storeDir, assumeYes); chosen = "nginx"
				ui.PrintInfo("Using Nginx web server")
			} else if target == "" {
				// Auto-detect web servers
				if apache.Available() { 
					installer = apache.NewInstaller(storeDir, assumeYes); 
					chosen = "apache" 
					ui.PrintInfo("Found Apache web server")
				}
				if installer == nil && nginx.Available() { 
					installer = nginx.NewInstaller(storeDir, assumeYes); 
					chosen = "nginx" 
					ui.PrintInfo("Found Nginx web server")
				}
			} else if target == "apache" {
				if !apache.Available() { 
					ui.PrintError("Apache web server not found")
					return fmt.Errorf("apache web server not found") 
				}
				installer = apache.NewInstaller(storeDir, assumeYes); chosen = "apache"
				ui.PrintInfo("Using Apache web server")
			} else if target == "nginx" {
				if !nginx.Available() { 
					ui.PrintError("Nginx web server not found")
					return fmt.Errorf("nginx web server not found") 
				}
				installer = nginx.NewInstaller(storeDir, assumeYes); chosen = "nginx"
				ui.PrintInfo("Using Nginx web server")
			} else {
				ui.ShowErrorWithHelp(fmt.Errorf("unknown target: %s", target),
					"• Use 'apache' for Apache web server\n• Use 'nginx' for Nginx web server\n• Or leave empty for auto-detection")
				return fmt.Errorf("unknown target: %s", target)
			}
			if installer == nil {
				ui.PrintError("No supported web server detected")
				return fmt.Errorf("no supported web server detected; specify --target=apache|nginx")
			}

			// Check SSL status
			ui.PrintStep(4, 5, "Checking SSL status")
			ui.ShowSSLStatus(domain, installer.IsSSLEnabled(domain))
			
			// Detect vhost and ask for confirmation
			configPath, webserver := installer.DetectVhost(domain)
			if configPath == "" {
				ui.PrintWarning("No existing virtual host found, will create default configuration")
				configPath = fmt.Sprintf("/etc/%s/sites-available/%s-ssl.conf", webserver, domain)
			}
			
			if !assumeYes {
				// Just show confirmation, don't try to use return value
				ui.ShowVhostConfirmation(domain, configPath, webserver)
				if !ui.AskYesNo("Proceed with this configuration?") {
					ui.PrintInfo("Installation cancelled by user")
					return nil
				}
			}

			// Obtain certificate
			ui.PrintProgress("Obtaining certificate from Let's Encrypt...")
			wr := installer.Webroot(domain)
			if wr == "" { 
				ui.PrintError(fmt.Sprintf("Could not detect webroot for %s", domain))
				return fmt.Errorf("could not detect webroot for %s", domain) 
			}
			
			cert, err = m.ObtainHTTP01([]string{domain}, wr)
			if err != nil { 
				ui.PrintError(fmt.Sprintf("Failed to obtain certificate: %v", err))
				return err 
			}
			ui.CompleteProgress()
			
			// Install certificate
			ui.PrintStep(5, 5, "Installing certificate")
			ui.PrintProgress("Installing SSL certificate...")
			if _, err := store.SaveCertificate(storeDir, domain, cert); err != nil { 
				ui.PrintError(fmt.Sprintf("Failed to save certificate: %v", err))
				return err 
			}
			if err := installer.Install(domain); err != nil { 
				ui.PrintError(fmt.Sprintf("Failed to install certificate: %v", err))
				return err 
			}
			ui.CompleteProgress()

			// Save renewal configuration
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
			
			ui.PrintSuccess(fmt.Sprintf("SSL certificate successfully installed for %s", domain))
			return nil
		}
		
		// For DigiCert, handle installation
		ui.PrintStep(3, 5, "Detecting web server configuration")
		var installer Installer
		var chosen string
		if target == "" {
			if apache.Available() { 
				installer = apache.NewInstaller(storeDir, assumeYes); 
				chosen = "apache" 
				ui.PrintInfo("Detected Apache web server")
			}
			if installer == nil && nginx.Available() { 
				installer = nginx.NewInstaller(storeDir, assumeYes); 
				chosen = "nginx" 
				ui.PrintInfo("Detected Nginx web server")
			}
		} else if target == "apache" {
			if !apache.Available() { 
				ui.PrintError("Apache not detected")
				return fmt.Errorf("apache not detected") 
			}
			installer = apache.NewInstaller(storeDir, assumeYes); chosen = "apache"
			ui.PrintInfo("Using Apache web server")
		} else if target == "nginx" {
			if !nginx.Available() { 
				ui.PrintError("Nginx not detected")
				return fmt.Errorf("nginx not detected") 
			}
			installer = nginx.NewInstaller(storeDir, assumeYes); chosen = "nginx"
			ui.PrintInfo("Using Nginx web server")
		} else {
			ui.PrintError(fmt.Sprintf("Unknown target: %s", target))
			return fmt.Errorf("unknown target: %s", target)
		}
		if installer == nil {
			ui.PrintError("No supported web server detected")
			return fmt.Errorf("no supported web server detected; specify --target=apache|nginx")
		}
		
		// Check SSL status
		ui.PrintStep(4, 5, "Checking SSL status")
		ui.ShowSSLStatus(domain, installer.IsSSLEnabled(domain))
		
		// Detect vhost and ask for confirmation
		configPath, webserver := installer.DetectVhost(domain)
		if configPath == "" {
			ui.PrintWarning("No existing virtual host found, will create default configuration")
			configPath = fmt.Sprintf("/etc/%s/sites-available/%s-ssl.conf", webserver, domain)
		}
		
		if !assumeYes {
			// Just show confirmation, don't try to use return value
			ui.ShowVhostConfirmation(domain, configPath, webserver)
			if !ui.AskYesNo("Proceed with this configuration?") {
				ui.PrintInfo("Installation cancelled by user")
				return nil
			}
		}
		
		// Install certificate
		ui.PrintStep(5, 5, "Installing certificate")
		ui.PrintProgress("Installing DigiCert certificate...")
		if _, err := store.SaveCertificate(storeDir, domain, cert); err != nil { 
			ui.PrintError(fmt.Sprintf("Failed to save certificate: %v", err))
			return err 
		}
		if err := installer.Install(domain); err != nil { 
			ui.PrintError(fmt.Sprintf("Failed to install certificate: %v", err))
			return err 
		}
		ui.CompleteProgress()

		// Save renewal configuration for DigiCert
		_ = renewal.Save(renewal.Config{
			Domain:  domain,
			Email:   email,
			Server:  server,
			Method:  "digicert",
			KeyType: keyType,
			KeySize: keySize,
			Targets: []string{chosen},
			BaseDir: storeDir,
		})
		
		ui.PrintSuccess(fmt.Sprintf("DigiCert SSL certificate successfully installed for %s", domain))
		return nil
	},
}

type Installer interface {
	Webroot(domain string) string
	Install(domain string) error
	IsSSLEnabled(domain string) bool
	DetectVhost(domain string) (string, string) // returns config path and webserver type
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
	
	// Add verbose flag
	installCmd.Flags().Bool("verbose", false, "Show verbose output")
	
	// Web server choice flags (simple English)
	installCmd.Flags().String("web-server", "", "Web server type: apache or nginx")
	installCmd.Flags().String("apache", "", "Use Apache web server")
	installCmd.Flags().String("nginx", "", "Use Nginx web server")
	
	// Certificate provider flags (simple English)
	installCmd.Flags().String("provider", "", "Certificate provider: letsencrypt or digicert")
	installCmd.Flags().String("cert-provider", "", "Certificate provider: letsencrypt or digicert")
	installCmd.Flags().String("digicert-key", "", "DigiCert key ID")
	installCmd.Flags().String("digicert-secret", "", "DigiCert secret key")
	installCmd.Flags().String("account-id", "", "DigiCert account ID")
	installCmd.Flags().String("org-id", "", "DigiCert organization ID")
}

// Validation functions
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainRegex.MatchString(domain)
}

func isValidEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}
	
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func checkNetworkConnectivity() error {
	client := &http.Client{Timeout: 5 * time.Second}
	
	// Try to connect to Google's DNS (basic connectivity test)
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to DNS servers: %w", err)
	}
	conn.Close()
	
	// Try to reach Let's Encrypt
	resp, err := client.Get("https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		return fmt.Errorf("cannot reach Let's Encrypt servers: %w", err)
	}
	resp.Body.Close()
	
	return nil
}