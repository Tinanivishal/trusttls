package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "trusttls",
	Short: "TrustTLS - Easy SSL Certificate Management",
	Long: `
╔══════════════════════════════════════════════════════════════╗
║                    🔒 TrustTLS v1.0                          ║
║              Easy SSL Certificate Management                  ║
║                                                              ║
║  🌟 Free SSL certificates with Let's Encrypt                 ║
║  🏢 Commercial certificates with DigiCert                    ║
║  🚀 Automatic installation and renewal                       ║
║  🎯 One-command SSL setup for Apache & Nginx                 ║
╚══════════════════════════════════════════════════════════════╝

TrustTLS makes SSL certificate management simple and automated.
Supports Let's Encrypt (free) and DigiCert (commercial) providers.
`,
}

func Execute() {
	if len(os.Args) > 1 && os.Args[1] != "--help" && os.Args[1] != "-h" {
		fmt.Println(`
╔══════════════════════════════════════════════════════════════╗
║                    🔒 TrustTLS v1.0                          ║
║              Easy SSL Certificate Management                  ║
╚══════════════════════════════════════════════════════════════╝`)
		fmt.Println()
	}
	
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
