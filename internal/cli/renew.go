package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trustctl/trusttls/internal/renewal"
)

var renewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew SSL certificates that are about to expire",
	Long: `
Check and renew SSL certificates that are due for renewal.

This command:
• Checks all your installed certificates
• Renews certificates expiring within 30 days
• Automatically installs renewed certificates
• Updates your web server configuration

Perfect for automated maintenance and cron jobs!

Example:
  trusttls renew                    # Renew all due certificates
  trusttls renew --verbose          # Show detailed progress

Set up automatic renewal:
  Add to crontab: 0 2 * * * /usr/local/bin/trusttls renew
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if err := renewal.RunAll(verbose); err != nil {
			return err
		}
		fmt.Println("🎉 SSL certificate renewal completed!")
		fmt.Println("💡 All certificates have been checked and renewed if needed.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(renewCmd)
	renewCmd.Flags().Bool("verbose", false, "Verbose output")
}
