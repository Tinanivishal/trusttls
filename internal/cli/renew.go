package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trustctl/trusttls/internal/renewal"
)

var renewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew certificates due for renewal",
	RunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if err := renewal.RunAll(verbose); err != nil {
			return err
		}
		fmt.Println("Renewal complete")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(renewCmd)
	renewCmd.Flags().Bool("verbose", false, "Verbose output")
}
