package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "httpaudit",
	Short: "HTTP testing and fuzzing toolkit",
	Long: `
	╦ ╦╔╦╗╔╦╗╔═╗╔═╗╦ ╦╔╦╗╦╔╦╗
	╠═╣ ║  ║ ╠═╝╠═╣║ ║ ║║║ ║ 
	╩ ╩ ╩  ╩ ╩  ╩ ╩╚═╝═╩╝╩ ╩ 

** For use against systems you own or have written authorisation to test. **

HTTPAudit - A powerful HTTP testing toolkit for security professionals:

• YAML template-based security testing
• HTTP fuzzing with placeholder support
• Clickjacking vulnerability detection
• Rate limiting bypass testing
• Proxy integration for Burp/ZAP
• Concurrent request handling
• Professional JSON reporting`,
	Version: "1.1.0",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add global flags if needed
	rootCmd.PersistentFlags().StringP("proxy", "p", "", "Proxy URL (http://host:port)")
	rootCmd.PersistentFlags().IntP("timeout", "t", 30, "Request timeout in seconds")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Quiet mode (suppress progress)")
}

// Helper function for consistent error handling
func checkErr(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
