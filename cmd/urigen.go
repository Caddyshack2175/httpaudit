package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var uriGenCmd = &cobra.Command{
	Use:   "uri-gen",
	Short: "Generate URIs from directory structure for artifact discovery",
	Long: `Scan a directory structure and generate corresponding URIs for web testing.
Perfect for discovering exposed development artifacts, config files, and leftover code.`,
	Example: `  # Discover artifacts and generate strike targets
  httpaudit uri-gen --directory /var/www/html --base-url https://example.com

  # Build target list for hammering
  httpaudit uri-gen --directory ./app --base-url https://target.com --output uris.txt

  # Generate and immediately test discovered URIs
  httpaudit uri-gen -d ./project -u https://site.com > targets.txt`,
	RunE: runURIGen,
}

func init() {
	rootCmd.AddCommand(uriGenCmd)

	// URI generator specific flags
	uriGenCmd.Flags().StringP("directory", "d", "", "Directory to scan (required)")
	uriGenCmd.Flags().StringP("base-url", "u", "", "Base URL for generated URIs (required)")
	uriGenCmd.Flags().StringP("output", "o", "", "Save URIs to file (default: stdout)")

	// Mark required flags
	uriGenCmd.MarkFlagRequired("directory")
	uriGenCmd.MarkFlagRequired("base-url")
}

func runURIGen(cmd *cobra.Command, args []string) error {
	// Get flags
	directory, _ := cmd.Flags().GetString("directory")
	baseURL, _ := cmd.Flags().GetString("base-url")
	outputFile, _ := cmd.Flags().GetString("output")

	// Get global flags
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Setup output
	var output *os.File = os.Stdout
	if outputFile != "" {
		var err error
		output, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error creating output file: %v", err)
		}
		defer output.Close()
		if !quiet {
			fmt.Printf("Output will be saved to: %s\n", outputFile)
		}
	}

	// Validate directory exists
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", directory)
	}

	if !quiet {
		fmt.Printf("Scanning directory: %s\n", directory)
		fmt.Printf("Base URL: %s\n", baseURL)
	}

	// Generate URIs
	uris, err := ScanDirectoryForURIs(directory, baseURL)
	if err != nil {
		return fmt.Errorf("error scanning directory: %v", err)
	}

	// Output results
	for _, uri := range uris {
		fmt.Fprintln(output, uri)
	}

	if !quiet {
		fmt.Printf("\nGenerated %d URIs\n", len(uris))
		if outputFile != "" {
			fmt.Printf("Results saved to: %s\n", outputFile)
		}
	}

	return nil
}

// ScanDirectoryForURIs scans a directory and generates URIs for all files
func ScanDirectoryForURIs(rootDir, baseURL string) ([]string, error) {
	var uris []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(rootDir, path)
			if err != nil {
				return err
			}

			// Convert file path to web path (forward slashes)
			webPath := filepath.ToSlash(relPath)

			// URL encode the path components
			pathParts := strings.Split(webPath, "/")
			for i, part := range pathParts {
				pathParts[i] = url.PathEscape(part)
			}
			encodedPath := strings.Join(pathParts, "/")

			// Construct full URI
			fullURI := strings.TrimSuffix(baseURL, "/") + "/" + encodedPath
			uris = append(uris, fullURI)
		}

		return nil
	})

	return uris, err
}