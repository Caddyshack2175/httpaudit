package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"httpaudit/pkg/fuzzer"
	httplib "httpaudit/pkg/http"
)

var staggerCmd = &cobra.Command{
	Use:   "stagger",
	Short: "HTTP fuzzing with batched requests and cooldown periods",
	Long: `Send HTTP requests with placeholder replacement in controlled batches.
Supports file-based wordlists and numeric ranges with optional zero-padding.
Includes batch-size and cool-down controls to avoid rate limiting.`,
	Example: `  # Stagger requests in batches of 50 with 10-minute cooldowns
  httpaudit stagger --request template.txt --USER users.txt -B 50 -C 10m

  # Stagger with multiple placeholders
  httpaudit stagger --request template.txt --ID 1-1000 -B 100 -C 5m --threads 10

  # Quick batches with short cooldown
  httpaudit stagger --request template.txt --DOCID 0001-9999 -B 25 -C 30s`,
	RunE: runStagger,
	// Disable flag parsing to allow unknown flags (placeholders)
	DisableFlagParsing: true,
}

func init() {
	rootCmd.AddCommand(staggerCmd)

	// Stagger specific flags
	staggerCmd.Flags().StringP("request", "r", "", "HTTP request template file (required)")
	staggerCmd.Flags().IntP("batch-size", "B", 50, "Number of requests per batch")
	staggerCmd.Flags().StringP("cool-down", "C", "10m", "Cooldown period between batches (e.g., 10m, 30s, 1h)")
	staggerCmd.Flags().IntP("threads", "j", 1, "Number of concurrent threads per batch")
	staggerCmd.Flags().IntP("delay", "d", 0, "Delay between requests per thread (ms)")
	staggerCmd.Flags().BoolP("https", "s", true, "Use HTTPS")
	staggerCmd.Flags().StringP("output", "o", "", "Save results to file")
	staggerCmd.Flags().StringP("filter-status", "f", "", "Show only specific status codes (e.g., 200,401)")
	staggerCmd.Flags().StringP("match", "m", "", "Show only responses containing string")
	staggerCmd.Flags().StringP("negative-match", "n", "", "Hide responses containing string")
	staggerCmd.Flags().BoolP("body-only", "b", false, "Show only response bodies")
	staggerCmd.Flags().BoolP("progress", "P", true, "Show progress bar")

	// Mark required flags
	staggerCmd.MarkFlagRequired("request")
}

func runStagger(cmd *cobra.Command, args []string) error {
	// Since we disabled flag parsing, we need to parse flags manually
	requestFile := ""
	batchSize := 50
	coolDown := "10m"
	threads := 1
	delay := 0
	https := true
	outputFile := ""
	filterStatus := ""
	matchString := ""
	negativeMatch := ""
	bodyOnly := false
	progress := true
	proxyURL := ""
	timeout := 30
	verbose := false
	quiet := false
	placeholderFiles := make(map[string]string)

	// Manual flag parsing
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			continue
		}

		// Handle both --flag and -f formats
		flagName := strings.TrimLeftFunc(arg, func(r rune) bool { return r == '-' })

		switch flagName {
		case "request", "r":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				requestFile = args[i+1]
				i++
			}
		case "batch-size", "B":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &batchSize)
				i++
			}
		case "cool-down", "C":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				coolDown = args[i+1]
				i++
			}
		case "threads", "j":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &threads)
				i++
			}
		case "delay", "d":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &delay)
				i++
			}
		case "https", "s":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if args[i+1] == "false" || args[i+1] == "0" {
					https = false
				}
				i++
			}
		case "output", "o":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				outputFile = args[i+1]
				i++
			}
		case "filter-status", "f":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				filterStatus = args[i+1]
				i++
			}
		case "match", "m":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				matchString = args[i+1]
				i++
			}
		case "negative-match", "n":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				negativeMatch = args[i+1]
				i++
			}
		case "body-only", "b":
			bodyOnly = true
		case "progress", "P":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if args[i+1] == "false" || args[i+1] == "0" {
					progress = false
				}
				i++
			}
		case "proxy", "p":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				proxyURL = args[i+1]
				i++
			}
		case "timeout", "t":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				fmt.Sscanf(args[i+1], "%d", &timeout)
				i++
			}
		case "verbose", "v":
			verbose = true
		case "quiet", "q":
			quiet = true
		case "help", "h":
			cmd.Help()
			return nil
		default:
			// Check if it's a placeholder flag (uppercase)
			if len(flagName) > 0 && strings.ToUpper(flagName) == flagName {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					placeholderFiles[flagName] = args[i+1]
					i++
				} else {
					return fmt.Errorf("placeholder flag --%s requires a value", flagName)
				}
			} else {
				return fmt.Errorf("unknown flag: --%s", flagName)
			}
		}
	}

	// Parse cooldown duration
	coolDownDuration, err := time.ParseDuration(coolDown)
	if err != nil {
		return fmt.Errorf("invalid cool-down duration: %v (use format like 10m, 30s, 1h)", err)
	}

	// Read request template
	templateData, err := os.ReadFile(requestFile)
	if err != nil {
		return fmt.Errorf("error reading request template: %v", err)
	}
	template := string(templateData)

	// Find all placeholders
	placeholders := fuzzer.FindPlaceholders(template)
	if len(placeholders) == 0 {
		return fmt.Errorf("no placeholders found in template (use {PLACEHOLDER} format)")
	}

	if !bodyOnly && !quiet {
		fmt.Printf("[*] Found placeholders: %v\n", placeholders)
		fmt.Printf("[*] Batch size: %d requests\n", batchSize)
		fmt.Printf("[*] Cooldown period: %v\n", coolDownDuration)

		if proxyURL != "" {
			fmt.Printf("[*] Using proxy: %s\n", proxyURL)
		}
		if matchString != "" {
			fmt.Printf("[*] Showing only responses containing: %s\n", matchString)
		}
		if negativeMatch != "" {
			fmt.Printf("[*] Hiding responses containing: %s\n", negativeMatch)
		}
	}

	// Load values for each placeholder
	valueMap := make(map[string][]string)
	for _, placeholder := range placeholders {
		fileOrRange, found := placeholderFiles[placeholder]
		if !found {
			return fmt.Errorf("no file or range specified for placeholder {%s}\nUse: --%s <filename> or --%s <start-end>",
				placeholder, placeholder, placeholder)
		}

		// Check if it's a numeric range
		if strings.Contains(fileOrRange, "-") {
			parts := strings.Split(fileOrRange, "-")
			if len(parts) == 2 {
				// Try to parse as numeric range
				values, err := fuzzer.GenerateNumericRange(fileOrRange)
				if err == nil {
					valueMap[placeholder] = values
					if !bodyOnly && !quiet {
						fmt.Printf("[*] Generated %d numeric values for {%s} from range %s\n",
							len(values), placeholder, fileOrRange)
					}
					continue
				}
			}
		}

		// Otherwise, treat as file
		values, err := fuzzer.LoadLinesFromFile(fileOrRange)
		if err != nil {
			return fmt.Errorf("error loading %s from %s: %v\nIf you meant to use a numeric range, use format: start-end (e.g., 1-100)",
				placeholder, fileOrRange, err)
		}
		valueMap[placeholder] = values
		if !bodyOnly && !quiet {
			fmt.Printf("[*] Loaded %d values for {%s} from %s\n",
				len(values), placeholder, fileOrRange)
		}
	}

	// Generate all combinations
	combinations := fuzzer.GenerateCombinations(placeholders, valueMap)
	totalJobs := len(combinations)

	if !bodyOnly && !quiet {
		fmt.Printf("[*] Generated %d request combinations\n", totalJobs)
		fmt.Printf("[*] Using %d concurrent threads per batch\n\n", threads)
	}

	// Parse filter status codes
	var filterStatuses []string
	if filterStatus != "" {
		filterStatuses = strings.Split(filterStatus, ",")
	}

	// Setup output (tee to both stdout and file if specified)
	var output io.Writer = os.Stdout
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error creating output file: %v", err)
		}
		defer file.Close()
		// Use io.MultiWriter to write to both stdout and file (like tee)
		output = io.MultiWriter(os.Stdout, file)
	}

	// Create HTTP client
	clientConfig := httplib.ClientConfig{
		ProxyURL:           proxyURL,
		Timeout:            timeout,
		InsecureSkipVerify: true,
		FollowRedirects:    false,
	}

	client, err := httplib.NewClient(clientConfig)
	if err != nil {
		return fmt.Errorf("error creating HTTP client: %v", err)
	}

	// Parse request template
	requestTemplate, err := parseRawRequestForFuzzer(template)
	if err != nil {
		return fmt.Errorf("error parsing request template: %v", err)
	}

	// Update scheme based on https flag
	if https {
		requestTemplate.URL = strings.Replace(requestTemplate.URL, "http://", "https://", 1)
	} else {
		requestTemplate.URL = strings.Replace(requestTemplate.URL, "https://", "http://", 1)
	}

	// Statistics tracking
	goodCount := 0
	badCount := 0
	networkFailures := 0
	processedCount := 0
	startTime := time.Now()

	if !bodyOnly && !quiet {
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println("STARTING BATCHES")
		fmt.Println(strings.Repeat("=", 80))
	}

	// Process in batches
	for i := 0; i < totalJobs; i += batchSize {
		// Get batch of items
		end := i + batchSize
		if end > totalJobs {
			end = totalJobs
		}

		batch := combinations[i:end]
		batchNum := i/batchSize + 1
		totalBatches := (totalJobs + batchSize - 1) / batchSize

		if !bodyOnly && !quiet {
			fmt.Printf("\n%s\n", strings.Repeat("-", 80))
			fmt.Printf("Processing batch %d/%d (requests %d-%d)\n", batchNum, totalBatches, i+1, end)
			fmt.Printf("%s\n", strings.Repeat("-", 80))
		}

		// Create channels and workers for this batch
		jobs := make(chan map[string]string, len(batch))
		results := make(chan *httplib.RequestResult, len(batch))

		var wg sync.WaitGroup
		var batchCompletedCount int64

		// Start workers for this batch
		for w := 1; w <= threads; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()

				for combo := range jobs {
					result := httplib.MakeRequest(requestTemplate, client, combo)
					result.Replacements = combo
					results <- result

					atomic.AddInt64(&batchCompletedCount, 1)

					// Add delay if specified
					if delay > 0 {
						time.Sleep(time.Duration(delay) * time.Millisecond)
					}
				}
			}(w)
		}

		// Send jobs for this batch
		go func() {
			for _, combo := range batch {
				jobs <- combo
			}
			close(jobs)
		}()

		// Close results channel when all workers are done
		go func() {
			wg.Wait()
			close(results)
		}()

		// Process results for this batch
		batchProcessedCount := 0
		for result := range results {
			processedCount++
			batchProcessedCount++

			// Progress bar for batch
			if progress && !bodyOnly && !quiet && batchProcessedCount%5 == 0 {
				fmt.Fprintf(os.Stderr, "\r[*] Batch progress: %d/%d (%.1f%%) ",
					batchProcessedCount, len(batch), float64(batchProcessedCount)/float64(len(batch))*100)
			}

			// Apply filters
			shouldDisplay := true

			if len(filterStatuses) > 0 {
				shouldDisplay = false
				statusStr := fmt.Sprintf("%d", result.StatusCode)
				for _, filter := range filterStatuses {
					if strings.TrimSpace(filter) == statusStr {
						shouldDisplay = true
						break
					}
				}
			}

			if matchString != "" && !strings.Contains(result.ResponseBody, matchString) {
				shouldDisplay = false
			}

			if negativeMatch != "" && strings.Contains(result.ResponseBody, negativeMatch) {
				shouldDisplay = false
			}

			// Classify result for statistics
			if result.HasNetworkError() {
				networkFailures++
			} else if result.IsSuccessful() {
				goodCount++
			} else {
				badCount++
			}

			// Display result
			if shouldDisplay {
				if bodyOnly {
					if result.HasNetworkError() {
						fmt.Fprintf(output, "NETWORK ERROR: %v\n", result.NetworkError)
					} else {
						fmt.Fprintf(output, "%s\n", result.ResponseBody)
					}
				} else {
					// Show full result
					fmt.Fprintf(output, "\n[Request #%d]\n", processedCount)
					for k, v := range result.Replacements {
						fmt.Fprintf(output, "  {%s} = %s\n", k, v)
					}

					if result.HasNetworkError() {
						fmt.Fprintf(output, "  Status: NETWORK ERROR - %v\n", result.NetworkError)
					} else {
						fmt.Fprintf(output, "  Status: %d (%s)\n", result.StatusCode, result.GetStatusCategory())
						fmt.Fprintf(output, "  Size: %d bytes\n", result.ResponseSize)
						fmt.Fprintf(output, "  Time: %v\n", result.ResponseTime)

						// Show response headers if verbose
						if verbose && len(result.ResponseHeaders) > 0 {
							fmt.Fprintf(output, "  Headers:\n")
							for key, values := range result.ResponseHeaders {
								for _, value := range values {
									fmt.Fprintf(output, "    %s: %s\n", key, value)
								}
							}
						}

						// Show response body
						fmt.Fprintf(output, "  Response Body:\n")
						if verbose {
							fmt.Fprintf(output, "%s\n", result.ResponseBody)
						} else {
							preview := result.ResponseBody
							if len(preview) > 500 {
								preview = preview[:500] + "..."
							}
							fmt.Fprintf(output, "%s\n", preview)
						}
					}
					fmt.Fprintf(output, "%s\n", strings.Repeat("-", 80))
				}
			}
		}

		if progress && !bodyOnly && !quiet {
			fmt.Fprintf(os.Stderr, "\r[*] Batch progress: %d/%d (100.0%%) \n", len(batch), len(batch))
		}

		// Wait for cooldown if there are more batches
		if end < totalJobs {
			if !bodyOnly && !quiet {
				fmt.Printf("\n%s\n", strings.Repeat("-", 80))
				fmt.Printf("Waiting %v before next batch...\n", coolDownDuration)
				fmt.Printf("%s\n", strings.Repeat("-", 80))
			}
			time.Sleep(coolDownDuration)
		}
	}

	// Summary
	if !bodyOnly && !quiet {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Printf("SUMMARY\n")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("Total Requests:     %d\n", totalJobs)
		fmt.Printf("Good (2xx):         %d\n", goodCount)
		fmt.Printf("Bad (non-2xx):      %d\n", badCount)
		fmt.Printf("Network Failures:   %d\n", networkFailures)
		fmt.Printf("Duration:           %v\n", time.Since(startTime))
		fmt.Printf("Batch Size:         %d\n", batchSize)
		fmt.Printf("Cooldown:           %v\n", coolDownDuration)

		if outputFile != "" {
			fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
		}
	}

	return nil
}
