package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"httpaudit/pkg/fuzzer"
	httplib "httpaudit/pkg/http"
)

var fuzzerCmd = &cobra.Command{
	Use:   "fuzzer",
	Short: "HTTP fuzzing tool with placeholder support",
	Long: `Send HTTP requests with placeholder replacement for fuzzing endpoints.
Supports file-based wordlists and numeric ranges with optional zero-padding.`,
	Example: `  # Hammer endpoints with numeric ranges
  httpaudit fuzzer --request template.txt --USER users.txt --ID 1-1000 --threads 10

  # Strike with zero-padded numbers
  httpaudit fuzzer --request template.txt --DOCID 0001-9999 --threads 20

  # Fast hammering with filtering
  httpaudit fuzzer --request template.txt --ID 1-10000 --threads 50 --filter-status 200

  # Precision strikes (hide errors)
  httpaudit fuzzer --request template.txt --ID 1-100 --negative-match "404 Not Found"`,
	RunE: runFuzzer,
	// Disable flag parsing to allow unknown flags (placeholders)
	DisableFlagParsing: true,
}

func init() {
	rootCmd.AddCommand(fuzzerCmd)

	// Fuzzer specific flags
	fuzzerCmd.Flags().StringP("request", "r", "", "HTTP request template file (required)")
	fuzzerCmd.Flags().IntP("threads", "j", 1, "Number of concurrent threads")
	fuzzerCmd.Flags().IntP("delay", "d", 0, "Delay between requests per thread (ms)")
	fuzzerCmd.Flags().BoolP("https", "s", true, "Use HTTPS")
	fuzzerCmd.Flags().StringP("output", "o", "", "Save results to file")
	fuzzerCmd.Flags().StringP("filter-status", "f", "", "Show only specific status codes (e.g., 200,401)")
	fuzzerCmd.Flags().StringP("match", "m", "", "Show only responses containing string")
	fuzzerCmd.Flags().StringP("negative-match", "n", "", "Hide responses containing string")
	fuzzerCmd.Flags().BoolP("body-only", "b", false, "Show only response bodies")
	fuzzerCmd.Flags().BoolP("progress", "P", true, "Show progress bar")
	fuzzerCmd.Flags().StringP("rate-limit", "l", "", "Rate limiting: total,concurrent (e.g., 150,10)")

	// Mark required flags
	fuzzerCmd.MarkFlagRequired("request")
}

func runFuzzer(cmd *cobra.Command, args []string) error {
	// Since we disabled flag parsing, we need to parse flags manually
	requestFile := ""
	threads := 1
	delay := 0
	https := true
	outputFile := ""
	filterStatus := ""
	matchString := ""
	negativeMatch := ""
	bodyOnly := false
	progress := true
	rateLimitFlag := ""
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
			// No value consumed
		case "progress", "P":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if args[i+1] == "false" || args[i+1] == "0" {
					progress = false
				}
				i++
			}
		case "rate-limit", "l":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				rateLimitFlag = args[i+1]
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
			// No value consumed
		case "quiet", "q":
			quiet = true
			// No value consumed
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

	// Parse rate limiting parameters
	var maxRequests int
	var maxConcurrent int
	var rateLimitChan chan struct{}
	var completedCount int64

	if rateLimitFlag != "" {
		parts := strings.Split(rateLimitFlag, ",")
		if len(parts) != 2 {
			return fmt.Errorf("invalid rate-limit format. Use: total,concurrent (e.g., 150,10)")
		}

		var err error
		maxRequests, err = strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid total requests in rate-limit: %v", err)
		}

		maxConcurrent, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("invalid concurrent limit in rate-limit: %v", err)
		}

		// Limit total jobs to maxRequests if rate limiting is enabled
		if totalJobs > maxRequests {
			totalJobs = maxRequests
			combinations = combinations[:maxRequests]
		}

		// Create rate limiting channel
		rateLimitChan = make(chan struct{}, maxConcurrent)

		if !bodyOnly && !quiet {
			fmt.Printf("[*] Rate limiting enabled: %d total requests, %d max concurrent\n",
				maxRequests, maxConcurrent)
		}
	}

	if !bodyOnly && !quiet {
		fmt.Printf("[*] Generated %d request combinations\n", totalJobs)
		if rateLimitFlag == "" {
			fmt.Printf("[*] Using %d concurrent threads\n\n", threads)
		} else {
			fmt.Printf("[*] Using rate limiting instead of thread control\n\n")
		}
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

	// Create channels and workers
	jobs := make(chan map[string]string, totalJobs)
	results := make(chan *httplib.RequestResult, totalJobs)

	var wg sync.WaitGroup
	workerCount := threads
	if rateLimitFlag != "" {
		workerCount = maxConcurrent * 2
		if workerCount > totalJobs {
			workerCount = totalJobs
		}
	}

	// Start workers
	for i := 1; i <= workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for combo := range jobs {
				// Acquire rate limit semaphore if enabled
				if rateLimitChan != nil {
					rateLimitChan <- struct{}{}
				}

				result := httplib.MakeRequest(requestTemplate, client, combo)
				result.Replacements = combo
				results <- result

				atomic.AddInt64(&completedCount, 1)

				// Release rate limit semaphore
				if rateLimitChan != nil {
					<-rateLimitChan
				}

				// Add delay if specified
				if delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
			}
		}(i)
	}

	// Send jobs
	go func() {
		for _, combo := range combinations {
			jobs <- combo
		}
		close(jobs)
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	if !bodyOnly && !quiet {
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println("FUZZING RESULTS")
		fmt.Println(strings.Repeat("=", 80))
	}

	goodCount := 0
	badCount := 0
	networkFailures := 0
	processedCount := 0
	startTime := time.Now()

	for result := range results {
		processedCount++

		// Progress bar
		if progress && !bodyOnly && !quiet && processedCount%10 == 0 {
			if rateLimitFlag != "" {
				fmt.Fprintf(os.Stderr, "\r[*] Progress: %d/%d (%.1f%%) - Completed: %d ",
					processedCount, totalJobs, float64(processedCount)/float64(totalJobs)*100,
					atomic.LoadInt64(&completedCount))
			} else {
				fmt.Fprintf(os.Stderr, "\r[*] Progress: %d/%d (%.1f%%) ",
					processedCount, totalJobs, float64(processedCount)/float64(totalJobs)*100)
			}
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
		fmt.Fprintf(os.Stderr, "\r[*] Progress: %d/%d (100.0%%) \n\n", totalJobs, totalJobs)
	}

	// Summary
	if !bodyOnly && !quiet {
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("SUMMARY\n")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("Total Requests:     %d\n", totalJobs)
		fmt.Printf("Good (2xx):         %d\n", goodCount)
		fmt.Printf("Bad (non-2xx):      %d\n", badCount)
		fmt.Printf("Network Failures:   %d\n", networkFailures)

		if rateLimitFlag != "" {
			duration := time.Since(startTime)
			fmt.Printf("Duration:           %v\n", duration)
			fmt.Printf("Requests/sec:       %.2f\n", float64(totalJobs)/duration.Seconds())
			fmt.Printf("Rate Limit:         %d total, %d concurrent\n", maxRequests, maxConcurrent)
		}

		if outputFile != "" {
			fmt.Printf("\n[*] Results saved to: %s\n", outputFile)
		}
	}

	return nil
}

// parseRawRequestForFuzzer parses a raw HTTP request for fuzzing
func parseRawRequestForFuzzer(raw string) (*httplib.RequestTemplate, error) {
	template := &httplib.RequestTemplate{
		Headers: make(map[string]string),
	}

	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}

	// Parse request line
	parts := strings.Split(strings.TrimSpace(lines[0]), " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line")
	}

	template.Method = parts[0]
	path := parts[1]

	var host string
	bodyStartIndex := len(lines)

	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			bodyStartIndex = i + 1
			break
		}

		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			key := strings.TrimSpace(headerParts[0])
			value := strings.TrimSpace(headerParts[1])
			template.Headers[key] = value

			if strings.ToLower(key) == "host" {
				host = value
			}
		}
	}

	// Construct URL
	if host == "" {
		return nil, fmt.Errorf("no Host header found")
	}
	template.URL = fmt.Sprintf("https://%s%s", host, path)

	// Parse body
	if bodyStartIndex < len(lines) {
		bodyLines := lines[bodyStartIndex:]
		template.Body = strings.Join(bodyLines, "\n")
	}

	return template, nil
}