package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	httplib "httpaudit/pkg/http"
)

var rateLimiterCmd = &cobra.Command{
	Use:   "rate-limiter",
	Short: "Test API rate limiting with controlled concurrent requests",
	Long: `Send multiple HTTP requests with rate limiting and concurrency control.
Perfect for testing API rate limits and authentication bypass attempts.`,
	Example: `  # Test an API with rate limiting tests
  httpaudit rate-limiter --request req.txt --total 150 --concurrent 10

  # Test through Burp Suite proxy
  httpaudit rate-limiter --request req.txt --total 100 --concurrent 5 --proxy http://127.0.0.1:8080

  # Controlled testing with delay
  httpaudit rate-limiter --request req.txt --total 50 --concurrent 3 --timeout 10 --delay 100`,
	RunE: runRateLimiter,
}

func init() {
	rootCmd.AddCommand(rateLimiterCmd)

	// Rate limiter specific flags
	rateLimiterCmd.Flags().StringP("request", "r", "", "HTTP request template file (required)")
	rateLimiterCmd.Flags().IntP("total", "n", 0, "Total number of requests to send (required)")
	rateLimiterCmd.Flags().IntP("concurrent", "c", 0, "Maximum concurrent requests (required)")
	rateLimiterCmd.Flags().IntP("delay", "d", 0, "Delay between requests in milliseconds")
	rateLimiterCmd.Flags().StringP("output", "o", "", "Save results to file (default: stdout)")

	// Mark required flags
	rateLimiterCmd.MarkFlagRequired("request")
	rateLimiterCmd.MarkFlagRequired("total")
	rateLimiterCmd.MarkFlagRequired("concurrent")
}

func runRateLimiter(cmd *cobra.Command, args []string) error {
	// Get flags
	requestFile, _ := cmd.Flags().GetString("request")
	totalRequests, _ := cmd.Flags().GetInt("total")
	maxConcurrent, _ := cmd.Flags().GetInt("concurrent")
	delay, _ := cmd.Flags().GetInt("delay")
	outputFile, _ := cmd.Flags().GetString("output")

	// Get global flags
	proxyURL, _ := cmd.Flags().GetString("proxy")
	timeout, _ := cmd.Flags().GetInt("timeout")
	verbose, _ := cmd.Flags().GetBool("verbose")
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Validate parameters
	if totalRequests <= 0 {
		return fmt.Errorf("total requests must be > 0, got: %d", totalRequests)
	}
	if maxConcurrent <= 0 {
		return fmt.Errorf("max concurrent must be > 0, got: %d", maxConcurrent)
	}
	if maxConcurrent > totalRequests {
		if !quiet {
			fmt.Printf("Warning: Max concurrent (%d) > total requests (%d), adjusting to %d\n",
				maxConcurrent, totalRequests, totalRequests)
		}
		maxConcurrent = totalRequests
	}

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

	// Parse request template
	if !quiet {
		fmt.Printf("Loading request template from: %s\n", requestFile)
	}
	template, err := httplib.ParseRequestFromFile(requestFile)
	if err != nil {
		return fmt.Errorf("error parsing request file: %v", err)
	}

	if !quiet {
		fmt.Printf("Parsed request: %s %s\n", template.Method, template.URL)
		fmt.Printf("Headers: %d\n", len(template.Headers))
		if template.Body != "" {
			fmt.Printf("Body length: %d bytes\n", len(template.Body))
		}
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

	if !quiet && proxyURL != "" {
		fmt.Printf("Using proxy: %s\n", proxyURL)
	}

	// Setup concurrency control
	resultChan := make(chan *httplib.RequestResult, totalRequests)
	rateLimitChan := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	var completedCount int64

	if !quiet {
		fmt.Printf("Starting %d requests with max %d concurrent\n", totalRequests, maxConcurrent)
		if delay > 0 {
			fmt.Printf("Delay between requests: %dms\n", delay)
		}
		if timeout != 30 {
			fmt.Printf("Request timeout: %ds\n", timeout)
		}
	}

	startTime := time.Now()

	// Launch workers
	for i := 1; i <= totalRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()

			// Acquire rate limit semaphore
			rateLimitChan <- struct{}{}
			defer func() { <-rateLimitChan }()

			// Make request
			result := httplib.MakeRequest(template, client, nil)
			result.RequestNum = requestNum
			resultChan <- result

			atomic.AddInt64(&completedCount, 1)

			// Progress indicator
			if !quiet && requestNum%10 == 0 {
				fmt.Printf("Progress: %d/%d requests completed\n",
					atomic.LoadInt64(&completedCount), totalRequests)
			}

			// Add delay if specified
			if delay > 0 {
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
		}(i)
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	goodCount := 0
	badCount := 0
	networkFailures := 0

	if !quiet {
		fmt.Printf("\n%s\n", strings.Repeat("=", 80))
		fmt.Printf("PROCESSING RESULTS\n")
		fmt.Printf("%s\n", strings.Repeat("=", 80))
	}

	for result := range resultChan {
		// Classify result
		if result.HasNetworkError() {
			networkFailures++
			if !quiet {
				fmt.Printf("Request %d failed: %v\n", result.RequestNum, result.NetworkError)
			}
		} else if result.IsSuccessful() {
			goodCount++
			if !quiet {
				fmt.Printf("[%s] Request %d: %s %s - %d\n",
					time.Now().Format("15:04:05"), result.RequestNum,
					result.Method, result.URL, result.StatusCode)
			}
		} else {
			badCount++
			if !quiet {
				fmt.Printf("[%s] %s Request %d: %s %s - %d\n",
					time.Now().Format("15:04:05"), result.GetStatusCategory(),
					result.RequestNum, result.Method, result.URL, result.StatusCode)
			}
		}

		// Verbose output
		if verbose {
			fmt.Fprintf(output, "%s # Request %d %s\n",
				strings.Repeat("-", 20), result.RequestNum, strings.Repeat("-", 20))
			if result.HasNetworkError() {
				fmt.Fprintf(output, "Network Error: %v\n", result.NetworkError)
			} else {
				fmt.Fprintf(output, "Status Code: %d (%s)\n",
					result.StatusCode, result.GetStatusCategory())
				fmt.Fprintf(output, "Response: %s\n", result.ResponseBody)
			}
			fmt.Fprintf(output, "%s\n", strings.Repeat("-", 50))
		} else if !quiet {
			fmt.Printf("Request %d: %d\n", result.RequestNum, result.StatusCode)
		}
	}

	// Final summary
	duration := time.Since(startTime)
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("FINAL RESULTS\n")
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("GOOD REQUESTS (2xx): %d\n", goodCount)
	fmt.Printf("BAD REQUESTS (non-2xx): %d\n", badCount)
	fmt.Printf("NETWORK FAILURES: %d\n", networkFailures)
	fmt.Printf("TOTAL: %d requests processed\n", goodCount+badCount+networkFailures)
	fmt.Printf("DURATION: %v\n", duration)
	fmt.Printf("REQUESTS/SEC: %.2f\n", float64(totalRequests)/duration.Seconds())
	fmt.Printf("CONCURRENCY: %d\n", maxConcurrent)
	if delay > 0 {
		fmt.Printf("DELAY: %dms\n", delay)
	}
	if outputFile != "" {
		fmt.Printf("OUTPUT: %s\n", outputFile)
	}
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	return nil
}
