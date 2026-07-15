package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"httpaudit/pkg/database"
	"httpaudit/pkg/fuzzer"
	headersPkg "httpaudit/pkg/headers"
	httplib "httpaudit/pkg/http"
	"httpaudit/pkg/templates"
)

var headersCmd = &cobra.Command{
	Use:   "headers",
	Short: "Check security headers on URLs or via fuzzing",
	Long: `Check security headers using either:
  1. Fuzzer mode: Request template with placeholders (--request template.txt --PLACEHOLDER values)
  2. Framer mode: URL list with custom headers (--urls targets.txt -H "Header: Value")

Examples:
  # URL list mode
  httpaudit headers --urls targets.txt -o findings.json

  # Fuzzer mode with placeholders
  httpaudit headers --request api.txt --ID 1-1000 -o findings.json

  # Custom templates with authentication
  httpaudit headers --urls targets.txt --templates custom/ -H "Cookie: session=abc" -o report.json
`,
	RunE:                headersRun,
	DisableFlagParsing:  true, // Manual parsing for dynamic placeholder flags
}

// Flags for headers command
var (
	headersRequestFile  string
	headersURLsFile     string
	headersSingleURL    string
	headersOutputFile   string
	headersTemplateFile string
	headersTemplatesDir string
	headersCustomHeaders []string
	headersThreads      int
	headersDelay        int
	headersVerbose      bool
	headersQuiet        bool
)

func init() {
	rootCmd.AddCommand(headersCmd)
}

func headersRun(cmd *cobra.Command, args []string) error {
	// Manual flag parsing to support dynamic placeholder flags
	var requestFile string
	var urlsFile string
	var singleURL string
	var outputFile string
	var templateFile string
	var templatesDir string
	var customHeaders []string
	var threads int = 5  // default
	var delay int = 0
	var verbose bool
	var quiet bool
	var proxyURL string = ""
	var timeout int = 30

	placeholderFiles := make(map[string]string)

	// Parse arguments manually
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			continue
		}

		// Remove leading dashes
		flagName := strings.TrimLeftFunc(arg, func(r rune) bool { return r == '-' })

		// Check for built-in flags
		switch flagName {
		case "r", "request":
			if i+1 < len(args) {
				requestFile = args[i+1]
				i++
			}
		case "u", "urls":
			if i+1 < len(args) {
				urlsFile = args[i+1]
				i++
			}
		case "U", "url":
			if i+1 < len(args) {
				singleURL = args[i+1]
				i++
			}
		case "o", "output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "T", "template":
			if i+1 < len(args) {
				templateFile = args[i+1]
				i++
			}
		case "D", "templates":
			if i+1 < len(args) {
				templatesDir = args[i+1]
				i++
			}
		case "H", "header":
			if i+1 < len(args) {
				customHeaders = append(customHeaders, args[i+1])
				i++
			}
		case "j", "threads":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &threads)
				i++
			}
		case "d", "delay":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &delay)
				i++
			}
		case "v", "verbose":
			verbose = true
		case "q", "quiet":
			quiet = true
		case "p", "proxy":
			if i+1 < len(args) {
				proxyURL = args[i+1]
				i++
			}
		case "t", "timeout":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &timeout)
				i++
			}
		default:
			// Check if this is a placeholder flag (uppercase)
			if strings.ToUpper(flagName) == flagName && flagName != "" && len(flagName) > 1 {
				if i+1 < len(args) {
					placeholderFiles[flagName] = args[i+1]
					i++
				}
			}
		}
	}

	// Validation: mutually exclusive modes
	fuzzerMode := requestFile != ""
	framerMode := urlsFile != "" || singleURL != ""

	if fuzzerMode && framerMode {
		return fmt.Errorf("cannot use --request with --urls/--url (modes are mutually exclusive)")
	}

	if !fuzzerMode && !framerMode {
		return fmt.Errorf("must specify either --request (fuzzer mode) or --urls/--url (framer mode)")
	}

	if fuzzerMode && len(placeholderFiles) == 0 {
		return fmt.Errorf("fuzzer mode requires at least one placeholder flag (e.g., --ID 1-100)")
	}

	if outputFile == "" {
		return fmt.Errorf("--output/-o is required")
	}

	// Load header templates
	var headerTemplates []*templates.HeaderTemplate
	var err error

	if templateFile != "" {
		// Load single template
		template, err := templates.LoadHeaderTemplate(templateFile)
		if err != nil {
			return fmt.Errorf("failed to load template: %w", err)
		}
		headerTemplates = []*templates.HeaderTemplate{template}
		if !quiet {
			fmt.Printf("[*] Loaded 1 custom template\n")
		}
	} else if templatesDir != "" {
		// Load directory of templates
		headerTemplates, err = templates.LoadHeaderTemplates(templatesDir)
		if err != nil {
			return fmt.Errorf("failed to load templates: %w", err)
		}
		if !quiet {
			fmt.Printf("[*] Loaded %d custom templates\n", len(headerTemplates))
		}
	} else {
		// Use default embedded templates
		headerTemplates, err = templates.GetDefaultHeaderTemplates()
		if err != nil {
			return fmt.Errorf("failed to load default templates: %w", err)
		}
		if !quiet {
			fmt.Printf("[*] Using %d default security header templates\n", len(headerTemplates))
		}
	}

	// Create in-memory SQLite database
	evidenceDB, err := database.NewEvidenceDB()
	if err != nil {
		return fmt.Errorf("failed to create evidence database: %w", err)
	}
	defer evidenceDB.Close()

	// Create HTTP client
	clientConfig := httplib.ClientConfig{
		ProxyURL:        proxyURL,
		Timeout:         timeout,
		FollowRedirects: false, // Don't follow redirects for header checks
	}
	httpClient, err := httplib.NewClient(clientConfig)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Parse custom headers
	headerMap := make(map[string]string)
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	var jobs []*HeaderCheckJob

	if fuzzerMode {
		// Fuzzer mode: generate jobs from request template and placeholders
		jobs, err = generateFuzzerJobs(requestFile, placeholderFiles, headerMap, quiet)
		if err != nil {
			return err
		}
	} else {
		// Framer mode: generate jobs from URL list
		jobs, err = generateFramerJobs(urlsFile, singleURL, headerMap, quiet)
		if err != nil {
			return err
		}
	}

	if !quiet {
		fmt.Printf("[*] Generated %d jobs to process\n", len(jobs))
		fmt.Printf("[*] Using %d concurrent threads\n", threads)
	}

	// Process jobs with worker pool
	err = processJobs(jobs, httpClient, headerTemplates, evidenceDB, threads, delay, quiet, verbose)
	if err != nil {
		return err
	}

	// Export report
	if !quiet {
		fmt.Printf("\n[*] Generating report...\n")
	}

	// Build template metadata map
	templateMetadata := make(map[string]*templates.ReportTemplate)
	for _, tmpl := range headerTemplates {
		templateMetadata[tmpl.ID] = tmpl.ToReportTemplate()
	}

	report, err := evidenceDB.ExportReport(templateMetadata)
	if err != nil {
		return fmt.Errorf("failed to export report: %w", err)
	}

	// Write JSON report
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	findingCount, _ := evidenceDB.GetFindingCount()
	if !quiet {
		fmt.Printf("[✓] Report written to: %s\n", outputFile)
		fmt.Printf("[*] Total findings: %d\n", findingCount)
		fmt.Printf("[*] Unique issues: %d\n", len(report.Issues))
	}

	return nil
}

// HeaderCheckJob represents a job to check headers for a URL
type HeaderCheckJob struct {
	URL          string
	Method       string
	Headers      map[string]string
	Body         string
	Replacements map[string]string // For fuzzer mode
}

// HeaderCheckResult represents the result of a header check
type HeaderCheckResult struct {
	Job             *HeaderCheckJob
	StatusCode      int
	ResponseHeaders map[string][]string
	Error           error
}

// generateFuzzerJobs creates jobs from request template and placeholders
func generateFuzzerJobs(requestFile string, placeholderFiles map[string]string, customHeaders map[string]string, quiet bool) ([]*HeaderCheckJob, error) {
	// Read request template to find placeholders
	templateData, err := os.ReadFile(requestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read request file: %w", err)
	}

	templateStr := string(templateData)

	// Find placeholders in template
	placeholders := fuzzer.FindPlaceholders(templateStr)
	if len(placeholders) == 0 {
		return nil, fmt.Errorf("no placeholders found in request template")
	}

	if !quiet {
		fmt.Printf("[*] Found placeholders: %v\n", placeholders)
	}

	// Load values for each placeholder
	valueMap := make(map[string][]string)
	for _, placeholder := range placeholders {
		fileOrRange, exists := placeholderFiles[placeholder]
		if !exists {
			return nil, fmt.Errorf("no value provided for placeholder {%s}", placeholder)
		}

		var values []string

		// Try numeric range first
		if strings.Contains(fileOrRange, "-") {
			parts := strings.Split(fileOrRange, "-")
			if len(parts) == 2 {
				values, err = fuzzer.GenerateNumericRange(fileOrRange)
				if err == nil {
					if !quiet {
						fmt.Printf("[*] Generated %d values for {%s} from range %s\n", len(values), placeholder, fileOrRange)
					}
					valueMap[placeholder] = values
					continue
				}
			}
		}

		// Otherwise load from file
		values, err = fuzzer.LoadLinesFromFile(fileOrRange)
		if err != nil {
			return nil, fmt.Errorf("failed to load values for {%s}: %w", placeholder, err)
		}

		if !quiet {
			fmt.Printf("[*] Loaded %d values for {%s} from file %s\n", len(values), placeholder, fileOrRange)
		}

		valueMap[placeholder] = values
	}

	// Generate combinations
	combinations := fuzzer.GenerateCombinations(placeholders, valueMap)
	if !quiet {
		fmt.Printf("[*] Generated %d combinations\n", len(combinations))
	}

	// Parse request template
	requestTemplate, err := httplib.ParseRequestFromFile(requestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request template: %w", err)
	}

	// Add custom headers to template
	for key, value := range customHeaders {
		requestTemplate.Headers[key] = value
	}

	// Create jobs
	var jobs []*HeaderCheckJob
	for _, combo := range combinations {
		// Replace placeholders in URL and body
		url := requestTemplate.URL
		body := requestTemplate.Body

		for placeholder, value := range combo {
			placeholder = "{" + placeholder + "}"
			url = strings.ReplaceAll(url, placeholder, value)
			body = strings.ReplaceAll(body, placeholder, value)
		}

		// Replace in headers too
		headers := make(map[string]string)
		for key, value := range requestTemplate.Headers {
			for placeholder, replaceValue := range combo {
				placeholderStr := "{" + placeholder + "}"
				value = strings.ReplaceAll(value, placeholderStr, replaceValue)
			}
			headers[key] = value
		}

		job := &HeaderCheckJob{
			URL:          url,
			Method:       requestTemplate.Method,
			Headers:      headers,
			Body:         body,
			Replacements: combo,
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// generateFramerJobs creates jobs from URL list
func generateFramerJobs(urlsFile string, singleURL string, customHeaders map[string]string, quiet bool) ([]*HeaderCheckJob, error) {
	var urls []string

	if singleURL != "" {
		urls = []string{singleURL}
	} else {
		file, err := os.Open(urlsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open URLs file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read URLs file: %w", err)
		}

		if !quiet {
			fmt.Printf("[*] Loaded %d URLs from file\n", len(urls))
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs to process")
	}

	// Create jobs
	var jobs []*HeaderCheckJob
	for _, url := range urls {
		job := &HeaderCheckJob{
			URL:     url,
			Method:  "GET",
			Headers: customHeaders,
		}
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// processJobs executes jobs with worker pool
func processJobs(
	jobs []*HeaderCheckJob,
	httpClient *http.Client,
	headerTemplates []*templates.HeaderTemplate,
	evidenceDB *database.EvidenceDB,
	threads int,
	delay int,
	quiet bool,
	verbose bool,
) error {
	totalJobs := len(jobs)
	jobsChan := make(chan *HeaderCheckJob, totalJobs)
	resultsChan := make(chan *HeaderCheckResult, totalJobs)

	// Progress tracking
	var completed int64
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for job := range jobsChan {
				result := executeHeaderCheck(job, httpClient)

				// Check all templates against this response
				if result.Error == nil {
					for _, template := range headerTemplates {
						checkResult := headersPkg.CheckTemplate(template, result.ResponseHeaders)

						if checkResult.Matched {
							// Add finding to database
							err := evidenceDB.AddFinding(
								checkResult.TemplateID,
								checkResult.TemplateName,
								job.URL,
								result.StatusCode,
								checkResult.DetectionType,
								checkResult.HeaderName,
								checkResult.HeaderValue,
								checkResult.IssueDescription,
								job.Method,
								job.Headers,
								result.ResponseHeaders,
							)

							if err != nil && verbose {
								fmt.Printf("[!] Error storing finding: %v\n", err)
							}
						}
					}
				}

				resultsChan <- result

				// Update progress
				count := atomic.AddInt64(&completed, 1)
				if !quiet && count%10 == 0 {
					fmt.Printf("[*] Progress: %d/%d\r", count, totalJobs)
				}

				// Apply delay
				if delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
			}
		}(i)
	}

	// Send jobs
	go func() {
		for _, job := range jobs {
			jobsChan <- job
		}
		close(jobsChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	for result := range resultsChan {
		if verbose {
			if result.Error != nil {
				fmt.Printf("[-] %s - Error: %v\n", result.Job.URL, result.Error)
			} else {
				fmt.Printf("[+] %s - Status: %d\n", result.Job.URL, result.StatusCode)
			}
		}
	}

	if !quiet {
		fmt.Printf("\n[✓] Completed %d requests\n", totalJobs)
	}

	return nil
}

// executeHeaderCheck performs HTTP request and returns headers
func executeHeaderCheck(job *HeaderCheckJob, client *http.Client) *HeaderCheckResult {
	result := &HeaderCheckResult{
		Job: job,
	}

	// Create request
	req, err := http.NewRequest(job.Method, job.URL, strings.NewReader(job.Body))
	if err != nil {
		result.Error = err
		return result
	}

	// Add headers
	for key, value := range job.Headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ResponseHeaders = resp.Header

	return result
}
