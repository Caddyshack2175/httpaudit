package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"httpaudit/pkg/templates"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var nucleiCmd = &cobra.Command{
	Use:   "nuclei",
	Short: "Run Nuclei templates and output in custom report format",
	Long: `Wraps the Nuclei scanner and converts output to custom report format.
Uses Nuclei's powerful template engine with custom reporting output.
Supports optional 'report' section in templates for enhanced findings.`,
	RunE: runNuclei,
}

var (
	nucleiURL              string
	nucleiURLs             string
	nucleiTemplate         string
	nucleiTemplates        string
	nucleiReportJSON       string
	nucleiTags             []string
	nucleiSeverity         []string
	nucleiThreads          int
	nucleiRateLimit        int
	nucleiTruncateResponse int
)

func init() {
	rootCmd.AddCommand(nucleiCmd)

	nucleiCmd.Flags().StringVarP(&nucleiURL, "url", "u", "", "Single URL to test")
	nucleiCmd.Flags().StringVarP(&nucleiURLs, "urls", "l", "", "File containing URLs to test (one per line)")
	nucleiCmd.Flags().StringVar(&nucleiTemplate, "template", "", "Single Nuclei template file")
	nucleiCmd.Flags().StringVar(&nucleiTemplates, "templates", "", "Directory containing Nuclei templates")
	nucleiCmd.Flags().StringSliceVar(&nucleiTags, "tags", []string{}, "Filter templates by tags (comma-separated)")
	nucleiCmd.Flags().StringSliceVar(&nucleiSeverity, "severity", []string{}, "Filter by severity (info,low,medium,high,critical)")
	nucleiCmd.Flags().StringVarP(&nucleiReportJSON, "report-json", "o", "", "Output JSON report file (required)")
	nucleiCmd.Flags().IntVarP(&nucleiThreads, "threads", "j", 25, "Number of concurrent threads")
	nucleiCmd.Flags().IntVarP(&nucleiRateLimit, "rate-limit", "r", 150, "Rate limit (requests per second)")
	nucleiCmd.Flags().IntVar(&nucleiTruncateResponse, "truncate-response", 2000, "Truncate response body to N characters (0 = no truncation)")

	nucleiCmd.MarkFlagRequired("report-json")
}

// NucleiResult represents a single finding from Nuclei JSON output
type NucleiResult struct {
	TemplateID   string                 `json:"template-id"`
	TemplatePath string                 `json:"template-path"`
	Info         NucleiInfo             `json:"info"`
	Type         string                 `json:"type"`
	Host         string                 `json:"host"`
	MatchedAt    string                 `json:"matched-at"`
	ExtractedResults []string           `json:"extracted-results,omitempty"`
	Request      string                 `json:"request,omitempty"`
	Response     string                 `json:"response,omitempty"`
	IP           string                 `json:"ip,omitempty"`
	Timestamp    string                 `json:"timestamp"`
	CurlCommand  string                 `json:"curl-command,omitempty"`
	MatcherName  string                 `json:"matcher-name,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type NucleiInfo struct {
	Name        string                 `json:"name"`
	Author      []string               `json:"author,omitempty"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Reference   []string               `json:"reference,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// EnhancedTemplate represents a Nuclei template with optional report section
type EnhancedTemplate struct {
	ID     string                 `yaml:"id"`
	Info   NucleiInfo             `yaml:"info"`
	Report *templates.ReportTemplate `yaml:"report,omitempty"`
}

func runNuclei(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Validate input
	if nucleiURL == "" && nucleiURLs == "" {
		return fmt.Errorf("either --url or --urls must be specified")
	}
	if nucleiTemplate == "" && nucleiTemplates == "" {
		return fmt.Errorf("either --template or --templates must be specified")
	}

	// Check if nuclei is installed
	if _, err := exec.LookPath("nuclei"); err != nil {
		return fmt.Errorf("nuclei not found in PATH. Please install nuclei: https://github.com/projectdiscovery/nuclei")
	}

	// Build nuclei command
	nucleiArgs := []string{
		"-jsonl",                                   // JSON Lines output
		"-silent",                                  // Suppress banner
		"-no-color",                                // No color codes
		"-stats",                                   // Show stats
		"-c", fmt.Sprintf("%d", nucleiThreads),    // Concurrency
		"-rl", fmt.Sprintf("%d", nucleiRateLimit), // Rate limit
	}

	// Add URL or URLs file
	if nucleiURL != "" {
		nucleiArgs = append(nucleiArgs, "-u", nucleiURL)
	} else {
		nucleiArgs = append(nucleiArgs, "-l", nucleiURLs)
	}

	// Add template or templates directory
	if nucleiTemplate != "" {
		nucleiArgs = append(nucleiArgs, "-t", nucleiTemplate)
	} else {
		nucleiArgs = append(nucleiArgs, "-t", nucleiTemplates)
	}

	// Add tags filter
	if len(nucleiTags) > 0 {
		nucleiArgs = append(nucleiArgs, "-tags", strings.Join(nucleiTags, ","))
	}

	// Add severity filter
	if len(nucleiSeverity) > 0 {
		nucleiArgs = append(nucleiArgs, "-severity", strings.Join(nucleiSeverity, ","))
	}

	// Add proxy if specified
	proxyURL, _ := cmd.Flags().GetString("proxy")
	if proxyURL != "" {
		nucleiArgs = append(nucleiArgs, "-proxy", proxyURL)
	}

	if !quiet {
		fmt.Printf("[*] Running nuclei with templates...\n")
		fmt.Printf("[*] Command: nuclei %s\n", strings.Join(nucleiArgs, " "))
	}

	// Run nuclei and capture output
	nucleiCmd := exec.Command("nuclei", nucleiArgs...)
	var stdout, stderr bytes.Buffer
	nucleiCmd.Stdout = &stdout
	nucleiCmd.Stderr = &stderr

	if err := nucleiCmd.Run(); err != nil {
		// Nuclei returns non-zero exit code when findings are found, so don't treat as error
		if !quiet {
			fmt.Fprintf(os.Stderr, "[*] Nuclei completed (exit code: %v)\n", err)
		}
	}

	// Show stderr output (stats and progress)
	if !quiet && stderr.Len() > 0 {
		fmt.Fprint(os.Stderr, stderr.String())
	}

	// Parse nuclei JSON output
	results := []NucleiResult{}
	scanner := bufio.NewScanner(&stdout)
	// Increase buffer size for large JSON responses (default is 64KB, set max to 10MB)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			if !quiet {
				fmt.Fprintf(os.Stderr, "[!] Error parsing nuclei output: %v\n", err)
			}
			continue
		}
		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading nuclei output: %v", err)
	}

	if !quiet {
		fmt.Printf("[*] Nuclei found %d result(s)\n", len(results))
	}

	// Load enhanced templates to get report sections
	enhancedTemplates := make(map[string]*EnhancedTemplate)
	if nucleiTemplate != "" {
		template, err := loadEnhancedTemplate(nucleiTemplate)
		if err == nil {
			enhancedTemplates[template.ID] = template
		}
	} else {
		enhancedTemplates, _ = loadEnhancedTemplates(nucleiTemplates)
	}

	// Convert to our report format
	report := convertNucleiToReport(results, enhancedTemplates)

	// Write report
	if err := writeNucleiReport(report); err != nil {
		return fmt.Errorf("error writing report: %v", err)
	}

	if !quiet {
		fmt.Printf("\n[✓] Report written to: %s\n", nucleiReportJSON)
		fmt.Printf("[*] Total findings: %d\n", len(report.Issues))
	}

	return nil
}

func loadEnhancedTemplate(path string) (*EnhancedTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var template EnhancedTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, err
	}

	return &template, nil
}

func loadEnhancedTemplates(dir string) (map[string]*EnhancedTemplate, error) {
	templates := make(map[string]*EnhancedTemplate)

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}

	ymlFiles, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	files = append(files, ymlFiles...)

	for _, file := range files {
		template, err := loadEnhancedTemplate(file)
		if err != nil {
			continue // Skip files that don't parse
		}
		templates[template.ID] = template
	}

	return templates, nil
}

func convertNucleiToReport(results []NucleiResult, enhancedTemplates map[string]*EnhancedTemplate) *templates.ReportOutput {
	report := templates.NewReportOutput()

	// Group results by template ID
	for _, result := range results {
		// Get or create report template
		var reportTemplate *templates.ReportTemplate

		// Check if template has enhanced metadata
		if result.Info.Metadata != nil && hasReportMetadata(result.Info.Metadata) {
			reportTemplate = extractReportFromMetadata(result)
		} else if enhanced, ok := enhancedTemplates[result.TemplateID]; ok && enhanced.Report != nil {
			// Fallback to enhanced template file
			reportTemplate = enhanced.Report
			reportTemplate.Tag = result.TemplateID
			reportTemplate.Name = result.Info.Name
		} else {
			// Auto-generate report template from Nuclei info
			reportTemplate = &templates.ReportTemplate{
				Tag:                     result.TemplateID,
				Name:                    result.Info.Name,
				OriginalRiskRating:      strings.Title(result.Info.Severity),
				ClientDefinedRiskRating: strings.Title(result.Info.Severity),
				Status:                  "Draft",
				Finding:                 fmt.Sprintf("<p>%s</p>", result.Info.Description),
				Summary:                 fmt.Sprintf("<p>%s</p>", result.Info.Description),
				Recommendation:          "<p>Review and remediate this finding.</p>",
				CVEs:                    []string{},
				References:              result.Info.Reference,
			}
		}

		// Parse host information
		hostname, ip, port := parseHostInfo(result.Host, result.MatchedAt, result.IP)

		host := templates.Host{
			Hostname: hostname,
			IP:       ip,
			Port:     port,
		}

		// Build evidence from Nuclei output
		evidence := buildNucleiEvidence(result)

		// Add to report
		report.AddFinding(reportTemplate, host, evidence)
	}

	return report
}

// hasReportMetadata checks if metadata contains any report_ fields
func hasReportMetadata(metadata map[string]interface{}) bool {
	for key := range metadata {
		if strings.HasPrefix(key, "report_") {
			return true
		}
	}
	return false
}

// extractReportFromMetadata extracts report template from Nuclei metadata
func extractReportFromMetadata(result NucleiResult) *templates.ReportTemplate {
	meta := result.Info.Metadata

	// Helper to get string from metadata
	getString := func(key, defaultValue string) string {
		if val, ok := meta[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
		return defaultValue
	}

	// Helper to get int from metadata
	getInt := func(key string, defaultValue int) int {
		if val, ok := meta[key]; ok {
			switch v := val.(type) {
			case int:
				return v
			case float64:
				return int(v)
			}
		}
		return defaultValue
	}

	// Helper to get string slice from metadata
	getStringSlice := func(key string) []string {
		if val, ok := meta[key]; ok {
			if slice, ok := val.([]interface{}); ok {
				result := make([]string, 0, len(slice))
				for _, item := range slice {
					if str, ok := item.(string); ok {
						result = append(result, str)
					}
				}
				return result
			}
		}
		return []string{}
	}

	return &templates.ReportTemplate{
		Tag:                     result.TemplateID,
		Name:                    result.Info.Name,
		OriginalRiskRating:      getString("report_original_risk_rating", strings.Title(result.Info.Severity)),
		ClientDefinedRiskRating: getString("report_client_defined_risk_rating", strings.Title(result.Info.Severity)),
		Status:                  getString("report_status", "Draft"),
		CVSSVector:              getString("report_cvss_vector", ""),
		NessusID:                getInt("report_nessus_id", 0),
		OWASPID:                 getString("report_owasp_id", ""),
		Finding:                 getString("report_finding", fmt.Sprintf("<p>%s</p>", result.Info.Description)),
		Summary:                 getString("report_summary", fmt.Sprintf("<p>%s</p>", result.Info.Description)),
		Recommendation:          getString("report_recommendation", "<p>Review and remediate this finding.</p>"),
		CVEs:                    getStringSlice("report_cves"),
		References:              getStringSlice("report_references"),
	}
}

func parseHostInfo(host, matchedAt, ip string) (string, string, int) {
	// Try to parse from matched-at URL first
	targetURL := matchedAt
	if targetURL == "" {
		targetURL = host
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return host, ip, 0
	}

	hostname := parsedURL.Hostname()
	port := parsedURL.Port()
	portInt := 0

	if port == "" {
		if parsedURL.Scheme == "https" {
			portInt = 443
		} else {
			portInt = 80
		}
	} else {
		fmt.Sscanf(port, "%d", &portInt)
	}

	// Resolve IP if not provided
	if ip == "" {
		ips, err := net.LookupIP(hostname)
		if err == nil && len(ips) > 0 {
			ip = ips[0].String()
		}
	}

	return hostname, ip, portInt
}

func buildNucleiEvidence(result NucleiResult) string {
	var evidence strings.Builder

	evidence.WriteString(`<p><br />The following host was found to match the detection criteria:</p>`)
	evidence.WriteString(`<ul><li><strong>Command:</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`)

	// Use curl command from Nuclei if available, otherwise construct one
	curlCmd := result.CurlCommand
	if curlCmd == "" {
		curlCmd = fmt.Sprintf("$ curl -skL %s", result.MatchedAt)
	}
	evidence.WriteString(fmt.Sprintf(`<code>%s</code></li></ul>`, curlCmd))

	evidence.WriteString(`<figure class="table"><table><tbody><tr><td><code>`)

	// Add the curl command
	evidence.WriteString(fmt.Sprintf(`%s<br>`, curlCmd))

	// Add response snippet if available
	if result.Response != "" {
		responseSnippet := result.Response
		// Remove \r characters (Windows line endings)
		responseSnippet = strings.ReplaceAll(responseSnippet, "\r", "")
		// Replace tabs with 4 spaces
		responseSnippet = strings.ReplaceAll(responseSnippet, "\t", "    ")
		// Truncate if needed (0 = no truncation)
		if nucleiTruncateResponse > 0 && len(responseSnippet) > nucleiTruncateResponse {
			responseSnippet = responseSnippet[:nucleiTruncateResponse] + "...\n[Response truncated]"
		}
		// Replace newlines with <br> tags
		responseSnippet = strings.ReplaceAll(responseSnippet, "\n", "<br>")
		evidence.WriteString(responseSnippet)
		evidence.WriteString(`<br>`)
	}

	evidence.WriteString(`</code><br><br>`)

	// Security Analysis section
	evidence.WriteString(`<code>Security Analysis:</code><br>`)
	evidence.WriteString(fmt.Sprintf(`<code><mark class="marker-green">%s</mark></code>`, result.Info.Name))

	// Add matcher info if available
	if result.MatcherName != "" {
		evidence.WriteString(fmt.Sprintf(`<br><code>Matched by: %s</code>`, result.MatcherName))
	}

	evidence.WriteString(`</td></tr></tbody></table></figure><p>&nbsp;</p>`)

	return evidence.String()
}

func writeNucleiReport(report *templates.ReportOutput) error {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "    ")
	err := encoder.Encode(report)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}
	jsonData := buffer.Bytes()

	if err := os.WriteFile(nucleiReportJSON, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing JSON report: %v", err)
	}

	return nil
}
