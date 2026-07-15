package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"httpaudit/pkg/templates"
)

// EvidenceDB manages an in-memory SQLite database for collecting security header findings
type EvidenceDB struct {
	db *sql.DB
	mu sync.Mutex
}

// FindingRow represents a single finding row from the database
type FindingRow struct {
	ID               int
	TemplateID       string
	TemplateName     string
	Hostname         string
	IP               string
	Port             int
	URL              string
	StatusCode       int
	DetectionType    string
	HeaderName       string
	HeaderValue      string
	IssueDescription string
	RequestMethod    string
	RequestHeaders   string
	ResponseHeaders  string
	Timestamp        string
}

// NewEvidenceDB creates a new in-memory SQLite database for evidence collection
func NewEvidenceDB() (*EvidenceDB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to create in-memory database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	edb := &EvidenceDB{db: db}

	// Create schema
	if err := edb.createSchema(); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return edb, nil
}

// createSchema creates the findings table and indexes
func (edb *EvidenceDB) createSchema() error {
	schema := `
	CREATE TABLE findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id TEXT NOT NULL,
		template_name TEXT NOT NULL,
		hostname TEXT NOT NULL,
		ip TEXT,
		port INTEGER,
		url TEXT,
		status_code INTEGER,
		detection_type TEXT,
		header_name TEXT,
		header_value TEXT,
		issue_description TEXT,
		request_method TEXT,
		request_headers TEXT,
		response_headers TEXT,
		timestamp TEXT
	);

	CREATE INDEX idx_template ON findings(template_id);
	CREATE INDEX idx_hostname ON findings(hostname);
	`

	_, err := edb.db.Exec(schema)
	return err
}

// AddFinding inserts a new finding into the database (thread-safe)
func (edb *EvidenceDB) AddFinding(
	templateID string,
	templateName string,
	url string,
	statusCode int,
	detectionType string,
	headerName string,
	headerValue string,
	issueDescription string,
	requestMethod string,
	requestHeaders map[string]string,
	responseHeaders map[string][]string,
) error {
	edb.mu.Lock()
	defer edb.mu.Unlock()

	// Parse URL to extract hostname, IP, and port
	hostname, ip, port := parseURLInfo(url)

	// Convert headers to JSON
	reqHeadersJSON, err := json.Marshal(requestHeaders)
	if err != nil {
		reqHeadersJSON = []byte("{}")
	}

	respHeadersJSON, err := json.Marshal(responseHeaders)
	if err != nil {
		respHeadersJSON = []byte("{}")
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	query := `
		INSERT INTO findings (
			template_id, template_name, hostname, ip, port, url, status_code,
			detection_type, header_name, header_value, issue_description,
			request_method, request_headers, response_headers, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = edb.db.Exec(
		query,
		templateID, templateName, hostname, ip, port, url, statusCode,
		detectionType, headerName, headerValue, issueDescription,
		requestMethod, string(reqHeadersJSON), string(respHeadersJSON), timestamp,
	)

	return err
}

// ExportReport converts the SQLite findings to a JSON report format
func (edb *EvidenceDB) ExportReport(templateMetadata map[string]*templates.ReportTemplate) (*templates.ReportOutput, error) {
	edb.mu.Lock()
	defer edb.mu.Unlock()

	report := templates.NewReportOutput()

	// Query all findings grouped by template_id
	query := `
		SELECT
			id, template_id, template_name, hostname, ip, port, url, status_code,
			detection_type, header_name, header_value, issue_description,
			request_method, request_headers, response_headers, timestamp
		FROM findings
		ORDER BY template_id, hostname
	`

	rows, err := edb.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	// Group findings by template_id
	grouped := make(map[string][]*FindingRow)

	for rows.Next() {
		var row FindingRow
		var headerValue sql.NullString

		err := rows.Scan(
			&row.ID, &row.TemplateID, &row.TemplateName, &row.Hostname,
			&row.IP, &row.Port, &row.URL, &row.StatusCode,
			&row.DetectionType, &row.HeaderName, &headerValue, &row.IssueDescription,
			&row.RequestMethod, &row.RequestHeaders, &row.ResponseHeaders, &row.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if headerValue.Valid {
			row.HeaderValue = headerValue.String
		} else {
			row.HeaderValue = ""
		}

		grouped[row.TemplateID] = append(grouped[row.TemplateID], &row)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	// Build report issues
	for templateID, findings := range grouped {
		// Get report template metadata
		reportTemplate, exists := templateMetadata[templateID]
		if !exists {
			// Create minimal report template if metadata not found
			reportTemplate = &templates.ReportTemplate{
				Tag:                  templateID,
				Name:                 findings[0].TemplateName,
				OriginalRiskRating:   "Low",
				ClientDefinedRiskRating: "Low",
				Status:              "Draft",
				Finding:             "<p>Security header issue detected.</p>",
				Summary:             "<p>A security header was found to be missing or misconfigured.</p>",
				Recommendation:      "<p>Review and configure the appropriate security headers.</p>",
			}
		}

		// Add each finding as evidence for this issue
		for _, finding := range findings {
			host := templates.Host{
				Hostname: finding.Hostname,
				IP:       finding.IP,
				Port:     finding.Port,
			}
			evidence := buildEvidence(finding)
			report.AddFinding(reportTemplate, host, evidence)
		}
	}

	return report, nil
}

// buildEvidence generates HTML evidence for a finding
func buildEvidence(finding *FindingRow) string {
	var evidence string

	evidence += "<p><br />The following host was found to have this issue:</p>"
	evidence += "<ul>"
	evidence += fmt.Sprintf("<li><strong>URL:</strong> <code>%s</code></li>", finding.URL)
	evidence += "<li><strong>Detection:</strong> "

	if finding.DetectionType == "missing" {
		evidence += fmt.Sprintf("Header <code>%s</code> is missing", finding.HeaderName)
	} else {
		evidence += fmt.Sprintf("Header <code>%s</code> is misconfigured", finding.HeaderName)
		if finding.HeaderValue != "" {
			evidence += fmt.Sprintf(" (value: <code>%s</code>)", finding.HeaderValue)
		}
	}

	if finding.IssueDescription != "" {
		evidence += fmt.Sprintf(" - %s", finding.IssueDescription)
	}

	evidence += "</li>"
	evidence += "</ul>"

	// Add response headers table
	evidence += `<figure class="table"><table><tbody><tr><td><code>`
	evidence += fmt.Sprintf("$ curl -skI %s<br><br>", finding.URL)
	evidence += fmt.Sprintf("HTTP/1.1 %d<br>", finding.StatusCode)

	// Parse and display response headers
	var respHeaders map[string][]string
	if err := json.Unmarshal([]byte(finding.ResponseHeaders), &respHeaders); err == nil {
		for name, values := range respHeaders {
			for _, value := range values {
				evidence += fmt.Sprintf("%s: %s<br>", name, value)
			}
		}
	}

	evidence += "</code></td></tr></tbody></table></figure>"

	return evidence
}

// parseURLInfo extracts hostname, IP, and port from a URL string
func parseURLInfo(urlStr string) (hostname string, ip string, port int) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr, "", 0
	}

	hostname = parsedURL.Hostname()
	portStr := parsedURL.Port()

	// Determine port
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	} else {
		if parsedURL.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	// Attempt to resolve IP
	ips, err := net.LookupIP(hostname)
	if err == nil && len(ips) > 0 {
		ip = ips[0].String()
	}

	return hostname, ip, port
}

// Close closes the database connection
func (edb *EvidenceDB) Close() error {
	return edb.db.Close()
}

// GetFindingCount returns the total number of findings in the database
func (edb *EvidenceDB) GetFindingCount() (int, error) {
	edb.mu.Lock()
	defer edb.mu.Unlock()

	var count int
	err := edb.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count)
	return count, err
}
