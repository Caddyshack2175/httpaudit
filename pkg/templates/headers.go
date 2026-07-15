package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// HeaderTemplate defines a security header detection template
type HeaderTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string   `yaml:"name"`
		Severity string   `yaml:"severity"`
		Tags     []string `yaml:"tags"`
		Metadata struct {
			ReportOriginalRiskRating     string   `yaml:"report_original_risk_rating"`
			ReportClientDefinedRiskRating string  `yaml:"report_client_defined_risk_rating"`
			ReportStatus                  string   `yaml:"report_status"`
			ReportCVSSVector              string   `yaml:"report_cvss_vector"`
			ReportNessusID                int      `yaml:"report_nessus_id"`
			ReportOWASPID                 string   `yaml:"report_owasp_id"`
			ReportFinding                 string   `yaml:"report_finding"`
			ReportSummary                 string   `yaml:"report_summary"`
			ReportRecommendation          string   `yaml:"report_recommendation"`
			ReportCVEs                    []string `yaml:"report_cves"`
			ReportReferences              []string `yaml:"report_references"`
		} `yaml:"metadata"`
	} `yaml:"info"`
	Detection struct {
		Type              string `yaml:"type"` // "missing" or "misconfigured"
		Header            string `yaml:"header"`
		MatchRegex        string `yaml:"match_regex,omitempty"`
		NegativeMatchRegex string `yaml:"negative_match_regex,omitempty"`
		Description       string `yaml:"description,omitempty"`
	} `yaml:"detection"`

	// Compiled regexes (not from YAML)
	MatchRegexCompiled        *regexp.Regexp
	NegativeMatchRegexCompiled *regexp.Regexp
}

// LoadHeaderTemplate loads a single header template from a YAML file
func LoadHeaderTemplate(filePath string) (*HeaderTemplate, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var template HeaderTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Compile regexes if provided
	if template.Detection.MatchRegex != "" {
		regex, err := regexp.Compile(template.Detection.MatchRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid match_regex: %w", err)
		}
		template.MatchRegexCompiled = regex
	}

	if template.Detection.NegativeMatchRegex != "" {
		regex, err := regexp.Compile(template.Detection.NegativeMatchRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid negative_match_regex: %w", err)
		}
		template.NegativeMatchRegexCompiled = regex
	}

	// Validate template
	if err := template.validate(); err != nil {
		return nil, fmt.Errorf("template validation failed: %w", err)
	}

	return &template, nil
}

// LoadHeaderTemplates loads all header templates from a directory
func LoadHeaderTemplates(dirPath string) ([]*HeaderTemplate, error) {
	var templates []*HeaderTemplate

	files, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only process .yaml and .yml files
		ext := filepath.Ext(file.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(dirPath, file.Name())
		template, err := LoadHeaderTemplate(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load template %s: %w", file.Name(), err)
		}

		templates = append(templates, template)
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no valid templates found in directory")
	}

	return templates, nil
}

// validate checks if the template is properly configured
func (t *HeaderTemplate) validate() error {
	if t.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if t.Info.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if t.Detection.Header == "" {
		return fmt.Errorf("detection header is required")
	}
	if t.Detection.Type != "missing" && t.Detection.Type != "misconfigured" {
		return fmt.Errorf("detection type must be 'missing' or 'misconfigured'")
	}
	if t.Detection.Type == "misconfigured" && t.Detection.MatchRegex == "" && t.Detection.NegativeMatchRegex == "" {
		return fmt.Errorf("misconfigured detection requires match_regex or negative_match_regex")
	}
	return nil
}

// ToReportTemplate converts a HeaderTemplate to a ReportTemplate
func (t *HeaderTemplate) ToReportTemplate() *ReportTemplate {
	return &ReportTemplate{
		Tag:                     t.ID,
		Name:                    t.Info.Name,
		OriginalRiskRating:      t.Info.Metadata.ReportOriginalRiskRating,
		ClientDefinedRiskRating: t.Info.Metadata.ReportClientDefinedRiskRating,
		Status:                  t.Info.Metadata.ReportStatus,
		CVSSVector:              t.Info.Metadata.ReportCVSSVector,
		NessusID:                t.Info.Metadata.ReportNessusID,
		OWASPID:                 t.Info.Metadata.ReportOWASPID,
		CVEs:                    t.Info.Metadata.ReportCVEs,
		References:              t.Info.Metadata.ReportReferences,
		Finding:                 t.Info.Metadata.ReportFinding,
		Summary:                 t.Info.Metadata.ReportSummary,
		Recommendation:          t.Info.Metadata.ReportRecommendation,
	}
}

// GetDefaultHeaderTemplates returns the built-in default templates
func GetDefaultHeaderTemplates() ([]*HeaderTemplate, error) {
	templates := []string{
		defaultXFrameOptions,
		defaultCSP,
		defaultHSTS,
		defaultXContentTypeOptions,
		defaultReferrerPolicy,
		defaultPermissionsPolicy,
		defaultXXSSProtection,
		defaultCSPUnsafeInline,
		defaultHSTSShortMaxAge,
		defaultXFrameOptionsAllowFrom,
	}

	var parsed []*HeaderTemplate
	for i, tmpl := range templates {
		var template HeaderTemplate
		if err := yaml.Unmarshal([]byte(tmpl), &template); err != nil {
			return nil, fmt.Errorf("failed to parse default template %d: %w", i, err)
		}

		// Compile regexes
		if template.Detection.MatchRegex != "" {
			regex, err := regexp.Compile(template.Detection.MatchRegex)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in default template %d: %w", i, err)
			}
			template.MatchRegexCompiled = regex
		}

		if template.Detection.NegativeMatchRegex != "" {
			regex, err := regexp.Compile(template.Detection.NegativeMatchRegex)
			if err != nil {
				return nil, fmt.Errorf("invalid negative regex in default template %d: %w", i, err)
			}
			template.NegativeMatchRegexCompiled = regex
		}

		parsed = append(parsed, &template)
	}

	return parsed, nil
}

// Default embedded templates
const defaultXFrameOptions = `
id: missing-x-frame-options
info:
  name: Missing X-Frame-Options Header
  severity: low
  tags:
    - headers
    - clickjacking
    - security-headers
  metadata:
    report_original_risk_rating: Low
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
    report_nessus_id: 85582
    report_owasp_id: WSTG-CLNT-09
    report_finding: "<p>Testing found that the application was missing the X-Frame-Options header.</p>"
    report_summary: "<p>The X-Frame-Options header is a security header that can prevent clickjacking attacks by controlling whether a page can be displayed in a frame, iframe, embed or object.</p>"
    report_recommendation: "<p>It is recommended to configure the server to send the X-Frame-Options header on all outgoing responses. The recommended value is 'DENY' or 'SAMEORIGIN'.</p>"
    report_cves: []
    report_references:
      - https://owasp.org/www-community/attacks/Clickjacking
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
detection:
  type: missing
  header: X-Frame-Options
`

const defaultCSP = `
id: missing-csp
info:
  name: Missing Content-Security-Policy Header (CSP)
  severity: low
  tags:
    - headers
    - csp
    - security-headers
  metadata:
    report_original_risk_rating: Low
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
    report_nessus_id: 10000001
    report_owasp_id: WSTG-CONF-12
    report_finding: "<p>Testing found that the application was missing the Content-Security-Policy header.</p>"
    report_summary: "<p>The Content-Security-Policy header was designed to modify the way browsers render pages and reduce the risk of XSS and other content injection attacks.</p>"
    report_recommendation: "<p>It is recommended to configure the server to send the Content-Security-Policy header on all outgoing responses with appropriate directives.</p>"
    report_cves: []
    report_references:
      - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
detection:
  type: missing
  header: Content-Security-Policy
`

const defaultHSTS = `
id: missing-hsts
info:
  name: Missing Strict-Transport-Security Header (HSTS)
  severity: low
  tags:
    - headers
    - hsts
    - security-headers
  metadata:
    report_original_risk_rating: Low
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
    report_nessus_id: 10000002
    report_owasp_id: WSTG-CRYP-01
    report_finding: "<p>Testing found that the application was missing the Strict-Transport-Security header.</p>"
    report_summary: "<p>HTTP Strict Transport Security (HSTS) is a security feature that forces browsers to only communicate with the site over HTTPS, preventing protocol downgrade attacks.</p>"
    report_recommendation: "<p>It is recommended to configure the server to send the Strict-Transport-Security header on HTTPS responses with a max-age of at least 31536000 (1 year).</p>"
    report_cves: []
    report_references:
      - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
detection:
  type: missing
  header: Strict-Transport-Security
`

const defaultXContentTypeOptions = `
id: missing-x-content-type-options
info:
  name: Missing X-Content-Type-Options Header
  severity: low
  tags:
    - headers
    - mime-sniffing
    - security-headers
  metadata:
    report_original_risk_rating: Low
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
    report_nessus_id: 10000003
    report_owasp_id: WSTG-CONF-12
    report_finding: "<p>Testing found that the application was missing the X-Content-Type-Options header.</p>"
    report_summary: "<p>The X-Content-Type-Options header prevents browsers from MIME-sniffing a response away from the declared content-type, reducing exposure to drive-by download attacks.</p>"
    report_recommendation: "<p>It is recommended to configure the server to send the X-Content-Type-Options header with the value 'nosniff' on all outgoing responses.</p>"
    report_cves: []
    report_references:
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
detection:
  type: missing
  header: X-Content-Type-Options
`

const defaultReferrerPolicy = `
id: missing-referrer-policy
info:
  name: Missing Referrer-Policy Header
  severity: info
  tags:
    - headers
    - privacy
    - security-headers
  metadata:
    report_original_risk_rating: Informational
    report_client_defined_risk_rating: Informational
    report_status: Draft
    report_cvss_vector: ""
    report_nessus_id: 10000004
    report_owasp_id: WSTG-CONF-12
    report_finding: "<p>Testing found that the application was missing the Referrer-Policy header.</p>"
    report_summary: "<p>The Referrer-Policy header controls how much referrer information should be included with requests, helping to protect user privacy.</p>"
    report_recommendation: "<p>It is recommended to configure the server to send the Referrer-Policy header with an appropriate value such as 'strict-origin-when-cross-origin' or 'no-referrer'.</p>"
    report_cves: []
    report_references:
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
detection:
  type: missing
  header: Referrer-Policy
`

const defaultPermissionsPolicy = `
id: missing-permissions-policy
info:
  name: Missing Permissions-Policy Header
  severity: info
  tags:
    - headers
    - permissions
    - security-headers
  metadata:
    report_original_risk_rating: Informational
    report_client_defined_risk_rating: Informational
    report_status: Draft
    report_cvss_vector: ""
    report_nessus_id: 10000005
    report_owasp_id: WSTG-CONF-12
    report_finding: "<p>Testing found that the application was missing the Permissions-Policy header.</p>"
    report_summary: "<p>The Permissions-Policy header allows a site to control which features and APIs can be used in the browser, providing an additional layer of security.</p>"
    report_recommendation: "<p>It is recommended to configure the server to send the Permissions-Policy header to restrict browser features that are not needed by the application.</p>"
    report_cves: []
    report_references:
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
detection:
  type: missing
  header: Permissions-Policy
`

const defaultXXSSProtection = `
id: deprecated-x-xss-protection
info:
  name: Deprecated X-XSS-Protection Header Present
  severity: info
  tags:
    - headers
    - deprecated
    - security-headers
  metadata:
    report_original_risk_rating: Informational
    report_client_defined_risk_rating: Informational
    report_status: Draft
    report_cvss_vector: ""
    report_nessus_id: 10000006
    report_owasp_id: WSTG-CONF-12
    report_finding: "<p>Testing found that the application was using the deprecated X-XSS-Protection header.</p>"
    report_summary: "<p>The X-XSS-Protection header is deprecated and should no longer be used. Modern browsers have removed support for this header in favor of Content-Security-Policy.</p>"
    report_recommendation: "<p>Remove the X-XSS-Protection header and implement a strong Content-Security-Policy instead.</p>"
    report_cves: []
    report_references:
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
detection:
  type: misconfigured
  header: X-XSS-Protection
  match_regex: ".*"
  description: "Header is deprecated and should not be used"
`

const defaultCSPUnsafeInline = `
id: csp-unsafe-inline
info:
  name: Content-Security-Policy Allows Unsafe Inline Scripts
  severity: medium
  tags:
    - headers
    - csp
    - xss
    - security-headers
  metadata:
    report_original_risk_rating: Medium
    report_client_defined_risk_rating: Medium
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
    report_nessus_id: 10000007
    report_owasp_id: WSTG-CONF-12
    report_finding: "<p>Testing found that the Content-Security-Policy header allows unsafe inline scripts or styles.</p>"
    report_summary: "<p>The Content-Security-Policy header contains 'unsafe-inline' in script-src or default-src directives, which significantly reduces the protection against XSS attacks.</p>"
    report_recommendation: "<p>Remove 'unsafe-inline' from the CSP policy and use nonces or hashes for inline scripts instead.</p>"
    report_cves: []
    report_references:
      - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
detection:
  type: misconfigured
  header: Content-Security-Policy
  match_regex: "(?i)(script-src|default-src).*'unsafe-inline'"
  description: "CSP allows 'unsafe-inline' which defeats XSS protection"
`

const defaultHSTSShortMaxAge = `
id: hsts-short-max-age
info:
  name: Strict-Transport-Security Header With Short max-age
  severity: low
  tags:
    - headers
    - hsts
    - security-headers
  metadata:
    report_original_risk_rating: Low
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
    report_nessus_id: 10000008
    report_owasp_id: WSTG-CRYP-01
    report_finding: "<p>Testing found that the Strict-Transport-Security header has a max-age value that is too short.</p>"
    report_summary: "<p>The HSTS max-age directive specifies how long the browser should remember to only access the site over HTTPS. A max-age less than 1 year (31536000 seconds) is considered insufficient.</p>"
    report_recommendation: "<p>Increase the max-age directive to at least 31536000 seconds (1 year). Consider also adding the includeSubDomains and preload directives.</p>"
    report_cves: []
    report_references:
      - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
detection:
  type: misconfigured
  header: Strict-Transport-Security
  match_regex: "max-age=([0-9]{1,7}|[12][0-9]{7}|30[0-9]{6}|31[0-4][0-9]{5}|315[0-2][0-9]{4}|3153[0-5][0-9]{3})[^0-9]?"
  description: "HSTS max-age is less than 31536000 (1 year)"
`

const defaultXFrameOptionsAllowFrom = `
id: x-frame-options-allow-from
info:
  name: X-Frame-Options Uses Deprecated ALLOW-FROM Directive
  severity: low
  tags:
    - headers
    - clickjacking
    - deprecated
    - security-headers
  metadata:
    report_original_risk_rating: Low
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N
    report_nessus_id: 10000009
    report_owasp_id: WSTG-CLNT-09
    report_finding: "<p>Testing found that the X-Frame-Options header uses the deprecated ALLOW-FROM directive.</p>"
    report_summary: "<p>The ALLOW-FROM directive in X-Frame-Options is deprecated and not supported by modern browsers. It should be replaced with the CSP frame-ancestors directive.</p>"
    report_recommendation: "<p>Replace the X-Frame-Options ALLOW-FROM directive with a Content-Security-Policy header using the frame-ancestors directive.</p>"
    report_cves: []
    report_references:
      - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
detection:
  type: misconfigured
  header: X-Frame-Options
  match_regex: "(?i)^ALLOW-FROM"
  description: "Uses deprecated ALLOW-FROM directive"
`
