package headers

import (
	"strings"

	"httpaudit/pkg/templates"
)

// CheckResult represents the result of checking a template against a response
type CheckResult struct {
	Matched          bool
	TemplateID       string
	TemplateName     string
	DetectionType    string
	HeaderName       string
	HeaderValue      string
	IssueDescription string
}

// CheckTemplate checks if a header template matches the given response headers
func CheckTemplate(template *templates.HeaderTemplate, responseHeaders map[string][]string) *CheckResult {
	headerValue := getHeaderCaseInsensitive(responseHeaders, template.Detection.Header)

	result := &CheckResult{
		Matched:       false,
		TemplateID:    template.ID,
		TemplateName:  template.Info.Name,
		DetectionType: template.Detection.Type,
		HeaderName:    template.Detection.Header,
	}

	switch template.Detection.Type {
	case "missing":
		// Check if header is missing
		if headerValue == "" {
			result.Matched = true
			result.IssueDescription = "Header is missing"
		}

	case "misconfigured":
		// Header must be present to be misconfigured
		if headerValue == "" {
			return result // Not matched, header doesn't exist
		}

		result.HeaderValue = headerValue

		// Check if value matches the misconfiguration pattern
		if template.MatchRegexCompiled != nil {
			if template.MatchRegexCompiled.MatchString(headerValue) {
				result.Matched = true
				if template.Detection.Description != "" {
					result.IssueDescription = template.Detection.Description
				} else {
					result.IssueDescription = "Header value matches misconfiguration pattern"
				}
			}
		}

		// Check negative match (value should match this pattern but doesn't)
		if template.NegativeMatchRegexCompiled != nil {
			if !template.NegativeMatchRegexCompiled.MatchString(headerValue) {
				result.Matched = true
				if template.Detection.Description != "" {
					result.IssueDescription = template.Detection.Description
				} else {
					result.IssueDescription = "Header value does not match expected pattern"
				}
			}
		}
	}

	return result
}

// getHeaderCaseInsensitive retrieves a header value case-insensitively
// Returns the first value if multiple values exist
func getHeaderCaseInsensitive(headers map[string][]string, headerName string) string {
	headerNameLower := strings.ToLower(headerName)

	for name, values := range headers {
		if strings.ToLower(name) == headerNameLower {
			if len(values) > 0 {
				return values[0]
			}
			return ""
		}
	}

	return ""
}

// GetAllHeaderValues retrieves all values for a header case-insensitively
func GetAllHeaderValues(headers map[string][]string, headerName string) []string {
	headerNameLower := strings.ToLower(headerName)

	for name, values := range headers {
		if strings.ToLower(name) == headerNameLower {
			return values
		}
	}

	return nil
}

// HasHeader checks if a header exists (case-insensitive)
func HasHeader(headers map[string][]string, headerName string) bool {
	headerNameLower := strings.ToLower(headerName)

	for name := range headers {
		if strings.ToLower(name) == headerNameLower {
			return true
		}
	}

	return false
}
