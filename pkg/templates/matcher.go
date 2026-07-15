package templates

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// MatchResult contains information about what matched
type MatchResult struct {
	Matched       bool
	MatchedBy     string // "header:Server" or "body:pattern"
	MatchedValue  string // The actual value that matched
	AllMatches    []string // All patterns that matched
}

// Match checks if the response matches the criteria
func (mc *MatchCriteria) Match(headers http.Header, body string) (*MatchResult, error) {
	result := &MatchResult{
		Matched:    false,
		AllMatches: []string{},
	}

	// Check header matches
	for headerName, pattern := range mc.Headers {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern for header %s: %v", headerName, err)
		}

		headerValue := headers.Get(headerName)
		if headerValue != "" && regex.MatchString(headerValue) {
			result.Matched = true
			matchInfo := fmt.Sprintf("header:%s", headerName)
			result.AllMatches = append(result.AllMatches, matchInfo)
			if result.MatchedBy == "" {
				result.MatchedBy = matchInfo
				result.MatchedValue = headerValue
			}
		}
	}

	// Check body matches
	for _, pattern := range mc.Body {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern for body: %v", err)
		}

		if regex.MatchString(body) {
			result.Matched = true
			matchInfo := fmt.Sprintf("body:%s", pattern)
			result.AllMatches = append(result.AllMatches, matchInfo)
			if result.MatchedBy == "" {
				result.MatchedBy = matchInfo
				// Get the first match from the body (truncated to 100 chars)
				matches := regex.FindStringSubmatch(body)
				if len(matches) > 0 {
					result.MatchedValue = truncateString(matches[0], 100)
				}
			}
		}
	}

	return result, nil
}

// MatchesDetection checks if a response matches a detection template
func MatchesDetection(template *DetectionTemplate, headers http.Header, body string) (bool, *MatchResult, error) {
	// Check positive matches
	positiveMatch, err := template.Match.Match(headers, body)
	if err != nil {
		return false, nil, err
	}

	// If no positive match, return false
	if !positiveMatch.Matched {
		return false, positiveMatch, nil
	}

	// Check negative matches (if defined)
	if template.NegativeMatch != nil {
		negativeMatch, err := template.NegativeMatch.Match(headers, body)
		if err != nil {
			return false, nil, err
		}

		// If negative pattern matches, exclude this result
		if negativeMatch.Matched {
			return false, positiveMatch, nil
		}
	}

	return true, positiveMatch, nil
}

// BuildTechnicalDetails generates HTML technical details from response
func BuildTechnicalDetails(url string, headers http.Header, body string, matchResult *MatchResult, detectionName string) string {
	var details strings.Builder

	details.WriteString(`<p><br />The following host was found to match the detection criteria:</p>`)
	details.WriteString(`<ul><li><strong>Command:</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`)
	details.WriteString(fmt.Sprintf(`<code>$ curl -skI %s</code></li></ul>`, url))

	details.WriteString(`<figure class="table"><table><tbody><tr><td><code>`)

	// curl command line
	details.WriteString(fmt.Sprintf(`$ curl -skI %s<br>`, url))

	// HTTP status line
	details.WriteString(`HTTP/2 200&nbsp;<br>`)

	// All headers lowercase
	for name, values := range headers {
		for _, value := range values {
			details.WriteString(fmt.Sprintf(`%s: %s<br>`, strings.ToLower(name), value))
		}
	}

	// Close the code block
	details.WriteString(`</code><br><br>`)

	// Security Analysis section
	details.WriteString(`<code>Security Analysis:</code><br>`)
	details.WriteString(fmt.Sprintf(`<code><mark class="marker-green">%s</mark></code>`, detectionName))

	details.WriteString(`</td></tr></tbody></table></figure><p>&nbsp;</p>`)

	return details.String()
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
