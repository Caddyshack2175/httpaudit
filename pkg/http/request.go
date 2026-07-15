package http

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// RequestTemplate represents a parsed HTTP request template
type RequestTemplate struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// RequestResult represents the result of an HTTP request
type RequestResult struct {
	RequestNum      int
	StatusCode      int
	ResponseSize    int
	ResponseTime    time.Duration
	ResponseBody    string
	ResponseHeaders map[string][]string
	NetworkError    error
	Method          string
	URL             string
	Replacements    map[string]string
}

// ParseRequestFromFile parses an HTTP request template from a file
func ParseRequestFromFile(filename string) (*RequestTemplate, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request file")
	}

	template := &RequestTemplate{
		Headers: make(map[string]string),
	}

	// Parse request line (first line)
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Split(requestLine, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	template.Method = parts[0]
	path := parts[1]

	// Parse headers and find Host header
	var host string
	bodyStartIndex := len(lines)

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Empty line indicates start of body
		if line == "" {
			bodyStartIndex = i + 1
			break
		}

		// Parse header
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

	// Construct full URL
	scheme := "https" // Default to HTTPS
	if host == "" {
		return nil, fmt.Errorf("no Host header found in request")
	}

	template.URL = fmt.Sprintf("%s://%s%s", scheme, host, path)

	// Parse body (everything after the empty line)
	if bodyStartIndex < len(lines) {
		bodyLines := lines[bodyStartIndex:]
		template.Body = strings.Join(bodyLines, "\n")
	}

	return template, nil
}

// MakeRequest sends an HTTP request using the provided template and client
func MakeRequest(template *RequestTemplate, client *http.Client, replacements map[string]string) *RequestResult {
	result := &RequestResult{
		Method:       template.Method,
		URL:          template.URL,
		Replacements: replacements,
	}

	// Apply replacements if provided
	url := template.URL
	body := template.Body
	headers := make(map[string]string)

	// Copy headers and apply replacements
	for k, v := range template.Headers {
		headers[k] = v
	}

	if replacements != nil {
		for placeholder, value := range replacements {
			placeholder = "{" + placeholder + "}"
			url = strings.ReplaceAll(url, placeholder, value)
			body = strings.ReplaceAll(body, placeholder, value)

			// Replace in headers
			for k, v := range headers {
				headers[k] = strings.ReplaceAll(v, placeholder, value)
			}
		}
	}

	result.URL = url

	// Create request body reader
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	// Create HTTP request
	req, err := http.NewRequest(template.Method, url, bodyReader)
	if err != nil {
		result.NetworkError = err
		return result
	}

	// Set headers
	for key, value := range headers {
		if key != "Host" && key != "Content-Length" {
			req.Header.Set(key, value)
		}
	}

	// Send request
	start := time.Now()
	resp, err := client.Do(req)
	result.ResponseTime = time.Since(start)

	if err != nil {
		result.NetworkError = err
		return result
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		result.NetworkError = err
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(respBody)
	result.ResponseBody = string(respBody)
	result.ResponseHeaders = resp.Header

	return result
}

// IsSuccessful returns true if the request was successful (2xx status code)
func (r *RequestResult) IsSuccessful() bool {
	return r.NetworkError == nil && r.StatusCode >= 200 && r.StatusCode < 300
}

// IsBadRequest returns true if the request returned a non-2xx status code
func (r *RequestResult) IsBadRequest() bool {
	return r.NetworkError == nil && (r.StatusCode < 200 || r.StatusCode >= 300)
}

// HasNetworkError returns true if there was a network/connection error
func (r *RequestResult) HasNetworkError() bool {
	return r.NetworkError != nil
}

// GetStatusCategory returns a human-readable status category
func (r *RequestResult) GetStatusCategory() string {
	if r.NetworkError != nil {
		return "NETWORK_ERROR"
	}

	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		return "SUCCESS"
	case r.StatusCode >= 300 && r.StatusCode < 400:
		return "REDIRECT"
	case r.StatusCode >= 400 && r.StatusCode < 500:
		return "CLIENT_ERROR"
	default:
		return "SERVER_ERROR"
	}
}