package headers

import (
	"reflect"
	"regexp"
	"testing"

	"httpaudit/pkg/templates"
)

func headerTemplate(id, detectionType, header string) *templates.HeaderTemplate {
	template := &templates.HeaderTemplate{ID: id}
	template.Info.Name = "Test Template"
	template.Detection.Type = detectionType
	template.Detection.Header = header
	return template
}

func TestCheckTemplateMissingHeader(t *testing.T) {
	template := headerTemplate("missing-csp", "missing", "Content-Security-Policy")

	got := CheckTemplate(template, map[string][]string{"Server": {"example"}})
	if !got.Matched || got.TemplateID != "missing-csp" || got.TemplateName != "Test Template" {
		t.Fatalf("CheckTemplate() = %#v", got)
	}
	if got.DetectionType != "missing" || got.HeaderName != "Content-Security-Policy" || got.IssueDescription != "Header is missing" {
		t.Errorf("missing-header details = %#v", got)
	}

	got = CheckTemplate(template, map[string][]string{"content-security-policy": {"default-src 'self'"}})
	if got.Matched {
		t.Errorf("CheckTemplate() matched a present header: %#v", got)
	}
}

func TestCheckTemplateMisconfiguredMatchRegex(t *testing.T) {
	template := headerTemplate("weak-csp", "misconfigured", "Content-Security-Policy")
	template.Detection.Description = "unsafe inline is enabled"
	template.MatchRegexCompiled = regexp.MustCompile(`(?i)'unsafe-inline'`)

	got := CheckTemplate(template, map[string][]string{
		"CONTENT-SECURITY-POLICY": {"default-src 'self'; script-src 'unsafe-inline'"},
	})
	if !got.Matched || got.HeaderValue == "" || got.IssueDescription != "unsafe inline is enabled" {
		t.Fatalf("CheckTemplate() = %#v", got)
	}

	got = CheckTemplate(template, map[string][]string{
		"Content-Security-Policy": {"default-src 'self'"},
	})
	if got.Matched {
		t.Errorf("CheckTemplate() matched a safe value: %#v", got)
	}

	got = CheckTemplate(template, nil)
	if got.Matched || got.HeaderValue != "" {
		t.Errorf("CheckTemplate() matched an absent misconfigured header: %#v", got)
	}
}

func TestCheckTemplateMisconfiguredNegativeMatchRegex(t *testing.T) {
	template := headerTemplate("weak-xfo", "misconfigured", "X-Frame-Options")
	template.NegativeMatchRegexCompiled = regexp.MustCompile(`(?i)^(DENY|SAMEORIGIN)$`)

	got := CheckTemplate(template, map[string][]string{"X-Frame-Options": {"ALLOW-FROM example.test"}})
	if !got.Matched || got.IssueDescription != "Header value does not match expected pattern" {
		t.Fatalf("CheckTemplate() = %#v", got)
	}

	got = CheckTemplate(template, map[string][]string{"X-Frame-Options": {"DENY"}})
	if got.Matched {
		t.Errorf("CheckTemplate() matched expected value: %#v", got)
	}
}

func TestHeaderLookupHelpersAreCaseInsensitive(t *testing.T) {
	headers := map[string][]string{
		"X-Example": {"one", "two"},
		"X-Empty":   {},
	}
	if got := getHeaderCaseInsensitive(headers, "x-example"); got != "one" {
		t.Errorf("getHeaderCaseInsensitive() = %q, want one", got)
	}
	if got := GetAllHeaderValues(headers, "X-EXAMPLE"); !reflect.DeepEqual(got, []string{"one", "two"}) {
		t.Errorf("GetAllHeaderValues() = %#v", got)
	}
	if !HasHeader(headers, "x-empty") {
		t.Error("HasHeader() = false for a present empty header")
	}
	if HasHeader(headers, "missing") {
		t.Error("HasHeader() = true for an absent header")
	}
	if got := GetAllHeaderValues(headers, "missing"); got != nil {
		t.Errorf("GetAllHeaderValues(missing) = %#v, want nil", got)
	}
}
