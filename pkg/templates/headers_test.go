package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validHeaderTemplateYAML = `
id: weak-example-header
info:
  name: Weak Example Header
  severity: medium
  tags: [headers]
  metadata:
    report_original_risk_rating: Medium
    report_client_defined_risk_rating: Low
    report_status: Draft
    report_cvss_vector: CVSS:3.1/example
    report_nessus_id: 123
    report_owasp_id: WSTG-CONF-01
    report_finding: finding
    report_summary: summary
    report_recommendation: recommendation
    report_cves: [CVE-2024-0001]
    report_references: [https://example.test/reference]
detection:
  type: misconfigured
  header: X-Example
  match_regex: '(?i)^weak$'
  description: weak header
`

func TestLoadHeaderTemplateAndConvertReport(t *testing.T) {
	path := writeTemplateFile(t, t.TempDir(), "header.yaml", validHeaderTemplateYAML)
	template, err := LoadHeaderTemplate(path)
	if err != nil {
		t.Fatalf("LoadHeaderTemplate() error = %v", err)
	}
	if template.ID != "weak-example-header" || template.MatchRegexCompiled == nil {
		t.Fatalf("unexpected loaded template: %#v", template)
	}
	if !template.MatchRegexCompiled.MatchString("WEAK") {
		t.Error("compiled match regex did not match expected value")
	}

	report := template.ToReportTemplate()
	if report.Tag != template.ID || report.Name != template.Info.Name {
		t.Errorf("ToReportTemplate() identity fields = %#v", report)
	}
	if report.OriginalRiskRating != "Medium" || report.ClientDefinedRiskRating != "Low" || report.NessusID != 123 {
		t.Errorf("ToReportTemplate() metadata = %#v", report)
	}
	if len(report.CVEs) != 1 || report.CVEs[0] != "CVE-2024-0001" {
		t.Errorf("ToReportTemplate() CVEs = %#v", report.CVEs)
	}
}

func TestLoadHeaderTemplateValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		wantError string
	}{
		{name: "invalid yaml", contents: "info: [", wantError: "failed to parse YAML"},
		{name: "missing id", contents: "info:\n  name: Test\ndetection:\n  type: missing\n  header: X-Test\n", wantError: "template ID is required"},
		{name: "missing name", contents: "id: test\ndetection:\n  type: missing\n  header: X-Test\n", wantError: "template name is required"},
		{name: "missing header", contents: "id: test\ninfo:\n  name: Test\ndetection:\n  type: missing\n", wantError: "detection header is required"},
		{name: "invalid type", contents: "id: test\ninfo:\n  name: Test\ndetection:\n  type: present\n  header: X-Test\n", wantError: "detection type must be"},
		{name: "missing regex", contents: "id: test\ninfo:\n  name: Test\ndetection:\n  type: misconfigured\n  header: X-Test\n", wantError: "requires match_regex or negative_match_regex"},
		{name: "invalid match regex", contents: "id: test\ninfo:\n  name: Test\ndetection:\n  type: misconfigured\n  header: X-Test\n  match_regex: '['\n", wantError: "invalid match_regex"},
		{name: "invalid negative regex", contents: "id: test\ninfo:\n  name: Test\ndetection:\n  type: misconfigured\n  header: X-Test\n  negative_match_regex: '['\n", wantError: "invalid negative_match_regex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemplateFile(t, t.TempDir(), "header.yaml", tt.contents)
			_, err := LoadHeaderTemplate(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("LoadHeaderTemplate() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestLoadHeaderTemplates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.yaml"), []byte(validHeaderTemplateYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	second := strings.ReplaceAll(validHeaderTemplateYAML, "weak-example-header", "second-header")
	if err := os.WriteFile(filepath.Join(dir, "two.yml"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := LoadHeaderTemplates(dir)
	if err != nil {
		t.Fatalf("LoadHeaderTemplates() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadHeaderTemplates() loaded %d templates, want 2", len(got))
	}

	empty := t.TempDir()
	if _, err := LoadHeaderTemplates(empty); err == nil || !strings.Contains(err.Error(), "no valid templates") {
		t.Fatalf("LoadHeaderTemplates(empty) error = %v", err)
	}
	if _, err := LoadHeaderTemplates(filepath.Join(empty, "missing")); err == nil {
		t.Fatal("LoadHeaderTemplates(missing) error = nil")
	}
}

func TestGetDefaultHeaderTemplates(t *testing.T) {
	got, err := GetDefaultHeaderTemplates()
	if err != nil {
		t.Fatalf("GetDefaultHeaderTemplates() error = %v", err)
	}
	if len(got) != 10 {
		t.Fatalf("GetDefaultHeaderTemplates() count = %d, want 10", len(got))
	}
	seen := make(map[string]bool)
	for _, template := range got {
		if err := template.validate(); err != nil {
			t.Errorf("default template %q is invalid: %v", template.ID, err)
		}
		if seen[template.ID] {
			t.Errorf("duplicate default template ID %q", template.ID)
		}
		seen[template.ID] = true
		if template.Detection.MatchRegex != "" && template.MatchRegexCompiled == nil {
			t.Errorf("default template %q match regex was not compiled", template.ID)
		}
		if template.Detection.NegativeMatchRegex != "" && template.NegativeMatchRegexCompiled == nil {
			t.Errorf("default template %q negative regex was not compiled", template.ID)
		}
	}
}
