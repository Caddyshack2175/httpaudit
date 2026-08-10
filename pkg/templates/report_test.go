package templates

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadReportTemplate(t *testing.T) {
	path := writeTemplateFile(t, t.TempDir(), "report.yaml", `
tag: exposed-admin
name: Exposed Admin Panel
original_risk_rating: Medium
client_defined_risk_rating: Medium
status: Draft
finding: finding
summary: summary
recommendation: recommendation
`)
	template, err := LoadReportTemplate(path)
	if err != nil {
		t.Fatalf("LoadReportTemplate() error = %v", err)
	}
	if template.Tag != "exposed-admin" || template.Name != "Exposed Admin Panel" {
		t.Fatalf("unexpected report template: %#v", template)
	}
	if template.CVEs == nil || template.References == nil || template.AffectedHosts == nil {
		t.Errorf("nil slices were not initialized: %#v", template)
	}
}

func TestLoadReportTemplateErrors(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		wantError string
	}{
		{name: "invalid yaml", contents: "tag: [", wantError: "error parsing report template YAML"},
		{name: "missing tag", contents: "name: Test\n", wantError: "missing required field: tag"},
		{name: "missing name", contents: "tag: test\n", wantError: "missing required field: name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemplateFile(t, t.TempDir(), "report.yaml", tt.contents)
			_, err := LoadReportTemplate(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("LoadReportTemplate() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
	if _, err := LoadReportTemplate(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("LoadReportTemplate() error = nil for missing file")
	}
}

func TestReportOutputAddFindingGroupsByTag(t *testing.T) {
	report := NewReportOutput()
	if report.Version != 1 || report.Issues == nil || len(report.Issues) != 0 {
		t.Fatalf("NewReportOutput() = %#v", report)
	}

	template := &ReportTemplate{
		Tag:                     "issue-one",
		Name:                    "Issue One",
		OriginalRiskRating:      "High",
		ClientDefinedRiskRating: "Medium",
		Status:                  "Draft",
		CVSSVector:              "vector",
		NessusID:                123,
		OWASPID:                 "WSTG-TEST",
		CVEs:                    []string{"CVE-2024-0001"},
		Finding:                 "finding",
		Summary:                 "summary",
		Recommendation:          "fix it",
		References:              []string{"https://example.test"},
	}
	hostOne := Host{Hostname: "one.example", IP: "192.0.2.1", Port: 443}
	hostTwo := Host{Hostname: "two.example", IP: "192.0.2.2", Port: 8443}
	report.AddFinding(template, hostOne, "evidence one")
	report.AddFinding(template, hostTwo, " evidence two")

	if len(report.Issues) != 1 {
		t.Fatalf("issue count = %d, want 1", len(report.Issues))
	}
	issue := report.Issues[0]
	if !reflect.DeepEqual(issue.AffectedHosts, []Host{hostOne, hostTwo}) {
		t.Errorf("AffectedHosts = %#v", issue.AffectedHosts)
	}
	if issue.TechnicalDetails != "evidence one evidence two" {
		t.Errorf("TechnicalDetails = %q", issue.TechnicalDetails)
	}
	if issue.Name != template.Name || issue.OriginalRiskRating != "High" || issue.NessusID != 123 {
		t.Errorf("finding metadata = %#v", issue)
	}

	report.AddFinding(&ReportTemplate{Tag: "issue-two", Name: "Issue Two"}, hostOne, "other")
	if len(report.Issues) != 2 {
		t.Fatalf("issue count after second tag = %d, want 2", len(report.Issues))
	}
}

func TestFindingTagIsNotSerialized(t *testing.T) {
	data, err := json.Marshal(Finding{Tag: "internal", Name: "Visible"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "internal") || strings.Contains(string(data), `"tag"`) {
		t.Errorf("serialized Finding leaked internal tag: %s", data)
	}
}
