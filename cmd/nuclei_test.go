package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"httpaudit/pkg/templates"
)

func TestLoadEnhancedTemplateAndDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	one := write("one.yaml", "id: one\ninfo:\n  name: One\n  severity: low\nreport:\n  name: Report One\n")
	write("two.yml", "id: two\ninfo:\n  name: Two\n  severity: high\n")
	write("bad.yaml", "info: [")
	write("ignored.txt", "id: ignored")

	template, err := loadEnhancedTemplate(one)
	if err != nil || template.ID != "one" || template.Report == nil || template.Report.Name != "Report One" {
		t.Fatalf("loadEnhancedTemplate() = %#v, %v", template, err)
	}
	loaded, err := loadEnhancedTemplates(dir)
	if err != nil {
		t.Fatalf("loadEnhancedTemplates() error = %v", err)
	}
	if len(loaded) != 2 || loaded["one"] == nil || loaded["two"] == nil {
		t.Fatalf("loadEnhancedTemplates() = %#v", loaded)
	}
	if _, err := loadEnhancedTemplate(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("loadEnhancedTemplate() error = nil for missing file")
	}
}

func TestHasAndExtractReportMetadata(t *testing.T) {
	if hasReportMetadata(nil) || hasReportMetadata(map[string]interface{}{"other": "value"}) {
		t.Error("hasReportMetadata() matched metadata without report_ fields")
	}
	if !hasReportMetadata(map[string]interface{}{"report_status": "Confirmed"}) {
		t.Error("hasReportMetadata() did not match report_ field")
	}

	result := NucleiResult{
		TemplateID: "test-template",
		Info: NucleiInfo{
			Name:        "Test Finding",
			Severity:    "high",
			Description: "description",
			Metadata: map[string]interface{}{
				"report_original_risk_rating":       "Critical",
				"report_client_defined_risk_rating": "Medium",
				"report_status":                     "Confirmed",
				"report_nessus_id":                  float64(321),
				"report_cves":                       []interface{}{"CVE-2024-0001", 7},
				"report_references":                 []interface{}{"https://example.test/reference"},
			},
		},
	}
	got := extractReportFromMetadata(result)
	if got.Tag != "test-template" || got.Name != "Test Finding" || got.OriginalRiskRating != "Critical" || got.ClientDefinedRiskRating != "Medium" {
		t.Errorf("extractReportFromMetadata() = %#v", got)
	}
	if got.NessusID != 321 || len(got.CVEs) != 1 || got.CVEs[0] != "CVE-2024-0001" {
		t.Errorf("extracted numeric/array metadata = %#v", got)
	}
	if got.Finding != "<p>description</p>" || got.Recommendation == "" {
		t.Errorf("metadata defaults = %#v", got)
	}
}

func TestConvertNucleiToReportSourcesAndGrouping(t *testing.T) {
	enhanced := &EnhancedTemplate{
		ID: "enhanced",
		Report: &templates.ReportTemplate{
			Name:                    "Enhanced Report",
			OriginalRiskRating:      "Low",
			ClientDefinedRiskRating: "Low",
			Status:                  "Draft",
		},
	}
	results := []NucleiResult{
		{
			TemplateID: "auto",
			Info:       NucleiInfo{Name: "Automatic", Severity: "medium", Description: "automatic description", Reference: []string{"https://example.test/auto"}},
			Host:       "https://192.0.2.1",
			MatchedAt:  "https://192.0.2.1/path",
			IP:         "192.0.2.1",
		},
		{
			TemplateID: "auto",
			Info:       NucleiInfo{Name: "Automatic", Severity: "medium", Description: "automatic description"},
			Host:       "https://192.0.2.2:8443",
			MatchedAt:  "https://192.0.2.2:8443/other",
			IP:         "192.0.2.2",
		},
		{
			TemplateID: "enhanced",
			Info:       NucleiInfo{Name: "Enhanced Finding", Severity: "low"},
			MatchedAt:  "http://192.0.2.3/test",
			IP:         "192.0.2.3",
		},
		{
			TemplateID: "metadata",
			Info:       NucleiInfo{Name: "Metadata Finding", Severity: "high", Metadata: map[string]interface{}{"report_status": "Confirmed"}},
			MatchedAt:  "https://192.0.2.4",
			IP:         "192.0.2.4",
		},
	}

	report := convertNucleiToReport(results, map[string]*EnhancedTemplate{"enhanced": enhanced})
	if len(report.Issues) != 3 {
		t.Fatalf("issue count = %d, want 3: %#v", len(report.Issues), report.Issues)
	}
	auto := report.Issues[0]
	if auto.Name != "Automatic" || auto.OriginalRiskRating != "Medium" || len(auto.AffectedHosts) != 2 {
		t.Errorf("automatic issue = %#v", auto)
	}
	if auto.AffectedHosts[0].Port != 443 || auto.AffectedHosts[1].Port != 8443 {
		t.Errorf("automatic hosts = %#v", auto.AffectedHosts)
	}
	if report.Issues[1].Name != "Enhanced Finding" || report.Issues[1].AffectedHosts[0].Port != 80 {
		t.Errorf("enhanced issue = %#v", report.Issues[1])
	}
	if report.Issues[2].Status != "Confirmed" || report.Issues[2].OriginalRiskRating != "High" {
		t.Errorf("metadata issue = %#v", report.Issues[2])
	}
}

func TestParseHostInfo(t *testing.T) {
	hostname, ip, port := parseHostInfo("https://ignored.example", "https://192.0.2.10:9443/path", "192.0.2.10")
	if hostname != "192.0.2.10" || ip != "192.0.2.10" || port != 9443 {
		t.Errorf("parseHostInfo() = %q, %q, %d", hostname, ip, port)
	}
	hostname, ip, port = parseHostInfo("%", "", "provided")
	if hostname != "%" || ip != "provided" || port != 0 {
		t.Errorf("parseHostInfo(invalid) = %q, %q, %d", hostname, ip, port)
	}
}

func TestBuildNucleiEvidence(t *testing.T) {
	previousLimit := nucleiTruncateResponse
	nucleiTruncateResponse = 12
	t.Cleanup(func() { nucleiTruncateResponse = previousLimit })

	result := NucleiResult{
		Info:        NucleiInfo{Name: "Sensitive File"},
		MatchedAt:   "https://example.test/file",
		Response:    "line one\r\nline\ttwo and more",
		MatcherName: "body-match",
	}
	got := buildNucleiEvidence(result)
	for _, want := range []string{
		"$ curl -skL https://example.test/file",
		"[Response truncated]",
		"Sensitive File",
		"Matched by: body-match",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildNucleiEvidence() missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "\r") || strings.Contains(got, "\t") {
		t.Errorf("buildNucleiEvidence() retained CR/tab characters: %q", got)
	}
}

func TestWriteNucleiReport(t *testing.T) {
	previousPath := nucleiReportJSON
	nucleiReportJSON = filepath.Join(t.TempDir(), "report.json")
	t.Cleanup(func() { nucleiReportJSON = previousPath })

	report := templates.NewReportOutput()
	report.AddFinding(&templates.ReportTemplate{Tag: "x", Name: "HTML"}, templates.Host{Hostname: "example.test"}, "<p>evidence</p>")
	if err := writeNucleiReport(report); err != nil {
		t.Fatalf("writeNucleiReport() error = %v", err)
	}
	data, err := os.ReadFile(nucleiReportJSON)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `\u003c`) {
		t.Errorf("writeNucleiReport() escaped HTML: %s", data)
	}
	var decoded templates.ReportOutput
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Issues) != 1 {
		t.Fatalf("written report = %#v, %v", decoded, err)
	}
}
