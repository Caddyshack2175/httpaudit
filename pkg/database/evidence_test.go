package database

import (
	"strings"
	"sync"
	"testing"

	"httpaudit/pkg/templates"
)

func TestEvidenceDBAddFindingAndExportReport(t *testing.T) {
	db, err := NewEvidenceDB()
	if err != nil {
		t.Fatalf("NewEvidenceDB() error = %v", err)
	}
	defer db.Close()

	if count, err := db.GetFindingCount(); err != nil || count != 0 {
		t.Fatalf("initial GetFindingCount() = %d, %v", count, err)
	}

	requestHeaders := map[string]string{"Authorization": "Bearer test"}
	responseHeaders := map[string][]string{"Server": {"example"}, "X-Test": {"one", "two"}}
	for _, targetURL := range []string{"https://192.0.2.10/path", "https://192.0.2.11:8443/other"} {
		if err := db.AddFinding(
			"missing-csp",
			"Missing CSP",
			targetURL,
			200,
			"missing",
			"Content-Security-Policy",
			"",
			"Header is missing",
			"GET",
			requestHeaders,
			responseHeaders,
		); err != nil {
			t.Fatalf("AddFinding() error = %v", err)
		}
	}

	if count, err := db.GetFindingCount(); err != nil || count != 2 {
		t.Fatalf("GetFindingCount() = %d, %v; want 2", count, err)
	}

	metadata := map[string]*templates.ReportTemplate{
		"missing-csp": {
			Tag:                     "missing-csp",
			Name:                    "Missing CSP",
			OriginalRiskRating:      "Medium",
			ClientDefinedRiskRating: "Low",
			Status:                  "Confirmed",
			Finding:                 "finding",
			Summary:                 "summary",
			Recommendation:          "recommendation",
		},
	}
	report, err := db.ExportReport(metadata)
	if err != nil {
		t.Fatalf("ExportReport() error = %v", err)
	}
	if len(report.Issues) != 1 {
		t.Fatalf("ExportReport() issue count = %d, want 1", len(report.Issues))
	}
	issue := report.Issues[0]
	if issue.Name != "Missing CSP" || issue.OriginalRiskRating != "Medium" || issue.Status != "Confirmed" {
		t.Errorf("exported metadata = %#v", issue)
	}
	if len(issue.AffectedHosts) != 2 {
		t.Fatalf("affected host count = %d, want 2", len(issue.AffectedHosts))
	}
	if issue.AffectedHosts[0].Hostname != "192.0.2.10" || issue.AffectedHosts[0].Port != 443 {
		t.Errorf("first host = %#v", issue.AffectedHosts[0])
	}
	if issue.AffectedHosts[1].Hostname != "192.0.2.11" || issue.AffectedHosts[1].Port != 8443 {
		t.Errorf("second host = %#v", issue.AffectedHosts[1])
	}
	for _, want := range []string{
		"Header <code>Content-Security-Policy</code> is missing",
		"Header is missing",
		"HTTP/1.1 200",
		"Server: example",
	} {
		if !strings.Contains(issue.TechnicalDetails, want) {
			t.Errorf("TechnicalDetails missing %q", want)
		}
	}
}

func TestEvidenceDBUsesFallbackMetadata(t *testing.T) {
	db, err := NewEvidenceDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.AddFinding(
		"unknown-template",
		"Unknown Template",
		"http://192.0.2.20/test",
		500,
		"misconfigured",
		"X-Test",
		"weak",
		"bad value",
		"POST",
		nil,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	report, err := db.ExportReport(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Issues) != 1 {
		t.Fatalf("issue count = %d", len(report.Issues))
	}
	issue := report.Issues[0]
	if issue.Name != "Unknown Template" || issue.OriginalRiskRating != "Low" || issue.Status != "Draft" {
		t.Errorf("fallback issue = %#v", issue)
	}
	if !strings.Contains(issue.TechnicalDetails, "misconfigured") || !strings.Contains(issue.TechnicalDetails, "value: <code>weak</code>") {
		t.Errorf("fallback TechnicalDetails = %q", issue.TechnicalDetails)
	}
}

func TestEvidenceDBConcurrentAdds(t *testing.T) {
	db, err := NewEvidenceDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const findingCount = 20
	var wg sync.WaitGroup
	errors := make(chan error, findingCount)
	for i := 0; i < findingCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- db.AddFinding(
				"concurrent", "Concurrent", "http://192.0.2.30", 200,
				"missing", "X-Test", "", "", "GET", nil, nil,
			)
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Errorf("concurrent AddFinding() error = %v", err)
		}
	}
	if count, err := db.GetFindingCount(); err != nil || count != findingCount {
		t.Fatalf("GetFindingCount() = %d, %v; want %d", count, err, findingCount)
	}
}

func TestBuildEvidenceHandlesInvalidHeaderJSON(t *testing.T) {
	finding := &FindingRow{
		URL:             "https://example.test",
		StatusCode:      404,
		DetectionType:   "misconfigured",
		HeaderName:      "X-Test",
		ResponseHeaders: "not-json",
	}
	got := buildEvidence(finding)
	if !strings.Contains(got, "HTTP/1.1 404") || strings.Contains(got, "not-json") {
		t.Errorf("buildEvidence() = %q", got)
	}
}

func TestParseURLInfo(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		hostname string
		ip       string
		port     int
	}{
		{name: "https default", url: "https://192.0.2.1/path", hostname: "192.0.2.1", ip: "192.0.2.1", port: 443},
		{name: "http default", url: "http://192.0.2.2/path", hostname: "192.0.2.2", ip: "192.0.2.2", port: 80},
		{name: "explicit port", url: "https://192.0.2.3:9443/path", hostname: "192.0.2.3", ip: "192.0.2.3", port: 9443},
		{name: "invalid", url: "%", hostname: "%", ip: "", port: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostname, ip, port := parseURLInfo(tt.url)
			if hostname != tt.hostname || ip != tt.ip || port != tt.port {
				t.Errorf("parseURLInfo(%q) = %q, %q, %d; want %q, %q, %d", tt.url, hostname, ip, port, tt.hostname, tt.ip, tt.port)
			}
		})
	}
}

func TestEvidenceDBMethodsAfterCloseReturnErrors(t *testing.T) {
	db, err := NewEvidenceDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetFindingCount(); err == nil {
		t.Fatal("GetFindingCount() error = nil after Close")
	}
	if _, err := db.ExportReport(nil); err == nil {
		t.Fatal("ExportReport() error = nil after Close")
	}
}
