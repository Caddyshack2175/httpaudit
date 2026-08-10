package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"httpaudit/pkg/database"
	"httpaudit/pkg/templates"
)

func TestGenerateFramerJobs(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer test"}
	jobs, err := generateFramerJobs("", "https://single.example", headers, true)
	if err != nil {
		t.Fatalf("generateFramerJobs(single) error = %v", err)
	}
	if len(jobs) != 1 || jobs[0].URL != "https://single.example" || jobs[0].Method != "GET" || !reflect.DeepEqual(jobs[0].Headers, headers) {
		t.Fatalf("generateFramerJobs(single) = %#v", jobs)
	}

	path := filepath.Join(t.TempDir(), "urls.txt")
	if err := os.WriteFile(path, []byte("# comment\nhttps://one.example\n\n https://two.example/path \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	jobs, err = generateFramerJobs(path, "", headers, true)
	if err != nil {
		t.Fatalf("generateFramerJobs(file) error = %v", err)
	}
	if len(jobs) != 2 || jobs[0].URL != "https://one.example" || jobs[1].URL != "https://two.example/path" {
		t.Fatalf("generateFramerJobs(file) = %#v", jobs)
	}
}

func TestGenerateFramerJobsErrors(t *testing.T) {
	if _, err := generateFramerJobs(filepath.Join(t.TempDir(), "missing"), "", nil, true); err == nil {
		t.Fatal("generateFramerJobs() error = nil for missing file")
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# comments only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := generateFramerJobs(empty, "", nil, true); err == nil || !strings.Contains(err.Error(), "no URLs") {
		t.Fatalf("generateFramerJobs(empty) error = %v", err)
	}
}

func TestGenerateFuzzerJobs(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.txt")
	raw := "POST /users/{USER}/docs/{ID} HTTP/1.1\nHost: example.test\nX-Context: {USER}:{ID}\n\nowner={USER}&doc={ID}"
	if err := os.WriteFile(requestPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	usersPath := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(usersPath, []byte("alice\nbob\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	jobs, err := generateFuzzerJobs(
		requestPath,
		map[string]string{"USER": usersPath, "ID": "01-02"},
		map[string]string{"X-Custom": "custom-{USER}"},
		true,
	)
	if err != nil {
		t.Fatalf("generateFuzzerJobs() error = %v", err)
	}
	if len(jobs) != 4 {
		t.Fatalf("job count = %d, want 4", len(jobs))
	}
	first := jobs[0]
	if first.URL != "https://example.test/users/alice/docs/01" || first.Method != "POST" {
		t.Errorf("first job method/URL = %q %q", first.Method, first.URL)
	}
	if first.Body != "owner=alice&doc=01" || first.Headers["X-Context"] != "alice:01" || first.Headers["X-Custom"] != "custom-alice" {
		t.Errorf("first job = %#v", first)
	}
	if !reflect.DeepEqual(first.Replacements, map[string]string{"USER": "alice", "ID": "01"}) {
		t.Errorf("first replacements = %#v", first.Replacements)
	}
}

func TestGenerateFuzzerJobsErrors(t *testing.T) {
	dir := t.TempDir()
	noPlaceholders := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(noPlaceholders, []byte("GET / HTTP/1.1\nHost: example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := generateFuzzerJobs(noPlaceholders, nil, nil, true); err == nil || !strings.Contains(err.Error(), "no placeholders") {
		t.Fatalf("generateFuzzerJobs(no placeholders) error = %v", err)
	}

	withPlaceholder := filepath.Join(dir, "placeholder.txt")
	if err := os.WriteFile(withPlaceholder, []byte("GET /{ID} HTTP/1.1\nHost: example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := generateFuzzerJobs(withPlaceholder, nil, nil, true); err == nil || !strings.Contains(err.Error(), "no value provided") {
		t.Fatalf("generateFuzzerJobs(missing values) error = %v", err)
	}
}

func TestExecuteHeaderCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("X-Test") != "request" {
			t.Errorf("received %s with X-Test %q", r.Method, r.Header.Get("X-Test"))
		}
		w.Header().Set("X-Response", "present")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	job := &HeaderCheckJob{
		URL:     server.URL,
		Method:  "POST",
		Headers: map[string]string{"X-Test": "request"},
		Body:    "body",
	}
	result := executeHeaderCheck(job, server.Client())
	if result.Error != nil || result.StatusCode != http.StatusAccepted || http.Header(result.ResponseHeaders).Get("X-Response") != "present" {
		t.Fatalf("executeHeaderCheck() = %#v", result)
	}
	if result.Job != job {
		t.Error("executeHeaderCheck() did not retain the original job")
	}

	bad := executeHeaderCheck(&HeaderCheckJob{Method: "GET", URL: "://bad"}, server.Client())
	if bad.Error == nil {
		t.Fatal("executeHeaderCheck() error = nil for invalid URL")
	}
}

func TestProcessJobsStoresMatchedFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	template := &templates.HeaderTemplate{ID: "missing-test"}
	template.Info.Name = "Missing Test Header"
	template.Detection.Type = "missing"
	template.Detection.Header = "X-Required"
	template.MatchRegexCompiled = regexp.MustCompile(".*")

	db, err := database.NewEvidenceDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	jobs := []*HeaderCheckJob{
		{URL: server.URL + "/one", Method: "GET"},
		{URL: server.URL + "/two", Method: "GET"},
	}
	if err := processJobs(jobs, server.Client(), []*templates.HeaderTemplate{template}, db, 2, 0, true, false); err != nil {
		t.Fatalf("processJobs() error = %v", err)
	}
	if count, err := db.GetFindingCount(); err != nil || count != 2 {
		t.Fatalf("finding count = %d, %v; want 2", count, err)
	}
}
