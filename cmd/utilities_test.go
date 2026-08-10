package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadURLsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "urls.txt")
	contents := "\n# comment\n https://one.example/path \n\t\nhttp://two.example\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadURLsFromFile(path)
	if err != nil {
		t.Fatalf("loadURLsFromFile() error = %v", err)
	}
	want := []string{"https://one.example/path", "http://two.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadURLsFromFile() = %#v, want %#v", got, want)
	}
	if _, err := loadURLsFromFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("loadURLsFromFile() error = nil for missing file")
	}
}

func TestSanitizeFilename(t *testing.T) {
	got := sanitizeFilename("https://example.test:8443/a/b?q=one&x=two")
	want := "frame_example_test_8443_a_b_q_one_x_two"
	if got != want {
		t.Fatalf("sanitizeFilename() = %q, want %q", got, want)
	}

	long := sanitizeFilename("http://" + strings.Repeat("a", 120))
	if len(long) != len("frame_")+100 {
		t.Fatalf("sanitizeFilename(long URL) length = %d, want %d", len(long), len("frame_")+100)
	}
}

func TestEmbeddedFramerTemplate(t *testing.T) {
	got := getDefaultTemplate()
	if got == "" || !strings.Contains(got, "{FRAME}") || !strings.Contains(got, "{DATE}") || !strings.Contains(got, "{TIME}") {
		t.Fatalf("getDefaultTemplate() is missing required placeholders")
	}
	if inline := getInlineTemplate(); !strings.Contains(inline, "{FRAME}") {
		t.Error("getInlineTemplate() is missing {FRAME}")
	}
}

func TestParseRawRequestForFuzzer(t *testing.T) {
	raw := "POST /api/{ID} HTTP/1.1\r\nHost: example.test:8443\r\nX-Token: a:b:c\r\n\r\nline one\r\nline two"
	got, err := parseRawRequestForFuzzer(raw)
	if err != nil {
		t.Fatalf("parseRawRequestForFuzzer() error = %v", err)
	}
	if got.Method != "POST" || got.URL != "https://example.test:8443/api/{ID}" {
		t.Errorf("parsed method/URL = %q %q", got.Method, got.URL)
	}
	if got.Headers["X-Token"] != "a:b:c" || got.Body != "line one\r\nline two" {
		t.Errorf("parsed request = %#v", got)
	}
}

func TestParseRawRequestForFuzzerErrors(t *testing.T) {
	for _, tt := range []struct {
		name      string
		raw       string
		wantError string
	}{
		{name: "invalid line", raw: "GET", wantError: "invalid request line"},
		{name: "missing host", raw: "GET / HTTP/1.1\nAccept: */*", wantError: "no Host header"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRawRequestForFuzzer(tt.raw)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("parseRawRequestForFuzzer() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestScanDirectoryForURIs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		"index.html":                "index",
		"nested dir/config #1.yaml": "secret",
	} {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		if err := os.WriteFile(fullPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ScanDirectoryForURIs(root, "https://example.test/base/")
	if err != nil {
		t.Fatalf("ScanDirectoryForURIs() error = %v", err)
	}
	want := []string{
		"https://example.test/base/index.html",
		"https://example.test/base/nested%20dir/config%20%231.yaml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanDirectoryForURIs() = %#v, want %#v", got, want)
	}
}

func TestScanDirectoryForURIsMissingRoot(t *testing.T) {
	if _, err := ScanDirectoryForURIs(filepath.Join(t.TempDir(), "missing"), "https://example.test"); err == nil {
		t.Fatal("ScanDirectoryForURIs() error = nil for missing root")
	}
}
