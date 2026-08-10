package fuzzer

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadLinesFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "values.txt")
	contents := "\n # ignored comment\n alpha \n\t\n beta\n#another comment\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadLinesFromFile(path)
	if err != nil {
		t.Fatalf("LoadLinesFromFile() error = %v", err)
	}
	want := []string{"alpha", "beta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadLinesFromFile() = %#v, want %#v", got, want)
	}
}

func TestLoadLinesFromFileErrors(t *testing.T) {
	if _, err := LoadLinesFromFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("LoadLinesFromFile() error = nil for a missing file")
	}

	path := filepath.Join(t.TempDir(), "long-line.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 70*1024)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLinesFromFile(path); err == nil {
		t.Fatal("LoadLinesFromFile() error = nil for a line exceeding bufio.Scanner's limit")
	}
}

func TestGenerateNumericRange(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		want      []string
		wantError string
	}{
		{name: "ordinary", spec: "1-3", want: []string{"1", "2", "3"}},
		{name: "single value", spec: "7-7", want: []string{"7"}},
		{name: "zero padded", spec: "0008-0010", want: []string{"0008", "0009", "0010"}},
		{name: "invalid format", spec: "1", wantError: "invalid range format"},
		{name: "too many separators", spec: "1-2-3", wantError: "invalid range format"},
		{name: "invalid start", spec: "a-2", wantError: "invalid start number"},
		{name: "invalid end", spec: "1-b", wantError: "invalid end number"},
		{name: "descending", spec: "3-1", wantError: "start must be <= end"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateNumericRange(tt.spec)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("GenerateNumericRange(%q) error = %v, want containing %q", tt.spec, err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("GenerateNumericRange(%q) error = %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("GenerateNumericRange(%q) = %#v, want %#v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestFindAndReplacePlaceholders(t *testing.T) {
	template := "GET /users/{USER}/docs/{DOC_ID}?owner={USER}&ignored={lower}&number={ID1}"
	if got, want := FindPlaceholders(template), []string{"USER", "DOC_ID"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("FindPlaceholders() = %#v, want %#v", got, want)
	}

	got := ReplacePlaceholders(template, map[string]string{
		"USER":   "alice",
		"DOC_ID": "42",
	})
	want := "GET /users/alice/docs/42?owner=alice&ignored={lower}&number={ID1}"
	if got != want {
		t.Fatalf("ReplacePlaceholders() = %q, want %q", got, want)
	}
}

func TestGenerateCombinations(t *testing.T) {
	got := GenerateCombinations(
		[]string{"USER", "ID"},
		map[string][]string{
			"USER": {"alice", "bob"},
			"ID":   {"1", "2"},
		},
	)
	want := []map[string]string{
		{"USER": "alice", "ID": "1"},
		{"USER": "alice", "ID": "2"},
		{"USER": "bob", "ID": "1"},
		{"USER": "bob", "ID": "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GenerateCombinations() = %#v, want %#v", got, want)
	}

	empty := GenerateCombinations(nil, nil)
	if wantEmpty := []map[string]string{{}}; !reflect.DeepEqual(empty, wantEmpty) {
		t.Fatalf("GenerateCombinations(nil, nil) = %#v, want %#v", empty, wantEmpty)
	}

	if got := GenerateCombinations([]string{"MISSING"}, map[string][]string{}); len(got) != 0 {
		t.Fatalf("GenerateCombinations() with no values = %#v, want no combinations", got)
	}
}
