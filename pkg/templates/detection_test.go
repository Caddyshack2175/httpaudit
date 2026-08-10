package templates

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTemplateFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDetectionTemplateAndTags(t *testing.T) {
	path := writeTemplateFile(t, t.TempDir(), "detect.yaml", `
id: admin-panel
info:
  name: Admin panel exposed
  severity: medium
  tags: [admin, exposure]
  description: Detects an exposed admin panel
paths: [/admin]
match:
  headers:
    Server: '(?i)example'
  body: ['Admin Login']
negative-match:
  body: ['not found']
`)

	got, err := LoadDetectionTemplate(path)
	if err != nil {
		t.Fatalf("LoadDetectionTemplate() error = %v", err)
	}
	if got.ID != "admin-panel" || got.Info.Name != "Admin panel exposed" {
		t.Fatalf("unexpected template: %#v", got)
	}
	if !reflect.DeepEqual(got.Paths, []string{"/admin"}) {
		t.Errorf("Paths = %#v", got.Paths)
	}
	if !got.HasTag("admin") || got.HasTag("missing") {
		t.Errorf("HasTag() returned unexpected results for %#v", got.Info.Tags)
	}
	if !got.HasAnyTag([]string{"missing", "exposure"}) || got.HasAnyTag([]string{"one", "two"}) {
		t.Errorf("HasAnyTag() returned unexpected results")
	}
	if got.GetTagsString() != "admin,exposure" {
		t.Errorf("GetTagsString() = %q", got.GetTagsString())
	}
}

func TestLoadDetectionTemplateErrors(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		wantError string
	}{
		{name: "invalid yaml", contents: "info: [", wantError: "error parsing template YAML"},
		{name: "missing id", contents: "info:\n  name: test\n", wantError: "missing required field: id"},
		{name: "missing name", contents: "id: test\ninfo: {}\n", wantError: "missing required field: info.name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemplateFile(t, t.TempDir(), "template.yaml", tt.contents)
			_, err := LoadDetectionTemplate(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("LoadDetectionTemplate() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}

	if _, err := LoadDetectionTemplate(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("LoadDetectionTemplate() error = nil for missing file")
	}
}

func TestLoadDetectionTemplates(t *testing.T) {
	dir := t.TempDir()
	writeTemplateFile(t, dir, "one.yaml", "id: one\ninfo:\n  name: One\n")
	writeTemplateFile(t, dir, "two.yaml", "id: two\ninfo:\n  name: Two\n")
	writeTemplateFile(t, dir, "ignored.txt", "not yaml")

	got, err := LoadDetectionTemplates(dir)
	if err != nil {
		t.Fatalf("LoadDetectionTemplates() error = %v", err)
	}
	if len(got) != 2 || got[0].ID != "one" || got[1].ID != "two" {
		t.Fatalf("LoadDetectionTemplates() = %#v", got)
	}

	ymlDir := t.TempDir()
	writeTemplateFile(t, ymlDir, "only.yml", "id: yml\ninfo:\n  name: YML\n")
	got, err = LoadDetectionTemplates(ymlDir)
	if err != nil || len(got) != 1 || got[0].ID != "yml" {
		t.Fatalf("LoadDetectionTemplates(.yml) = %#v, %v", got, err)
	}
}

func TestLoadDetectionTemplatesReturnsInvalidTemplateError(t *testing.T) {
	dir := t.TempDir()
	writeTemplateFile(t, dir, "bad.yaml", "info:\n  name: Missing ID\n")
	_, err := LoadDetectionTemplates(dir)
	if err == nil || !strings.Contains(err.Error(), "error loading template") {
		t.Fatalf("LoadDetectionTemplates() error = %v", err)
	}
}
