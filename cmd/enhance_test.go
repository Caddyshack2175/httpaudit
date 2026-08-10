package cmd

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"httpaudit/pkg/templates"
)

func TestAddMetadataToTemplateCreatesAndUpdatesMetadata(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(`
id: example
info:
  name: Example
  metadata:
    report_status: Old
`), &root); err != nil {
		t.Fatal(err)
	}

	finding := &templates.Finding{
		OriginalRiskRating:      "High",
		ClientDefinedRiskRating: "Medium",
		Status:                  "Confirmed",
		CVSSVector:              "CVSS:3.1/example",
		NessusID:                1234,
		OWASPID:                 "WSTG-CONF-01",
		Finding:                 "line one\n\n\nline two",
		Summary:                 "summary",
		Recommendation:          "recommendation",
		CVEs:                    []string{"CVE-2024-0001"},
		References:              []string{"https://example.test/reference"},
	}
	if err := addMetadataToTemplate(&root, finding); err != nil {
		t.Fatalf("addMetadataToTemplate() error = %v", err)
	}

	var decoded struct {
		Info struct {
			Metadata map[string]interface{} `yaml:"metadata"`
		} `yaml:"info"`
	}
	data, err := yaml.Marshal(&root)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	metadata := decoded.Info.Metadata
	if metadata["report_status"] != "Confirmed" || metadata["report_original_risk_rating"] != "High" {
		t.Errorf("metadata values = %#v", metadata)
	}
	if metadata["report_nessus_id"] != 1234 {
		t.Errorf("report_nessus_id = %#v", metadata["report_nessus_id"])
	}
	if metadata["report_finding"] != "line one\nline two" {
		t.Errorf("report_finding = %#v", metadata["report_finding"])
	}
	if !strings.Contains(string(data), "report_cves:") || !strings.Contains(string(data), "report_references:") {
		t.Errorf("marshaled metadata is missing arrays:\n%s", data)
	}
}

func TestAddMetadataToTemplateCreatesInfoAndEmptyCVEs(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("id: example\n"), &root); err != nil {
		t.Fatal(err)
	}
	if err := addMetadataToTemplate(&root, &templates.Finding{}); err != nil {
		t.Fatalf("addMetadataToTemplate() error = %v", err)
	}
	data, err := yaml.Marshal(&root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "info:") || !strings.Contains(string(data), "report_cves: []") {
		t.Errorf("marshaled YAML =\n%s", data)
	}
	if strings.Contains(string(data), "report_references:") {
		t.Errorf("empty references should not be emitted:\n%s", data)
	}
}

func TestAddMetadataToTemplateRejectsInvalidStructure(t *testing.T) {
	if err := addMetadataToTemplate(&yaml.Node{}, &templates.Finding{}); err == nil || !strings.Contains(err.Error(), "invalid YAML document") {
		t.Fatalf("empty root error = %v", err)
	}
	root := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.SequenceNode}}}
	if err := addMetadataToTemplate(root, &templates.Finding{}); err == nil || !strings.Contains(err.Error(), "expected mapping") {
		t.Fatalf("sequence root error = %v", err)
	}
}

func TestYAMLNodeHelpers(t *testing.T) {
	mapping := &yaml.Node{Kind: yaml.MappingNode}
	child := findOrCreateMapNode(mapping, "metadata")
	if child == nil || child.Kind != yaml.MappingNode {
		t.Fatalf("findOrCreateMapNode() = %#v", child)
	}
	if again := findOrCreateMapNode(mapping, "metadata"); again != child || len(mapping.Content) != 2 {
		t.Error("findOrCreateMapNode() did not reuse existing node")
	}
	if got := findOrCreateMapNode(&yaml.Node{Kind: yaml.SequenceNode}, "bad"); got != nil {
		t.Errorf("findOrCreateMapNode(non-map) = %#v, want nil", got)
	}

	setStringValue(mapping, "text", "one\n\n\ntwo")
	setStringValue(mapping, "text", "updated")
	setIntValue(mapping, "number", 7)
	setIntValue(mapping, "number", 8)
	setStringArrayValue(mapping, "items", []string{"a", "b"})
	setStringArrayValue(mapping, "items", nil)

	data, err := yaml.Marshal(mapping)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"text: updated", "number: 8", "items: []"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("helper output missing %q:\n%s", want, data)
		}
	}
}

func TestNewlineCompactionHelpers(t *testing.T) {
	if got := removeExcessiveNewlines("one\n\n\nthree"); got != "one\nthree" {
		t.Errorf("removeExcessiveNewlines() = %q", got)
	}
	if got := compactMultilineString("one\n\n\n two \n\n"); got != "one\n\n two " {
		t.Errorf("compactMultilineString() = %q", got)
	}
	if got := compactMultilineString("single line"); got != "single line" {
		t.Errorf("compactMultilineString(single line) = %q", got)
	}
}
