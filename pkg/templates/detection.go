package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DetectionTemplate represents a YAML template for detecting issues
type DetectionTemplate struct {
	ID    string                 `yaml:"id"`
	Info  DetectionInfo          `yaml:"info"`
	Paths []string               `yaml:"paths"`
	Match MatchCriteria          `yaml:"match"`
	NegativeMatch *MatchCriteria `yaml:"negative-match,omitempty"`
}

// DetectionInfo contains metadata about the detection
type DetectionInfo struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Tags        []string `yaml:"tags"`
	Description string   `yaml:"description,omitempty"`
}

// MatchCriteria defines what to match in headers and body
type MatchCriteria struct {
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    []string          `yaml:"body,omitempty"`
}

// LoadDetectionTemplate loads a detection template from a YAML file
func LoadDetectionTemplate(filename string) (*DetectionTemplate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading template file: %v", err)
	}

	var template DetectionTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("error parsing template YAML: %v", err)
	}

	// Validate required fields
	if template.ID == "" {
		return nil, fmt.Errorf("template missing required field: id")
	}
	if template.Info.Name == "" {
		return nil, fmt.Errorf("template missing required field: info.name")
	}

	return &template, nil
}

// LoadDetectionTemplates loads all templates from a directory
func LoadDetectionTemplates(dir string) ([]*DetectionTemplate, error) {
	var templates []*DetectionTemplate

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("error reading template directory: %v", err)
	}

	if len(files) == 0 {
		// Also try .yml extension
		files, err = filepath.Glob(filepath.Join(dir, "*.yml"))
		if err != nil {
			return nil, fmt.Errorf("error reading template directory: %v", err)
		}
	}

	for _, file := range files {
		template, err := LoadDetectionTemplate(file)
		if err != nil {
			return nil, fmt.Errorf("error loading template %s: %v", file, err)
		}
		templates = append(templates, template)
	}

	return templates, nil
}

// HasTag checks if the template has a specific tag
func (t *DetectionTemplate) HasTag(tag string) bool {
	for _, t := range t.Info.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// HasAnyTag checks if the template has any of the specified tags
func (t *DetectionTemplate) HasAnyTag(tags []string) bool {
	for _, tag := range tags {
		if t.HasTag(tag) {
			return true
		}
	}
	return false
}

// GetTagsString returns a comma-separated string of tags
func (t *DetectionTemplate) GetTagsString() string {
	return strings.Join(t.Info.Tags, ",")
}
