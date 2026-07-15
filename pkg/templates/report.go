package templates

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ReportTemplate represents a YAML template for reporting findings
type ReportTemplate struct {
	Tag                      string   `yaml:"tag"`
	Name                     string   `yaml:"name"`
	OriginalRiskRating       string   `yaml:"original_risk_rating"`
	ClientDefinedRiskRating  string   `yaml:"client_defined_risk_rating"`
	Status                   string   `yaml:"status"`
	CVSSVector               string   `yaml:"cvss_vector"`
	NessusID                 int      `yaml:"nessus_id,omitempty"`
	OWASPID                  string   `yaml:"owasp_id,omitempty"`
	CVEs                     []string `yaml:"cves"`
	Finding                  string   `yaml:"finding"`
	Summary                  string   `yaml:"summary"`
	Recommendation           string   `yaml:"recommendation"`
	References               []string `yaml:"references"`
	AffectedHosts            []Host   `yaml:"affected_hosts"`
	TechnicalDetails         string   `yaml:"technical_details"`
}

// Host represents an affected host in the report
type Host struct {
	Hostname string `json:"hostname" yaml:"hostname"`
	IP       string `json:"ip" yaml:"ip"`
	Name     string `json:"name,omitempty" yaml:"name,omitempty"`
	Port     int    `json:"port" yaml:"port"`
}

// LoadReportTemplate loads a report template from a YAML file
func LoadReportTemplate(filename string) (*ReportTemplate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading report template file: %v", err)
	}

	var template ReportTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("error parsing report template YAML: %v", err)
	}

	// Validate required fields
	if template.Tag == "" {
		return nil, fmt.Errorf("report template missing required field: tag")
	}
	if template.Name == "" {
		return nil, fmt.Errorf("report template missing required field: name")
	}

	// Initialize empty slices if nil
	if template.CVEs == nil {
		template.CVEs = []string{}
	}
	if template.References == nil {
		template.References = []string{}
	}
	if template.AffectedHosts == nil {
		template.AffectedHosts = []Host{}
	}

	return &template, nil
}

// Finding represents a complete finding with all evidence
type Finding struct {
	Tag                     string   `json:"-"` // Used internally, not in JSON output
	Name                    string   `json:"name"`
	OriginalRiskRating      string   `json:"original_risk_rating"`
	ClientDefinedRiskRating string   `json:"client_defined_risk_rating"`
	Status                  string   `json:"status"`
	CVSSVector              string   `json:"cvss_vector"`
	NessusID                int      `json:"nessus_id,omitempty"`
	OWASPID                 string   `json:"owasp_id,omitempty"`
	CVEs                    []string `json:"cves"`
	Finding                 string   `json:"finding"`
	Summary                 string   `json:"summary"`
	Recommendation          string   `json:"recommendation"`
	References              []string `json:"references"`
	AffectedHosts           []Host   `json:"affected_hosts"`
	TechnicalDetails        string   `json:"technical_details"`
}

// ReportOutput represents the final JSON report structure
type ReportOutput struct {
	Issues  []Finding `json:"issues"`
	Version int       `json:"version"`
}

// NewReportOutput creates a new report output with version 1
func NewReportOutput() *ReportOutput {
	return &ReportOutput{
		Issues:  []Finding{},
		Version: 1,
	}
}

// AddFinding adds a finding to the report, grouping by tag
func (r *ReportOutput) AddFinding(template *ReportTemplate, host Host, evidence string) {
	// Check if finding already exists
	for i := range r.Issues {
		if r.Issues[i].Tag == template.Tag {
			// Add host to existing finding
			r.Issues[i].AffectedHosts = append(r.Issues[i].AffectedHosts, host)
			// Append evidence to technical_details
			r.Issues[i].TechnicalDetails += evidence
			return
		}
	}

	// Create new finding
	finding := Finding{
		Tag:                     template.Tag,
		Name:                    template.Name,
		OriginalRiskRating:      template.OriginalRiskRating,
		ClientDefinedRiskRating: template.ClientDefinedRiskRating,
		Status:                  template.Status,
		CVSSVector:              template.CVSSVector,
		NessusID:                template.NessusID,
		OWASPID:                 template.OWASPID,
		CVEs:                    template.CVEs,
		Finding:                 template.Finding,
		Summary:                 template.Summary,
		Recommendation:          template.Recommendation,
		References:              template.References,
		AffectedHosts:           []Host{host},
		TechnicalDetails:        evidence,
	}

	r.Issues = append(r.Issues, finding)
}
