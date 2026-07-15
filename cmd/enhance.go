package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"httpaudit/pkg/templates"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var enhanceCmd = &cobra.Command{
	Use:   "enhance-template",
	Short: "Enhance Nuclei template with report metadata from JSON report",
	Long: `Takes a JSON report and adds enhanced reporting metadata to a Nuclei template.
This allows you to create professional report templates from existing findings.`,
	RunE: runEnhance,
}

var (
	enhanceReport   string
	enhanceTemplate string
	enhanceName     string
	enhanceOutput   string
)

func init() {
	rootCmd.AddCommand(enhanceCmd)

	enhanceCmd.Flags().StringVar(&enhanceReport, "report", "", "JSON report file to extract metadata from (required)")
	enhanceCmd.Flags().StringVar(&enhanceTemplate, "template", "", "Nuclei template file to enhance (required)")
	enhanceCmd.Flags().StringVar(&enhanceName, "name", "", "Finding name to extract from report (required)")
	enhanceCmd.Flags().StringVarP(&enhanceOutput, "output", "o", "", "Output template file (default: overwrites input template)")

	enhanceCmd.MarkFlagRequired("report")
	enhanceCmd.MarkFlagRequired("template")
	enhanceCmd.MarkFlagRequired("name")
}

func runEnhance(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Read JSON report
	reportData, err := os.ReadFile(enhanceReport)
	if err != nil {
		return fmt.Errorf("error reading report file: %v", err)
	}

	var report templates.ReportOutput
	if err := json.Unmarshal(reportData, &report); err != nil {
		return fmt.Errorf("error parsing report JSON: %v", err)
	}

	// Find the finding matching the name
	var targetFinding *templates.Finding
	for i := range report.Issues {
		if report.Issues[i].Name == enhanceName {
			targetFinding = &report.Issues[i]
			break
		}
	}

	if targetFinding == nil {
		return fmt.Errorf("no finding found with name '%s' in report", enhanceName)
	}

	if !quiet {
		fmt.Printf("[*] Found finding: %s\n", targetFinding.Name)
	}

	// Read Nuclei template
	templateData, err := os.ReadFile(enhanceTemplate)
	if err != nil {
		return fmt.Errorf("error reading template file: %v", err)
	}

	// Parse YAML
	var templateNode yaml.Node
	if err := yaml.Unmarshal(templateData, &templateNode); err != nil {
		return fmt.Errorf("error parsing template YAML: %v", err)
	}

	// Add/update metadata in the YAML structure
	if err := addMetadataToTemplate(&templateNode, targetFinding); err != nil {
		return fmt.Errorf("error adding metadata: %v", err)
	}

	// Marshal back to YAML with 2-space indent
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&templateNode); err != nil {
		return fmt.Errorf("error marshaling enhanced template: %v", err)
	}
	encoder.Close()
	enhancedData := buf.Bytes()

	// Determine output file
	outputFile := enhanceOutput
	if outputFile == "" {
		outputFile = enhanceTemplate
	}

	// Write enhanced template
	if err := os.WriteFile(outputFile, enhancedData, 0644); err != nil {
		return fmt.Errorf("error writing enhanced template: %v", err)
	}

	if !quiet {
		fmt.Printf("[✓] Enhanced template written to: %s\n", outputFile)
		fmt.Printf("[*] Added metadata fields:\n")
		fmt.Printf("    - report_original_risk_rating: %s\n", targetFinding.OriginalRiskRating)
		fmt.Printf("    - report_cvss_vector: %s\n", targetFinding.CVSSVector)
		fmt.Printf("    - report_owasp_id: %s\n", targetFinding.OWASPID)
		fmt.Printf("    - report_nessus_id: %d\n", targetFinding.NessusID)
		fmt.Printf("    - report_finding: <%d chars>\n", len(targetFinding.Finding))
		fmt.Printf("    - report_summary: <%d chars>\n", len(targetFinding.Summary))
		fmt.Printf("    - report_recommendation: <%d chars>\n", len(targetFinding.Recommendation))
		if len(targetFinding.CVEs) > 0 {
			fmt.Printf("    - report_cves: %v\n", targetFinding.CVEs)
		}
		if len(targetFinding.References) > 0 {
			fmt.Printf("    - report_references: %d items\n", len(targetFinding.References))
		}
	}

	return nil
}

// addMetadataToTemplate adds report metadata to the YAML template structure
func addMetadataToTemplate(root *yaml.Node, finding *templates.Finding) error {
	// Navigate to the document root
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return fmt.Errorf("invalid YAML document structure")
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node at document root")
	}

	// Find or create 'info' node
	infoNode := findOrCreateMapNode(doc, "info")
	if infoNode == nil {
		return fmt.Errorf("could not find or create 'info' node")
	}

	// Find or create 'metadata' node under 'info'
	metadataNode := findOrCreateMapNode(infoNode, "metadata")
	if metadataNode == nil {
		return fmt.Errorf("could not find or create 'metadata' node")
	}

	// Add/update metadata fields
	setStringValue(metadataNode, "report_original_risk_rating", finding.OriginalRiskRating)
	setStringValue(metadataNode, "report_client_defined_risk_rating", finding.ClientDefinedRiskRating)
	setStringValue(metadataNode, "report_status", finding.Status)
	setStringValue(metadataNode, "report_cvss_vector", finding.CVSSVector)
	setIntValue(metadataNode, "report_nessus_id", finding.NessusID)
	setStringValue(metadataNode, "report_owasp_id", finding.OWASPID)
	setStringValue(metadataNode, "report_finding", finding.Finding)
	setStringValue(metadataNode, "report_summary", finding.Summary)
	setStringValue(metadataNode, "report_recommendation", finding.Recommendation)

	// Add arrays (always include CVEs even if empty, references only if present)
	setStringArrayValue(metadataNode, "report_cves", finding.CVEs)
	if len(finding.References) > 0 {
		setStringArrayValue(metadataNode, "report_references", finding.References)
	}

	return nil
}

// findOrCreateMapNode finds or creates a key in a mapping node
func findOrCreateMapNode(parent *yaml.Node, key string) *yaml.Node {
	if parent.Kind != yaml.MappingNode {
		return nil
	}

	// Search for existing key
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}

	// Create new key-value pair
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: key,
	}
	valueNode := &yaml.Node{
		Kind: yaml.MappingNode,
	}

	parent.Content = append(parent.Content, keyNode, valueNode)
	return valueNode
}

// setStringValue sets or updates a string value in a mapping node
func setStringValue(parent *yaml.Node, key, value string) {
	if parent.Kind != yaml.MappingNode {
		return
	}

	// Remove excessive blank lines from HTML content
	value = removeExcessiveNewlines(value)

	// Determine style
	var style yaml.Style
	if strings.Contains(value, "\n") {
		style = yaml.LiteralStyle // Use | for multiline
	} else {
		style = 0 // Plain style for single-line
	}

	// Search for existing key
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			// Update existing value
			parent.Content[i+1].Value = value
			parent.Content[i+1].Style = style
			return
		}
	}

	// Create new key-value pair
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: key,
	}
	valueNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: value,
		Style: style,
	}

	parent.Content = append(parent.Content, keyNode, valueNode)
}

// removeExcessiveNewlines removes multiple consecutive newlines, keeping only one
func removeExcessiveNewlines(s string) string {
	// Replace multiple newlines with single newline
	re := regexp.MustCompile(`\n\n+`)
	return re.ReplaceAllString(s, "\n")
}

// compactMultilineString removes excessive blank lines from strings
func compactMultilineString(s string) string {
	// Only process if contains newlines
	if !strings.Contains(s, "\n") {
		return s
	}

	lines := strings.Split(s, "\n")
	var result []string
	prevBlank := false

	for _, line := range lines {
		isBlank := strings.TrimSpace(line) == ""

		// Skip consecutive blank lines (keep only one)
		if isBlank && prevBlank {
			continue
		}

		result = append(result, line)
		prevBlank = isBlank
	}

	// Remove trailing blank lines
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}

	return strings.Join(result, "\n")
}

// setIntValue sets or updates an integer value in a mapping node
func setIntValue(parent *yaml.Node, key string, value int) {
	if parent.Kind != yaml.MappingNode {
		return
	}

	valueStr := fmt.Sprintf("%d", value)

	// Search for existing key
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			// Update existing value
			parent.Content[i+1].Value = valueStr
			parent.Content[i+1].Tag = "!!int"
			return
		}
	}

	// Create new key-value pair
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: key,
	}
	valueNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: valueStr,
		Tag:   "!!int",
	}

	parent.Content = append(parent.Content, keyNode, valueNode)
}

// setStringArrayValue sets or updates a string array in a mapping node
func setStringArrayValue(parent *yaml.Node, key string, values []string) {
	if parent.Kind != yaml.MappingNode {
		return
	}

	// Create sequence node (flow style for empty arrays to ensure they appear as [])
	seqNode := &yaml.Node{
		Kind: yaml.SequenceNode,
	}

	// If empty array, use flow style to ensure it renders as []
	if len(values) == 0 {
		seqNode.Style = yaml.FlowStyle
	}

	for _, v := range values {
		seqNode.Content = append(seqNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: v,
		})
	}

	// Search for existing key
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			// Replace existing value
			parent.Content[i+1] = seqNode
			return
		}
	}

	// Create new key-value pair
	keyNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: key,
	}

	parent.Content = append(parent.Content, keyNode, seqNode)
}
