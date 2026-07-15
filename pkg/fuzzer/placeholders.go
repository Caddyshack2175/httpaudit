package fuzzer

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// LoadLinesFromFile reads all lines from a file, ignoring empty lines and comments
func LoadLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

// GenerateNumericRange generates a range of numbers with optional zero-padding
func GenerateNumericRange(rangeSpec string) ([]string, error) {
	// Parse format: "1-123" or "0001-9999"
	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format, use: start-end (e.g., 1-100 or 0001-9999)")
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid start number: %v", err)
	}

	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid end number: %v", err)
	}

	if start > end {
		return nil, fmt.Errorf("start must be <= end")
	}

	// Determine padding from the format
	padding := len(parts[0])
	if len(parts[1]) > padding {
		padding = len(parts[1])
	}

	// Generate range
	var result []string
	for i := start; i <= end; i++ {
		// Format with zero-padding if original had leading zeros
		if len(parts[0]) > 1 && parts[0][0] == '0' {
			result = append(result, fmt.Sprintf("%0*d", padding, i))
		} else {
			result = append(result, fmt.Sprintf("%d", i))
		}
	}

	return result, nil
}

// FindPlaceholders finds all {PLACEHOLDER} patterns in the template
func FindPlaceholders(template string) []string {
	re := regexp.MustCompile(`\{([A-Z_]+)\}`)
	matches := re.FindAllStringSubmatch(template, -1)

	seen := make(map[string]bool)
	var placeholders []string
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			placeholders = append(placeholders, match[1])
			seen[match[1]] = true
		}
	}

	return placeholders
}

// ReplacePlaceholders replaces all placeholders with their values
func ReplacePlaceholders(template string, values map[string]string) string {
	result := template
	for placeholder, value := range values {
		result = strings.ReplaceAll(result, "{"+placeholder+"}", value)
	}
	return result
}

// GenerateCombinations generates all combinations of placeholder values
func GenerateCombinations(placeholders []string, valueMap map[string][]string) []map[string]string {
	if len(placeholders) == 0 {
		return []map[string]string{{}}
	}

	var results []map[string]string

	// Recursive generation
	var generate func(int, map[string]string)
	generate = func(index int, current map[string]string) {
		if index == len(placeholders) {
			// Copy the map
			combo := make(map[string]string)
			for k, v := range current {
				combo[k] = v
			}
			results = append(results, combo)
			return
		}

		placeholder := placeholders[index]
		values := valueMap[placeholder]

		for _, value := range values {
			current[placeholder] = value
			generate(index+1, current)
		}
	}

	generate(0, make(map[string]string))
	return results
}