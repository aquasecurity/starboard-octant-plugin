package vulnerabilities

import (
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type VulnerabilityItems []starboard.VulnerabilityItem

func (s VulnerabilityItems) Len() int { return len(s) }

func (s VulnerabilityItems) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// BySeverity implements sort.Interface by providing Less and using the Len and
// Swap methods of the embedded VulnerabilityItems value.
type BySeverity struct{ VulnerabilityItems }

var severityOrder = map[starboard.Severity]int{
	starboard.SeverityCritical: 5,
	starboard.SeverityHigh:     4,
	starboard.SeverityMedium:   3,
	starboard.SeverityLow:      2,
	starboard.SeverityUnknown:  1,
}

func (s BySeverity) Less(i, j int) bool {
	return severityOrder[s.VulnerabilityItems[i].Severity] > severityOrder[s.VulnerabilityItems[j].Severity]
}
