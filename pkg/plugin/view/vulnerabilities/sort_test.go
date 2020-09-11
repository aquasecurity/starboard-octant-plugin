package vulnerabilities

import (
	"sort"
	"testing"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestBySeverity(t *testing.T) {
	items := []starboard.Vulnerability{
		{VulnerabilityID: "CVE-0000-0001", Severity: starboard.SeverityLow},
		{VulnerabilityID: "CVE-0000-0002", Severity: starboard.SeverityMedium},
		{VulnerabilityID: "CVE-0000-0003", Severity: starboard.SeverityMedium},
		{VulnerabilityID: "CVE-0000-0004", Severity: starboard.SeverityCritical},
		{VulnerabilityID: "CVE-0000-0005", Severity: starboard.SeverityHigh},
		{VulnerabilityID: "CVE-0000-0006", Severity: starboard.SeverityHigh},
	}

	sort.Stable(BySeverity{items})

	assert.Equal(t, []starboard.Vulnerability{
		{VulnerabilityID: "CVE-0000-0004", Severity: starboard.SeverityCritical},
		{VulnerabilityID: "CVE-0000-0005", Severity: starboard.SeverityHigh},
		{VulnerabilityID: "CVE-0000-0006", Severity: starboard.SeverityHigh},
		{VulnerabilityID: "CVE-0000-0002", Severity: starboard.SeverityMedium},
		{VulnerabilityID: "CVE-0000-0003", Severity: starboard.SeverityMedium},
		{VulnerabilityID: "CVE-0000-0001", Severity: starboard.SeverityLow},
	}, items)

}
