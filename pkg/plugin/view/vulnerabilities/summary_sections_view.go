package vulnerabilities

import (
	"strconv"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewSummarySections(summary *v1alpha1.VulnerabilitySummary) []component.SummarySection {
	if summary == nil {
		return []component.SummarySection{}
	}
	return []component.SummarySection{
		{Header: "Critical Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.CriticalCount))},
		{Header: "High Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.HighCount))},
		{Header: "Medium Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.MediumCount))},
		{Header: "Low Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.LowCount))},
		{Header: "Unknown Vulnerabilities", Content: component.NewText(strconv.Itoa(summary.UnknownCount))},
	}
}
