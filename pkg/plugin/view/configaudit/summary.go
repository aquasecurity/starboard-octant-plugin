package configaudit

import (
	"strconv"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewSummarySections(summary *v1alpha1.ConfigAuditSummary) []component.SummarySection {
	if summary == nil {
		return []component.SummarySection{}
	}
	return []component.SummarySection{
		{Header: "Audit Risks", Content: component.NewText(strconv.Itoa(summary.DangerCount))},
		{Header: "Audit Warnings", Content: component.NewText(strconv.Itoa(summary.WarningCount))},
	}
}
