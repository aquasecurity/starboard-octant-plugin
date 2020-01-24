package view

import (
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewDescriptorScanReport(report *security.DescriptorScanReport) component.Component {
	table := component.NewTableWithRows(
		"Descriptor Scan Report",
		"Descriptor scan report",
		component.NewTableCols("CheckID", "Severity", "Description"),
		[]component.TableRow{})
	if report != nil {
		for _, check := range report.Spec.Checks {
			table.Add(component.TableRow{
				"CheckID":     component.NewText(check.CheckID),
				"Severity":    component.NewText(check.Severity),
				"Description": component.NewText(check.Description),
			})
		}
	}
	return table
}
