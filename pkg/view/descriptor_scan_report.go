package view

import (
	"fmt"
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewDescriptorScanReport(report *security.DescriptorScanReport) component.Component {
	flexLayout := component.NewFlexLayout("Descriptor Scan Report")

	flexLayout.AddSections([]component.FlexLayoutItem{{
		Width: component.WidthFull,
		View:  NewChecksReport("Pod Spec", report.Spec.Pod),
	}})

	var items []component.FlexLayoutItem
	for _, containerReport := range report.Spec.Containers {
		items = append(items, component.FlexLayoutItem{
			Width: component.WidthFull,
			View:  NewChecksReport(fmt.Sprintf("Container %s", containerReport.Name), containerReport.Checks),
		})
	}

	flexLayout.AddSections(items)

	return flexLayout
}

func NewChecksReport(name string, checks []security.DescriptorCheck) component.Component {
	table := component.NewTableWithRows(
		name,
		"Descriptor scan report",
		component.NewTableCols("CheckID", "Severity", "Description", "Result"),
		[]component.TableRow{})

	for _, check := range checks {
		table.Add(component.TableRow{
			"CheckID":     component.NewText(check.CheckID),
			"Severity":    component.NewText(check.Severity),
			"Description": component.NewText(check.Description),
			"Result":      component.NewText(check.Result),
		})
	}

	return table
}
