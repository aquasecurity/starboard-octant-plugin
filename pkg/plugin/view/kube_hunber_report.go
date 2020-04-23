package view

import (
	sec "github.com/aquasecurity/starboard-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewKubeHunterReport(report sec.KubeHunterOutput) (flexLayout *component.FlexLayout) {
	flexLayout = component.NewFlexLayout("Kube Hunter Report")

	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthThird,
			View:  NewReportSummary(report.GeneratedAt.Time),
		},
		{
			Width: component.WidthThird,
			View:  NewScannerSummary(report.Scanner),
		},
		{
			Width: component.WidthFull,
			View:  createTable(report),
		},
	})
	return
}

const (
	columnSeverity      = "Severity"
	columnID            = "ID"
	columnVulnerability = "Vulnerability"
	columnCategory      = "Category"
	columnHunter        = "Hunter"
	columnLocation      = "Location"
)

func createTable(section sec.KubeHunterOutput) component.Component {
	table := component.NewTableWithRows(
		"", "There are no vulnerabilities!",
		component.NewTableCols(columnSeverity, columnID, columnVulnerability, columnCategory, columnHunter, columnLocation),
		[]component.TableRow{})

	for _, v := range section.Vulnerabilities {
		tr := component.TableRow{
			columnSeverity:      component.NewText(v.Severity),
			columnID:            component.NewText(v.ID),
			columnVulnerability: component.NewText(v.Vulnerability),
			columnCategory:      component.NewText(v.Category),
			columnHunter:        component.NewText(v.Hunter),
			columnLocation:      component.NewText(v.Location),
		}
		table.Add(tr)
	}

	return table
}
