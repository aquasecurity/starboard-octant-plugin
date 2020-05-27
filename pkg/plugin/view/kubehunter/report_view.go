package kubehunter

import (
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

// NewReport creates a new view component for displaying the specified KubeHunerReport.
func NewReport(report *starboard.KubeHunterReport) (flexLayout *component.FlexLayout) {

	flexLayout = component.NewFlexLayout("kube-hunter Report")
	if report == nil {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText("This report is not available.\n" +
					"> Note that [kube-hunter] reports are represented by instances of the `kubehunterreports.aquasecurity.github.io` resource.\n" +
					"> You can create such a report by running [kube-hunter] with [Starboard CLI][starboard-cli]:\n" +
					"> ```\n" +
					"> $ starboard kube-hunter\n" +
					"> ```\n" +
					"\n" +
					"[kube-hunter]: https://github.com/aquasecurity/kube-hunter\n" +
					"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli"),
			},
		})
		return
	}

	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthThird,
			View:  view.NewReportSummary(report.CreationTimestamp.Time),
		},
		{
			Width: component.WidthThird,
			View:  view.NewScannerSummary(report.Report.Scanner),
		},
		{
			Width: component.WidthFull,
			View:  createTable(report.Report),
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

func createTable(section starboard.KubeHunterOutput) component.Component {
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
