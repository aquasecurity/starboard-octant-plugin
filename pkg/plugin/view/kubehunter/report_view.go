package kubehunter

import (
	"strconv"

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
			Width: component.WidthThird,
			View:  NewKubeHunterReportSummary(report),
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

func NewKubeHunterReportSummary(report *starboard.KubeHunterReport) (summary *component.Summary) {
	totalHigh := 0
	totalMedium := 0
	totalLow := 0

	for _, section := range report.Report.Vulnerabilities {
		totalHigh += map[bool]int{true: 1, false: 0}[section.Severity == "high"]
		totalMedium += map[bool]int{true: 1, false: 0}[section.Severity == "medium"]
		totalLow += map[bool]int{true: 1, false: 0}[section.Severity == "low"]
		println(section.Severity)
	}

	summary = component.NewSummary("Summary")

	summary.Add([]component.SummarySection{
		{Header: "High ", Content: component.NewText(strconv.Itoa(totalHigh))},
		{Header: "Medium ", Content: component.NewText(strconv.Itoa(totalMedium))},
		{Header: "Low ", Content: component.NewText(strconv.Itoa(totalLow))},
	}...)
	return
}
