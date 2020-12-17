package kubehunter

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

// NewReport creates a new view component for displaying the specified KubeHunterReport.
func NewReport(kubeHunterReportsDefined bool, report *starboard.KubeHunterReport) (flexLayout *component.FlexLayout) {
	flexLayout = component.NewFlexLayout("kube-hunter Report")

	if !kubeHunterReportsDefined {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"The `%[1]s` resource, which represents kube-hunter reports, is not defined.\n"+
						"> You can create this resource definition by running the [Starboard CLI][starboard-cli] init command:\n"+
						"> ```\n"+
						"> $ kubectl starboard init\n"+
						"> ```\n"+
						"or\n"+
						"> ```\n"+
						"> $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/crd/kubehunterreports.crd.yaml\n"+
						"> ```\n"+
						"\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					starboard.KubeHunterReportCRName,
				)),
			},
		})
		return
	}

	if report == nil {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText("This report is not available.\n" +
					"> Note that [kube-hunter] reports are represented by instances of the `kubehunterreports.aquasecurity.github.io` resource.\n" +
					"> You can create such a report by running [kube-hunter] with [Starboard CLI][starboard-cli]:\n" +
					"> ```\n" +
					"> $ kubectl starboard scan kubehunterreports\n" +
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
			View:  view.NewReportMetadata(report.ObjectMeta),
		},
		{
			Width: component.WidthThird,
			View:  view.NewScannerSummary(report.Report.Scanner),
		},
		{
			Width: component.WidthThird,
			View:  NewKubeHunterReportSummary(report.Report.Summary),
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
			columnSeverity:      component.NewText(string(v.Severity)),
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

func NewKubeHunterReportSummary(summary starboard.KubeHunterSummary) (componentSummary *component.Summary) {
	componentSummary = component.NewSummary("Summary", []component.SummarySection{
		{Header: "high ", Content: component.NewText(strconv.Itoa(summary.HighCount))},
		{Header: "medium ", Content: component.NewText(strconv.Itoa(summary.MediumCount))},
		{Header: "low ", Content: component.NewText(strconv.Itoa(summary.LowCount))},
	}...)
	return
}
