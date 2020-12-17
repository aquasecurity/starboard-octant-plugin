package kubebench

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

// NewReport creates a new view component for displaying the specified CISKubeBenchReport.
func NewReport(kubeBenchReportsDefined bool, report *v1alpha1.CISKubeBenchReport) (flexLayout component.FlexLayout) {
	flexLayout = *component.NewFlexLayout("CIS Kubernetes Benchmark")

	if !kubeBenchReportsDefined {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"The `%[1]s` resource, which represents kube-bench reports, is not defined.\n"+
						"> You can create this resource definition by running the [Starboard CLI][starboard-cli] init command:\n"+
						"> ```\n"+
						"> $ kubectl starboard init\n"+
						"> ```\n"+
						"or\n"+
						"> ```\n"+
						"> $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/crd/ciskubebenchreports.crd.yaml\n"+
						"> ```\n"+
						"\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					v1alpha1.CISKubeBenchReportCRName,
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
					"> Note that [kube-bench] reports are represented by instances of the `ciskubebenchreports.aquasecurity.github.io` resource.\n" +
					"> You can create such a report by running [kube-bench] with [Starboard CLI][starboard-cli]:\n" +
					"> ```\n" +
					"> $ kubectl starboard scan ciskubebenchreports\n" +
					"> ```\n" +
					"\n" +
					"[kube-bench]: https://github.com/aquasecurity/kube-bench\n" +
					"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli"),
			},
		})
		return
	}

	uiSections := make([]component.FlexLayoutItem, len(report.Report.Sections))

	for i, section := range report.Report.Sections {
		uiSections[i] = component.FlexLayoutItem{
			Width: component.WidthFull,
			View:  createTableForSection(section),
		}
	}

	uiSections = append([]component.FlexLayoutItem{
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
			View:  NewCISKubeBenchSummary(report.Report.Summary),
		},
	}, uiSections...)

	flexLayout.AddSections(uiSections)
	return
}

func createTableForSection(section v1alpha1.CISKubeBenchSection) component.Component {
	table := component.NewTableWithRows(
		fmt.Sprintf("%s %s", section.ID, section.Text), "There are no results!",
		component.NewTableCols("Status", "Number", "Description", "Scored"),
		[]component.TableRow{})

	for _, test := range section.Tests {
		for _, result := range test.Results {

			tr := component.TableRow{
				"Status":      component.NewText(result.Status),
				"Number":      component.NewText(result.TestNumber),
				"Description": component.NewText(result.TestDesc),
				"Scored":      component.NewText(strconv.FormatBool(result.Scored)),
			}
			table.Add(tr)
		}
	}

	return table
}

func NewCISKubeBenchSummary(summary v1alpha1.CISKubeBenchSummary) (summaryComponent *component.Summary) {
	summaryComponent = component.NewSummary("Summary")

	summaryComponent.Add([]component.SummarySection{
		{Header: "PASS ", Content: component.NewText(strconv.Itoa(summary.PassCount))},
		{Header: "INFO", Content: component.NewText(strconv.Itoa(summary.InfoCount))},
		{Header: "WARN ", Content: component.NewText(strconv.Itoa(summary.WarnCount))},
		{Header: "FAIL ", Content: component.NewText(strconv.Itoa(summary.FailCount))},
	}...)
	return
}
