package view

import (
	"fmt"
	"strconv"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewCISKubeBenchReport(benchmark *starboard.CISKubeBenchReport) (flexLayout component.FlexLayout) {
	flexLayout = *component.NewFlexLayout("CIS Kubernetes Benchmark")
	uiSections := make([]component.FlexLayoutItem, len(benchmark.Report.Sections))

	for i, section := range benchmark.Report.Sections {
		uiSections[i] = component.FlexLayoutItem{
			Width: component.WidthFull,
			View:  createTableForSection(section),
		}
	}

	uiSections = append([]component.FlexLayoutItem{
		{
			Width: component.WidthThird,
			View:  NewReportSummary(benchmark.Report.GeneratedAt.Time),
		},
		{
			Width: component.WidthThird,
			View:  NewScannerSummary(benchmark.Report.Scanner),
		},
		{
			Width: component.WidthThird,
			View:  NewCISKubeBenchReportSummary(benchmark),
		},
	}, uiSections...)

	flexLayout.AddSections(uiSections)
	return
}

func createTableForSection(section starboard.CISKubeBenchSection) component.Component {
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

// TODO Implement summary counting
func NewCISKubeBenchReportSummary(report *starboard.CISKubeBenchReport) (summary *component.Summary) {
	totalPass := 0
	totalInfo := 0
	totalWarn := 0
	totalFail := 0

	for _, section := range report.Report.Sections {
		totalPass += section.TotalPass
		totalInfo += section.TotalInfo
		totalWarn += section.TotalWarn
		totalFail += section.TotalFail
	}

	summary = component.NewSummary("Summary")

	summary.Add([]component.SummarySection{
		{Header: "PASS ", Content: component.NewText(strconv.Itoa(totalPass))},
		{Header: "INFO", Content: component.NewText(strconv.Itoa(totalInfo))},
		{Header: "WARN ", Content: component.NewText(strconv.Itoa(totalWarn))},
		{Header: "FAIL ", Content: component.NewText(strconv.Itoa(totalFail))},
	}...)
	return
}
