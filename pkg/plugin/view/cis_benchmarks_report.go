package view

import (
	"fmt"
	"strconv"

	sec "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewCISKubernetesBenchmarksReport(benchmark sec.CISKubernetesBenchmark) (flexLayout component.FlexLayout) {
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
			View:  NewCISKubernetesBenchmarksSummary(benchmark),
		},
	}, uiSections...)

	flexLayout.AddSections(uiSections)
	return
}

func createTableForSection(section sec.CISKubernetesBenchmarkSection) component.Component {
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
func NewCISKubernetesBenchmarksSummary(_ sec.CISKubernetesBenchmark) (c *component.Summary) {
	c = component.NewSummary("Summary")

	sections := []component.SummarySection{
		{Header: "PASS ", Content: component.NewText(strconv.Itoa(30))},
		{Header: "WARN ", Content: component.NewText(strconv.Itoa(10))},
		{Header: "FAIL ", Content: component.NewText(strconv.Itoa(12))},
	}
	c.Add(sections...)
	return
}
