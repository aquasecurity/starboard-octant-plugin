package configaudit

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewReport(report *starboard.ConfigAuditReport) (flexLayout *component.FlexLayout) {
	flexLayout = component.NewFlexLayout("")
	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthFull,
			View:  component.NewMarkdownText("#### Config Audit Reports"),
		},
	})

	if report == nil {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"These reports are not available.\n"+
						"> Note that configuration audit reports are represented by instances of the `%[1]s` resource.\n"+
						"> You can create such reports by running [Polaris][polaris] with [Starboard CLI][starboard-cli]:\n"+
						"> ```\n"+
						"> $ starboard polaris\n"+
						"> ```\n"+
						"\n"+
						"[polaris]: https://www.fairwinds.com/polaris\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					starboard.ConfigAuditReportCRName,
				)),
			},
		})
		return
	}

	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthThird,
			View:  view.NewReportSummary(report.GetCreationTimestamp().Time),
		},
		{
			Width: component.WidthThird,
			View:  view.NewScannerSummary(report.Report.Scanner),
		},
		{
			Width: component.WidthThird,
			View:  NewSummary(report.Report),
		},
	})

	var items []component.FlexLayoutItem
	items = append(items, component.FlexLayoutItem{
		Width: component.WidthThird,
		View:  createCardComponent("Pod Template", report.Report.PodChecks),
	})

	var containerNames []string

	for containerName := range report.Report.ContainerChecks {
		containerNames = append(containerNames, containerName)
	}

	sort.Strings(containerNames)

	for _, containerName := range containerNames {
		items = append(items, component.FlexLayoutItem{
			Width: component.WidthThird,
			View:  createCardComponent(fmt.Sprintf("Container %s", containerName), report.Report.ContainerChecks[containerName]),
		})
	}

	flexLayout.AddSections(items)

	return
}

func createCardComponent(title string, checks []starboard.Check) (x *component.Card) {
	x = component.NewCard(component.TitleFromString(title))
	x.SetBody(createChecksTable(checks))
	return x
}

func createChecksTable(checks []starboard.Check) component.Component {
	table := component.NewTableWithRows(
		"", "There are no checks!",
		component.NewTableCols("Success", "ID", "Severity", "Category"),
		[]component.TableRow{})

	for _, c := range checks {
		checkID := c.ID

		tr := component.TableRow{
			"Success":  component.NewText(strconv.FormatBool(c.Success)),
			"ID":       component.NewText(checkID),
			"Severity": component.NewText(fmt.Sprintf("%s", c.Severity)),
			"Category": component.NewText(c.Category),
		}
		table.Add(tr)
	}

	return table
}

func NewSummary(report starboard.ConfigAudit) (summary *component.Summary) {
	counts := calculateSummary(report)

	summary = component.NewSummary("Summary")

	var sections []component.SummarySection

	for header, count := range counts {
		sections = append(sections, component.SummarySection{
			Header: header, Content: component.NewText(strconv.Itoa(count)),
		})
	}

	sort.Stable(ByHeader(sections))

	summary.Add(sections...)
	return
}

func calculateSummary(report starboard.ConfigAudit) map[string]int {
	counts := map[string]int{
		"error":   0,
		"warning": 0,
	}

	for _, check := range report.PodChecks {
		if check.Success {
			continue
		}
		counts[check.Severity] = counts[check.Severity] + 1
	}

	for _, checks := range report.ContainerChecks {
		for _, check := range checks {
			if check.Success {
				continue
			}
			counts[check.Severity] = counts[check.Severity] + 1
		}
	}
	return counts
}

// ByHeader implements sort.Interface based on the Header field of SummarySection.
type ByHeader []component.SummarySection

func (a ByHeader) Len() int           { return len(a) }
func (a ByHeader) Less(i, j int) bool { return a[i].Header < a[j].Header }
func (a ByHeader) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
