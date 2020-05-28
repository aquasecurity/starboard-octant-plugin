package vulnerabilities

import (
	"fmt"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	"strconv"
	"strings"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/model"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

// NewReport creates a new view component for displaying the specified ContainerImageScanReport.
func NewReport(workload model.Workload, reports []model.ContainerImageScanReport) (flexLayout component.FlexLayout) {
	flexLayout = *component.NewFlexLayout("Vulnerabilities")
	if len(reports) == 0 {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"These reports are not available.\n"+
						"> Note that vulnerability reports are represented by instances of the `vulnerabilities.aquasecurity.github.io` resource.\n"+
						"> You can create such reports by running [Trivy][trivy] with [Starboard CLI][starboard-cli]:\n"+
						"> ```\n"+
						"> $ starboard find vulnerabilities %[1]s/%[2]s --namespace %[3]s\n"+
						"> ```\n"+
						"\n"+
						"[trivy]: https://github.com/aquasecurity/trivy\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					strings.ToLower(workload.Kind),
					workload.Name,
					workload.Namespace,
				)),
			},
		})
		return
	}

	var items []component.FlexLayoutItem
	for _, containerReport := range reports {
		items = append(items, component.FlexLayoutItem{
			Width: component.WidthThird,
			View:  view.NewReportSummary(containerReport.Report.CreationTimestamp.Time),
		})

		items = append(items, component.FlexLayoutItem{
			Width: component.WidthThird,
			View:  view.NewScannerSummary(containerReport.Report.Report.Scanner),
		})

		items = append(items, component.FlexLayoutItem{
			Width: component.WidthThird,
			View:  NewVulnerabilitiesSummary("Summary", containerReport.Report.Report.Summary),
		})

		items = append(items, component.FlexLayoutItem{
			Width: component.WidthFull,
			View:  createVulnerabilitiesTable(containerReport.Name, containerReport.Report),
		})
	}

	flexLayout.AddSections(items)

	return flexLayout
}

func createVulnerabilitiesTable(containerName string, report sec.Vulnerability) component.Component {
	table := component.NewTableWithRows(
		containerName, "There are no vulnerabilities!",
		component.NewTableCols("ID", "Severity", "Title", "Resource", "Installed Version", "Fixed Version"),
		[]component.TableRow{})

	for _, vi := range report.Report.Vulnerabilities {
		tr := component.TableRow{
			"ID":                getLinkComponent(vi),
			"Severity":          component.NewText(fmt.Sprintf("%s", vi.Severity)),
			"Title":             component.NewText(vi.Title),
			"Resource":          component.NewText(vi.Resource),
			"Installed Version": component.NewText(vi.InstalledVersion),
			"Fixed Version":     component.NewText(vi.FixedVersion),
		}
		table.Add(tr)
	}

	return table
}

func getLinkComponent(v sec.VulnerabilityItem) component.Component {
	if len(v.Links) > 0 {
		return component.NewLink(v.VulnerabilityID, v.VulnerabilityID, v.Links[0])
	}
	return component.NewText(v.VulnerabilityID)
}

func NewVulnerabilitiesSummary(title string, summary sec.VulnerabilitySummary) (c *component.Summary) {
	c = component.NewSummary(title)

	sections := []component.SummarySection{
		{Header: "CRITICAL ", Content: component.NewText(strconv.Itoa(summary.CriticalCount))},
		{Header: "HIGH ", Content: component.NewText(strconv.Itoa(summary.HighCount))},
		{Header: "MEDIUM ", Content: component.NewText(strconv.Itoa(summary.MediumCount))},
		{Header: "LOW ", Content: component.NewText(strconv.Itoa(summary.LowCount))},
		{Header: "UNKNOWN ", Content: component.NewText(strconv.Itoa(summary.UnknownCount))},
	}
	c.Add(sections...)
	return
}
