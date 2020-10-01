package vulnerabilities

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/starboard/pkg/kube"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/model"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

// NewReport creates a new view component for displaying the specified ContainerImageScanReport.
func NewReport(workload kube.Object, vulnerabilityReportsDefined bool, reports []model.NamedVulnerabilityReport) (flexLayout component.FlexLayout) {
	flexLayout = *component.NewFlexLayout(fmt.Sprintf("Vulnerabilities"))

	if !vulnerabilityReportsDefined {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"The `%[1]s` resource, which represents vulnerability reports, is not defined.\n"+
						"> You can create this resource definition by running the [Starboard CLI][starboard-cli] init command:\n"+
						"> ```\n"+
						"> $ kubectl starboard init\n"+
						"> ```\n"+
						"or\n"+
						"> ```\n"+
						"> $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/vulnerabilityreports-crd.yaml\n"+
						"> ```\n"+
						"\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					starboard.VulnerabilityReportsCRName,
				)),
			},
		})
		return
	}

	if len(reports) == 0 {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"Vulnerability reports are not available for %[2]s/%[3]s in the %[4]s namespace.\n"+
						"> Note that vulnerability reports are represented by instances of the `%[1]s` resource.\n"+
						"> You can create such reports by running [Trivy][trivy] with [Starboard CLI][starboard-cli]:\n"+
						"> ```\n"+
						"> $ kubectl starboard find vulnerabilities %[2]s/%[3]s --namespace %[4]s\n"+
						"> ```\n"+
						"\n"+
						"[trivy]: https://github.com/aquasecurity/trivy\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					starboard.VulnerabilityReportsCRName,
					strings.ToLower(string(workload.Kind)),
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

func createVulnerabilitiesTable(containerName string, report starboard.VulnerabilityReport) component.Component {
	table := component.NewTableWithRows(
		fmt.Sprintf("Container %s", containerName), "There are no vulnerabilities!",
		component.NewTableCols("ID", "Severity", "Title", "Resource", "Installed Version", "Fixed Version"),
		[]component.TableRow{})

	sort.Stable(BySeverity{report.Report.Vulnerabilities})

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

func getLinkComponent(v starboard.Vulnerability) component.Component {
	if len(v.Links) > 0 {
		return component.NewMarkdownText(view.ToMarkdownLink(v.VulnerabilityID, v.Links[0]))
	}
	return component.NewText(v.VulnerabilityID)
}

func NewVulnerabilitiesSummary(title string, summary starboard.VulnerabilitySummary) (c *component.Summary) {
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
