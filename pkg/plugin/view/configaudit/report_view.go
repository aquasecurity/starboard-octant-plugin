package configaudit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/starboard/pkg/kube"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewReport(workload kube.Object, configAuditReportsDefined bool, report *starboard.ConfigAuditReport) (flexLayout *component.FlexLayout) {
	flexLayout = component.NewFlexLayout("")

	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthFull,
			View:  component.NewMarkdownText("#### Config Audit Reports"),
		},
	})

	if !configAuditReportsDefined {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"The `%[1]s` resource, which represents config audit reports, is not defined.\n"+
						"> You can create this resource definition by running the [Starboard CLI][starboard-cli] init command:\n"+
						"> ```\n"+
						"> $ kubectl starboard init\n"+
						"> ```\n"+
						"or\n"+
						"> ```\n"+
						"> $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/master/kube/crd/configauditreports-crd.yaml\n"+
						"> ```\n"+
						"\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					starboard.ConfigAuditReportCRName,
				)),
			},
		})
		return
	}

	if report == nil {
		flexLayout.AddSections(component.FlexLayoutSection{
			{
				Width: component.WidthFull,
				View: component.NewMarkdownText(fmt.Sprintf(
					"Config audit reports are not available.\n"+
						"> Note that config audit reports are represented by instances of the `%[1]s` resource.\n"+
						"> You can create such reports by running [Polaris][polaris] with [Starboard CLI][starboard-cli]:\n"+
						"> ```\n"+
						"> $ kubectl starboard polaris %[2]s/%[3]s --namespace %[4]s\n"+
						"> ```\n"+
						"\n"+
						"[polaris]: https://www.fairwinds.com/polaris\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					starboard.ConfigAuditReportCRName,
					strings.ToLower(string(workload.Kind)),
					workload.Name,
					workload.Namespace,
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

func NewSummary(report starboard.ConfigAudit) (summaryComponent *component.Summary) {
	sections := []component.SummarySection{
		{Header: "danger", Content: component.NewText(strconv.Itoa(report.Summary.DangerCount))},
		{Header: "warning", Content: component.NewText(strconv.Itoa(report.Summary.WarningCount))},
	}
	sort.Stable(ByHeader(sections))

	summaryComponent = component.NewSummary("Summary", sections...)

	return
}

// ByHeader implements sort.Interface based on the Header field of SummarySection.
type ByHeader []component.SummarySection

func (a ByHeader) Len() int           { return len(a) }
func (a ByHeader) Less(i, j int) bool { return a[i].Header < a[j].Header }
func (a ByHeader) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
