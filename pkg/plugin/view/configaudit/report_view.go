package configaudit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewReport(workload kube.Object, isConfigAuditReportsCRDefined bool, report *v1alpha1.ConfigAuditReport) *component.FlexLayout {
	flexLayout := component.NewFlexLayout("Audit Reports")

	flexLayout.AddSections(component.FlexLayoutSection{
		{
			Width: component.WidthFull,
			View:  component.NewMarkdownText("#### Config"),
		},
	})

	if !isConfigAuditReportsCRDefined {
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
						"> $ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/starboard/main/deploy/crd/configauditreports.crd.yaml\n"+
						"> ```\n"+
						"\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					v1alpha1.ConfigAuditReportCRName,
				)),
			},
		})
		return flexLayout
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
						"> $ kubectl starboard scan configauditreports %[2]s/%[3]s --namespace %[4]s\n"+
						"> ```\n"+
						"\n"+
						"[polaris]: https://www.fairwinds.com/polaris\n"+
						"[starboard-cli]: https://github.com/aquasecurity/starboard#starboard-cli",
					v1alpha1.ConfigAuditReportCRName,
					strings.ToLower(string(workload.Kind)),
					workload.Name,
					workload.Namespace,
				)),
			},
		})
		return flexLayout
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
			View:  NewSummary(report.Report),
		},
	})

	var items []component.FlexLayoutItem
	items = append(items, component.FlexLayoutItem{
		Width: component.WidthHalf,
		View:  createCardComponent("Pod Template", report.Report.PodChecks),
	})

	var containerNames []string

	for containerName := range report.Report.ContainerChecks {
		containerNames = append(containerNames, containerName)
	}

	sort.Strings(containerNames)

	for _, containerName := range containerNames {
		items = append(items, component.FlexLayoutItem{
			Width: component.WidthHalf,
			View:  createCardComponent(fmt.Sprintf("Container %s", containerName), report.Report.ContainerChecks[containerName]),
		})
	}

	flexLayout.AddSections(items)

	return flexLayout
}

func createCardComponent(title string, checks []v1alpha1.Check) *component.Card {
	card := component.NewCard(component.TitleFromString(title))
	card.SetBody(createChecksTable(checks))
	return card
}

func createChecksTable(checks []v1alpha1.Check) component.Component {
	table := component.NewTableWithRows(
		"", "There are no checks!",
		component.NewTableCols("ID", "Severity", "Category"),
		[]component.TableRow{})

	for _, c := range checks {
		tr := component.TableRow{
			"ID":       CheckIDWithIcon(c),
			"Severity": component.NewText(fmt.Sprintf("%s", c.Severity)),
			"Category": component.NewText(c.Category),
		}
		table.Add(tr)
	}

	sort.Slice(table.Rows(), func(i, j int) bool {
		return table.Rows()[i]["ID"].(*component.Text).Config.Status > table.Rows()[j]["ID"].(*component.Text).Config.Status
	})

	return table
}

func CheckIDWithIcon(check v1alpha1.Check) component.Component {
	status := component.TextStatusOK
	if !check.Success && check.Severity == "warning" {
		status = component.TextStatusWarning
	}
	if !check.Success && check.Severity == "danger" {
		status = component.TextStatusError
	}

	text := component.NewText(check.ID, func(t *component.Text) {
		t.SetStatus(status)
	})

	return text
}

func NewSummary(report v1alpha1.ConfigAuditReportData) *component.Summary {
	return component.NewSummary("Summary", []component.SummarySection{
		{Header: "pass", Content: component.NewText(strconv.Itoa(report.Summary.PassCount))},
		{Header: "warning", Content: component.NewText(strconv.Itoa(report.Summary.WarningCount))},
		{Header: "danger", Content: component.NewText(strconv.Itoa(report.Summary.DangerCount))},
	}...)
}
