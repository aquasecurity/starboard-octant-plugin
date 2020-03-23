package view

import (
	"fmt"

	sec "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewImageScanReport(reportName string, report sec.Vulnerability) component.Component {
	table := component.NewTableWithRows(
		fmt.Sprintf(reportName), "There are no vulnerabilities!",
		component.NewTableCols("ID", "Severity", "Title", "Resource", "Installed Version", "Fixed Version", "Layer ID"),
		[]component.TableRow{})

	for _, vi := range report.Spec.Vulnerabilities {
		tr := component.TableRow{
			"ID":                getLinkComponent(vi),
			"Severity":          component.NewText(fmt.Sprintf("%s", vi.Severity)),
			"Title":             component.NewText(vi.Title),
			"Resource":          component.NewText(vi.Resource),
			"Installed Version": component.NewText(vi.InstalledVersion),
			"Fixed Version":     component.NewText(vi.FixedVersion),
			"Layer ID":          component.NewText(vi.LayerID),
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
