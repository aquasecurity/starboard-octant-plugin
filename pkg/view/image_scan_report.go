package view

import (
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewImageScanReport(report *security.ImageScanReport) component.Component {
	table := component.NewTableWithRows(
		"Image Scan Report", "Image scan report",
		component.NewTableCols("ID", "Severity", "Title", "Resource", "Installed Version", "Fixed Version"),
		[]component.TableRow{})

	if report != nil {
		for _, vi := range report.Spec.Vulnerabilities {
			tr := component.TableRow{
				"ID":                getLinkComponent(vi),
				"Severity":          component.NewText(vi.Severity),
				"Title":             component.NewText(vi.Title),
				"Resource":          component.NewText(vi.Resource),
				"Installed Version": component.NewText(vi.InstalledVersion),
				"Fixed Version":     component.NewText(vi.FixedVersion),
			}
			table.Add(tr)
		}
	}

	table.Sort("ID", false)
	return table
}

func getLinkComponent(v security.VulnerabilitySpec) component.Component {
	if len(v.Links) > 0 {
		return component.NewLink(v.VulnerabilityID, v.VulnerabilityID, v.Links[0])
	}
	return component.NewText(v.VulnerabilityID)
}
