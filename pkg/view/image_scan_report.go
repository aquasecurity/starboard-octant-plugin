package view

import (
	"fmt"
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"sort"
	"strings"
)

func NewImageScanReport(containerName string, report security.ImageScanReport) component.Component {
	table := component.NewTableWithRows(
		fmt.Sprintf("Image Scan Report %s", containerName), "There are no vulnerabilities!",
		component.NewTableCols("ID", "Severity", "Title", "Resource", "Installed Version", "Fixed Version"),
		[]component.TableRow{})

	vulnerabilities := report.Spec.Vulnerabilities

	sort.SliceStable(vulnerabilities, func(i, j int) bool {
		return strings.Compare(vulnerabilities[i].Severity, vulnerabilities[j].Severity) < 0
	})

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

	return table
}

func getLinkComponent(v security.VulnerabilitySpec) component.Component {
	if len(v.Links) > 0 {
		return component.NewLink(v.VulnerabilityID, v.VulnerabilityID, v.Links[0])
	}
	return component.NewText(v.VulnerabilityID)
}
