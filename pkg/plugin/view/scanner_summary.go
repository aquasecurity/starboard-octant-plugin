package view

import (
	"time"

	sec "github.com/aquasecurity/starboard-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
)

func NewScannerSummary(scanner sec.Scanner) (c *component.Summary) {
	c = component.NewSummary("Scanner")
	sections := []component.SummarySection{
		{
			Header:  "Name",
			Content: component.NewText(scanner.Name),
		},
		{
			Header:  "Vendor",
			Content: component.NewText(scanner.Vendor),
		},
		{
			Header:  "Version",
			Content: component.NewText(scanner.Version),
		},
	}
	c.Add(sections...)
	return
}

// TODO Rename to Report Metadata
func NewReportSummary(generatedAt time.Time) (c *component.Summary) {
	c = component.NewSummary("Report Metadata")
	sections := []component.SummarySection{
		{
			Header:  "Generated At",
			Content: component.NewTimestamp(generatedAt),
		},
	}
	c.Add(sections...)
	return
}
