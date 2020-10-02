package view

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func NewReportMetadata(meta metav1.ObjectMeta) (c *component.Summary) {
	c = component.NewSummary("Metadata")
	sections := []component.SummarySection{
		{
			Header:  "Age",
			Content: component.NewTimestamp(meta.CreationTimestamp.Time),
		},
		{
			Header:  "Labels",
			Content: component.NewLabels(meta.Labels),
		},
		// TODO Add link to the Owner
	}
	c.Add(sections...)
	return
}
