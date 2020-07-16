package model

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/aquasecurity/starboard/pkg/kube"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
)

const (
	ClusterKind = "Cluster"
)

type Repository struct {
	client service.Dashboard
}

func NewRepository(client service.Dashboard) *Repository {
	return &Repository{
		client: client,
	}
}

type ContainerImageScanReport struct {
	Name   string
	Report starboard.Vulnerability
}

func (r *Repository) GetVulnerabilitiesSummary(ctx context.Context, options kube.Object) (vs starboard.VulnerabilitySummary, err error) {
	containerReports, err := r.GetVulnerabilitiesForWorkload(ctx, options)
	if err != nil {
		return vs, err
	}
	for _, cr := range containerReports {
		for _, v := range cr.Report.Report.Vulnerabilities {
			switch v.Severity {
			case starboard.SeverityCritical:
				vs.CriticalCount++
			case starboard.SeverityHigh:
				vs.HighCount++
			case starboard.SeverityMedium:
				vs.MediumCount++
			case starboard.SeverityLow:
				vs.LowCount++
			default:
				vs.UnknownCount++
			}
		}
	}
	return
}

func (r *Repository) GetVulnerabilitiesForWorkload(ctx context.Context, options kube.Object) (reports []ContainerImageScanReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.VulnerabilitiesCRVersion),
		Kind:       starboard.VulnerabilityKind,
		Namespace:  options.Namespace,
		Selector: &labels.Set{
			kube.LabelResourceKind: string(options.Kind),
			kube.LabelResourceName: options.Name,
		},
	})
	if err != nil {
		err = fmt.Errorf("listing vulnerabilities: %w", err)
		return
	}
	var reportList starboard.VulnerabilityList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to VulnerabilityList: %w", err)
		return
	}
	for _, item := range reportList.Items {
		if containerName, containerNameSpecified := item.Labels[kube.LabelContainerName]; containerNameSpecified {
			reports = append(reports, ContainerImageScanReport{
				Name:   fmt.Sprintf("Container %s", containerName),
				Report: *item.DeepCopy(),
			})
		}
	}

	sort.SliceStable(reports, func(i, j int) bool {
		return strings.Compare(reports[i].Name, reports[j].Name) < 0
	})

	return
}

func (r *Repository) GetConfigAudit(ctx context.Context, options kube.Object) (report *starboard.ConfigAuditReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.ConfigAuditReportCRVersion),
		Kind:       starboard.ConfigAuditReportKind,
		Namespace:  options.Namespace,
		Selector: &labels.Set{
			kube.LabelResourceKind: string(options.Kind),
			kube.LabelResourceName: options.Name,
		},
	})
	if err != nil {
		err = fmt.Errorf("listing config audit reports: %w", err)
		return
	}
	if len(unstructuredList.Items) == 0 {
		return
	}
	var reportList starboard.ConfigAuditReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to ConfigAuditReportList: %w", err)
		return
	}

	report = reportList.Items[0].DeepCopy()
	return
}

func (r *Repository) GetCISKubeBenchReport(ctx context.Context, node string) (report *starboard.CISKubeBenchReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.CISKubeBenchReportCRVersion),
		Kind:       starboard.CISKubeBenchReportKind,
		Selector: &labels.Set{
			kube.LabelResourceKind:  string(kube.KindNode),
			kube.LabelResourceName:  node,
			kube.LabelHistoryLatest: "true",
		},
	})
	if err != nil {
		err = fmt.Errorf("listing CIS Kubernetes Benchmarks: %w", err)
		return
	}
	if len(unstructuredList.Items) == 0 {
		return
	}
	var reportList starboard.CISKubeBenchReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to CISKubernetesBenchmarkList: %w", err)
		return
	}

	report = reportList.Items[0].DeepCopy()
	return
}

func (r *Repository) GetKubeHunterReport(ctx context.Context) (report *starboard.KubeHunterReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.KubeHunterReportCRVersion),
		Kind:       starboard.KubeHunterReportKind,
		Selector: &labels.Set{
			kube.LabelResourceKind: ClusterKind,
			kube.LabelResourceName: "cluster",
		},
	})
	if err != nil {
		return
	}
	if len(unstructuredList.Items) == 0 {
		return
	}
	var reportList starboard.KubeHunterReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		return
	}

	report = reportList.Items[0].DeepCopy()
	return
}

func (r *Repository) structure(ul *unstructured.UnstructuredList, v interface{}) (err error) {
	b, err := ul.MarshalJSON()
	if err != nil {
		return
	}
	err = json.Unmarshal(b, v)
	return
}
