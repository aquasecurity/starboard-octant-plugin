package model

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/aquasecurity/starboard/pkg/kube"

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

// NamedVulnerabilityReport allows sorting VulnerabilityReports by container name.
type NamedVulnerabilityReport struct {
	Name   string
	Report starboard.VulnerabilityReport
}

func (r *Repository) GetVulnerabilitiesSummary(ctx context.Context, options kube.Object) (*starboard.VulnerabilitySummary, error) {
	vs := &starboard.VulnerabilitySummary{}
	containerReports, err := r.GetVulnerabilityReportsByOwner(ctx, options)
	if err != nil {
		return nil, err
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
	return vs, nil
}

func (r *Repository) GetCustomResourceDefinitionByName(ctx context.Context, name string) (*v1.CustomResourceDefinition, error) {
	unstructuredResp, err := r.client.Get(ctx, store.Key{
		APIVersion: "apiextensions.k8s.io/v1beta1",
		Kind:       "CustomResourceDefinition",
		Name:       name,
	})
	if err != nil {
		return nil, err
	}
	var crd v1.CustomResourceDefinition
	err = r.structure(unstructuredResp, &crd)
	return &crd, err
}

func (r *Repository) GetVulnerabilityReportsByOwner(ctx context.Context, owner kube.Object) (reports []NamedVulnerabilityReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.VulnerabilityReportsCRVersion),
		Kind:       starboard.VulnerabilityReportKind,
		Namespace:  owner.Namespace,
		Selector: &labels.Set{
			kube.LabelResourceKind: string(owner.Kind),
			kube.LabelResourceName: owner.Name,
		},
	})
	if err != nil {
		err = fmt.Errorf("listing vulnerabilities: %w", err)
		return
	}
	var reportList starboard.VulnerabilityReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to VulnerabilityList: %w", err)
		return
	}
	for _, item := range reportList.Items {
		if containerName, containerNameSpecified := item.Labels[kube.LabelContainerName]; containerNameSpecified {
			reports = append(reports, NamedVulnerabilityReport{
				Name:   containerName,
				Report: *item.DeepCopy(),
			})
		}
	}

	sort.SliceStable(reports, func(i, j int) bool {
		return strings.Compare(reports[i].Name, reports[j].Name) < 0
	})

	return
}

func (r *Repository) GetConfigAuditReport(ctx context.Context, owner kube.Object) (*starboard.ConfigAuditReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.ConfigAuditReportCRVersion),
		Kind:       starboard.ConfigAuditReportKind,
		Namespace:  owner.Namespace,
		Selector: &labels.Set{
			kube.LabelResourceKind:      string(owner.Kind),
			kube.LabelResourceName:      owner.Name,
			kube.LabelResourceNamespace: owner.Namespace,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("listing config audit reports: %w", err)
	}
	if len(unstructuredList.Items) == 0 {
		return nil, nil
	}
	var reportList starboard.ConfigAuditReportList
	err = r.structure(unstructuredList, &reportList)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling JSON to ConfigAuditReportList: %w", err)
	}

	return reportList.Items[0].DeepCopy(), nil
}

func (r *Repository) GetCISKubeBenchReport(ctx context.Context, node string) (report *starboard.CISKubeBenchReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: fmt.Sprintf("%s/%s", aquasecurity.GroupName, starboard.CISKubeBenchReportCRVersion),
		Kind:       starboard.CISKubeBenchReportKind,
		Selector: &labels.Set{
			kube.LabelResourceKind: string(kube.KindNode),
			kube.LabelResourceName: node,
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

func (r *Repository) structure(m json.Marshaler, v interface{}) (err error) {
	b, err := m.MarshalJSON()
	if err != nil {
		return
	}
	err = json.Unmarshal(b, v)
	return
}
