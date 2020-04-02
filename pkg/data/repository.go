package data

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	security "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
)

const (
	WorkloadKindPod        = "Pod"
	WorkloadKindDeployment = "Deployment"
	WorkloadKindDaemonSet  = "DaemonSet"
	KindNamespace          = "Namespace"
	KindNode               = "Node"
)

const (
	labelWorkloadKind  = "starboard.workload.kind"
	labelWorkloadName  = "starboard.workload.name"
	labelContainerName = "starboard.container.name"
)

const (
	aquaSecurityAPIVersion     = "aquasecurity.github.com/v1alpha1"
	vulnerabilitiesKind        = "Vulnerability"
	CISKubernetesBenchmarkKind = "CISKubernetesBenchmark"
)

type Workload struct {
	Kind string
	Name string
}

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
	Report security.Vulnerability
}

func (r *Repository) GetVulnerabilitiesSummary(ctx context.Context, options Workload) (vs security.VulnerabilitySummary, err error) {
	containerReports, err := r.GetVulnerabilitiesForWorkload(ctx, options)
	if err != nil {
		return vs, err
	}
	for _, cr := range containerReports {
		for _, v := range cr.Report.Report.Vulnerabilities {
			switch v.Severity {
			case security.SeverityCritical:
				vs.CriticalCount++
			case security.SeverityHigh:
				vs.HighCount++
			case security.SeverityMedium:
				vs.MediumCount++
			case security.SeverityLow:
				vs.LowCount++
			default:
				vs.UnknownCount++
			}
		}
	}
	return
}

func (r *Repository) GetVulnerabilitiesForNamespace(ctx context.Context, namespace string) (report ContainerImageScanReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: aquaSecurityAPIVersion,
		Kind:       vulnerabilitiesKind,
		Namespace:  namespace,
	})
	if err != nil {
		return
	}
	b, err := unstructuredList.MarshalJSON()
	if err != nil {
		return
	}
	var reportList security.VulnerabilityList
	err = json.Unmarshal(b, &reportList)
	if err != nil {
		return
	}

	var vulnerabilities []security.VulnerabilityItem

	for _, i := range reportList.Items {
		if _, containerNameSpecified := i.Labels[labelContainerName]; !containerNameSpecified {
			continue
		}
		vulnerabilities = append(vulnerabilities, i.Report.Vulnerabilities...)
	}

	sort.SliceStable(vulnerabilities, func(i, j int) bool {
		return strings.Compare(vulnerabilities[i].VulnerabilityID, vulnerabilities[j].VulnerabilityID) < 0
	})

	report = ContainerImageScanReport{
		Name: fmt.Sprintf("Namespace %s", namespace),
		Report: security.Vulnerability{
			Report: security.VulnerabilityReport{
				Vulnerabilities: vulnerabilities,
			},
		},
	}

	return
}

func (r *Repository) GetVulnerabilitiesForWorkload(ctx context.Context, options Workload) (reports []ContainerImageScanReport, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: aquaSecurityAPIVersion,
		Kind:       vulnerabilitiesKind,
		// TODO Report bug to Octant? Apparently the label selector doesn't work and I have to do filtering manually :(
		//Selector: &labels.Set{
		//	labelWorkloadKind: options.Kind,
		//	labelWorkloadName: options.Name,
		//},
	})
	if err != nil {
		err = fmt.Errorf("listing vulnerabilities: %w", err)
		return
	}
	b, err := unstructuredList.MarshalJSON()
	if err != nil {
		err = fmt.Errorf("marshalling unstructured list to JSON: %w", err)
		return
	}
	var reportList security.VulnerabilityList
	err = json.Unmarshal(b, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to VulnerabilityList: %w", err)
		return
	}
	for _, item := range reportList.Items {
		containerName, containerNameSpecified := item.Labels[labelContainerName]
		if item.Labels[labelWorkloadKind] == options.Kind &&
			item.Labels[labelWorkloadName] == options.Name &&
			containerNameSpecified {
			reports = append(reports, ContainerImageScanReport{
				Name:   fmt.Sprintf("Container %s", containerName),
				Report: item,
			})
		}
	}

	sort.SliceStable(reports, func(i, j int) bool {
		return strings.Compare(reports[i].Name, reports[j].Name) < 0
	})

	return
}

func (r *Repository) GetCISKubernetesBenchmark(ctx context.Context, node string) (report security.CISKubernetesBenchmark, err error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: aquaSecurityAPIVersion,
		Kind:       CISKubernetesBenchmarkKind,
		Name:       node,
	})
	if err != nil {
		err = fmt.Errorf("listing CIS Kubernetes Benchmarks: %w", err)
		return
	}
	b, err := unstructuredList.MarshalJSON()
	if err != nil {
		err = fmt.Errorf("marshalling unstructured list to JSON: %w", err)
		return
	}
	var reportList security.CISKubernetesBenchmarkList
	err = json.Unmarshal(b, &reportList)
	if err != nil {
		err = fmt.Errorf("unmarshalling JSON to CISKubernetesBenchmarkList: %w", err)
		return
	}

	for _, r := range reportList.Items {
		if r.Name == node {
			report = r
			return
		}
	}

	return
}
