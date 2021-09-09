package controller

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/model"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/configaudit"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/kubebench"
	"github.com/aquasecurity/starboard-octant-plugin/pkg/plugin/view/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"strconv"
)

// ResourceTabPrinter is called when Octant wants to add new tab for the underlying resource.
func ResourceTabPrinter(request *service.PrintRequest) (tab plugin.TabResponse, err error) {
	if request.Object == nil {
		err = errors.New("request object is nil")
		return
	}

	workload, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return
	}

	switch workload.Kind {
	case kube.KindPod,
		kube.KindDeployment,
		kube.KindDaemonSet,
		kube.KindStatefulSet,
		kube.KindReplicaSet,
		kube.KindReplicationController,
		kube.KindCronJob,
		kube.KindJob:
		return vulnerabilitiesTabPrinter(request, workload)
	case kube.KindNode:
		return printKubernetesBenchmarkTab(request, workload.Name)
	default:
		err = fmt.Errorf("unrecognized workload kind: %s", workload.Kind)
		return
	}

}

func vulnerabilitiesTabPrinter(request *service.PrintRequest, workload kube.Object) (plugin.TabResponse, error) {
	repository := model.NewRepository(request.DashboardClient)

	_, err := repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.VulnerabilityReportsCRName)
	vulnerabilityReportsDefined := err == nil

	var reports []model.NamedVulnerabilityReport
	if vulnerabilityReportsDefined {
		reports, err = repository.GetVulnerabilityReportsByOwner(request.Context(), workload)
		if err != nil {
			return plugin.TabResponse{}, err
		}
	}

	tab := component.NewTabWithContents(vulnerabilities.NewReport(workload, vulnerabilityReportsDefined, reports))
	return plugin.TabResponse{Tab: tab}, nil
}

// printKubernetesBenchmarkTab creates the CIS Kubernetes Benchmark TabResponse
// for the specified node.
func printKubernetesBenchmarkTab(request *service.PrintRequest, node string) (plugin.TabResponse, error) {
	repository := model.NewRepository(request.DashboardClient)

	_, err := repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.CISKubeBenchReportCRName)
	kubeBenchReportDefined := err == nil

	var report *v1alpha1.CISKubeBenchReport

	if kubeBenchReportDefined {
		report, err = repository.GetCISKubeBenchReport(request.Context(), node)
		if err != nil {
			return plugin.TabResponse{}, nil
		}
	}

	return plugin.TabResponse{
		Tab: component.NewTabWithContents(kubebench.NewReport(kubeBenchReportDefined, report)),
	}, nil
}

// ResourcePrinter is called when Octant wants to print the details of the underlying resource.
func ResourcePrinter(request *service.PrintRequest) (plugin.PrintResponse, error) {
	if request.Object == nil {
		return plugin.PrintResponse{}, errors.New("object is nil")
	}

	workload, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, err
	}

	repository := model.NewRepository(request.DashboardClient)

	_, err = repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.VulnerabilityReportsCRName)
	vulnerabilityReportsDefined := err == nil

	var summary *v1alpha1.VulnerabilitySummary
	if vulnerabilityReportsDefined {
		summary, err = repository.GetVulnerabilitiesSummary(request.Context(), workload)
		if err != nil {
			return plugin.PrintResponse{}, err
		}
	}

	_, err = repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.ConfigAuditReportCRName)
	configAuditReportsDefined := err == nil

	var configAuditReport *v1alpha1.ConfigAuditReport
	var configAuditSummary *v1alpha1.ConfigAuditSummary
	if configAuditReportsDefined {
		configAuditReport, err = repository.GetConfigAuditReportByOwner(request.Context(), workload)
		if err != nil {
			return plugin.PrintResponse{}, err
		}
		if configAuditReport != nil {
			configAuditSummary = &configAuditReport.Report.Summary
		}
	}

	return plugin.PrintResponse{
		Status: vulnerabilities.NewSummarySections(summary),
		Config: configaudit.NewSummarySections(configAuditSummary),
	}, nil
}

func ResourceReportTabPrinter(request *service.PrintRequest) (plugin.TabResponse, error) {
	if request.Object == nil {
		return plugin.TabResponse{}, errors.New("object is nil")
	}

	workload, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return plugin.TabResponse{}, err
	}

	repository := model.NewRepository(request.DashboardClient)

	_, err = repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.ConfigAuditReportCRName)
	configAuditReportsDefined := err == nil

	var configAuditReport *v1alpha1.ConfigAuditReport
	if configAuditReportsDefined {
		configAuditReport, err = repository.GetConfigAuditReportByOwner(request.Context(), workload)
		if err != nil {
			return plugin.TabResponse{}, err
		}
	}

	return plugin.TabResponse{
		Tab: component.NewTabWithContents(*configaudit.NewReport(workload, configAuditReportsDefined, configAuditReport)),
	}, nil
}

// ResourceObjectStatus is called when Octant wants to determine the status (icon color) of an object
func ResourceObjectStatus(request *service.PrintRequest) (plugin.ObjectStatusResponse, error) {
	if request.Object == nil {
		return plugin.ObjectStatusResponse{}, errors.New("object is nil")
	}

	workload, err := getWorkloadFromObject(request.Object)
	if err != nil {
		return plugin.ObjectStatusResponse{}, err
	}

	repository := model.NewRepository(request.DashboardClient)

	_, err = repository.GetCustomResourceDefinitionByName(request.Context(), v1alpha1.VulnerabilityReportsCRName)
	vulnerabilityReportsDefined := err == nil

	var summary *v1alpha1.VulnerabilitySummary
	if vulnerabilityReportsDefined {
		summary, err = repository.GetVulnerabilitiesSummary(request.Context(), workload)
		if err != nil {
			return plugin.ObjectStatusResponse{}, err
		}
	}
	// summary could be nil due to delays in fetching the CRDs
	if summary == nil {
		return plugin.ObjectStatusResponse{}, nil
	}

	status := vulnerabilities.NewSummaryStatus(summary)

	return plugin.ObjectStatusResponse{
		ObjectStatus: component.PodSummary{
			Details: []component.Component{
				component.NewLabels(map[string]string{
					"Critical Vulnerabilities": strconv.Itoa(summary.CriticalCount),
				}),
				component.NewLabels(map[string]string{
					"High Vulnerabilities": strconv.Itoa(summary.HighCount),
				}),
				component.NewLabels(map[string]string{
					"Medium Vulnerabilities": strconv.Itoa(summary.MediumCount),
				}),
				component.NewLabels(map[string]string{
					"Low Vulnerabilities": strconv.Itoa(summary.LowCount),
				}),
				component.NewLabels(map[string]string{
					"Unknown Vulnerabilities": strconv.Itoa(summary.UnknownCount),
				}),
			},
			Properties: []component.Property{
				{Label: "Critical Vulnerabilities", Value: component.NewText(strconv.Itoa(summary.CriticalCount))},
				{Label: "High Vulnerabilities", Value: component.NewText(strconv.Itoa(summary.HighCount))},
				{Label: "Medium Vulnerabilities", Value: component.NewText(strconv.Itoa(summary.MediumCount))},
				{Label: "Low Vulnerabilities", Value: component.NewText(strconv.Itoa(summary.LowCount))},
				{Label: "Unknown Vulnerabilities", Value: component.NewText(strconv.Itoa(summary.UnknownCount))},
			},
			Status: status,
		},
	}, nil
}

func getWorkloadFromObject(o runtime.Object) (workload kube.Object, err error) {
	accessor := meta.NewAccessor()

	kind, err := accessor.Kind(o)
	if err != nil {
		return
	}

	name, err := accessor.Name(o)
	if err != nil {
		return
	}

	namespace, err := accessor.Namespace(o)
	if err != nil {
		return
	}

	workload = kube.Object{
		Kind:      kube.Kind(kind),
		Name:      name,
		Namespace: namespace,
	}
	return
}
