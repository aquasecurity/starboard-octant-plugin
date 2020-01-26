package data

import (
	"context"
	"encoding/json"
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sort"
	"strings"
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
	Report security.ImageScanReport
}

func (r *Repository) GetImageScanReports(ctx context.Context, options Workload) ([]ContainerImageScanReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: "security.danielpacak.github.com/v1",
		Kind:       "ImageScanReport",
		//Selector: &labels.Set{
		//	"risky.workload.kind":  options.Kind,
		//	"risky.workload.name":  options.Name,
		//	"risky.container.name": options.Container,
		//},
	})
	if err != nil {
		return nil, err
	}
	b, err := unstructuredList.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var reportList security.ImageScanReportList
	err = json.Unmarshal(b, &reportList)
	if err != nil {
		return nil, err
	}
	var reports []ContainerImageScanReport
	for _, i := range reportList.Items {
		containerName, containerNameSpecified := i.Labels["risky.container.name"]
		if i.Labels["risky.workload.kind"] == options.Kind &&
			i.Labels["risky.workload.name"] == options.Name &&
			containerNameSpecified {
			reports = append(reports, ContainerImageScanReport{
				Name:   containerName,
				Report: i,
			})
		}
	}

	sort.SliceStable(reports, func(i, j int) bool {
		return strings.Compare(reports[i].Name, reports[j].Name) < 0
	})

	return reports, nil
}

func (r *Repository) GetDescriptorScanReportFor(ctx context.Context, options Workload) (*security.DescriptorScanReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: "security.danielpacak.github.com/v1",
		Kind:       "DescriptorScanReport",
		//Selector: &labels.Set{
		//	"risky.workload.kind":  options.Kind,
		//	"risky.workload.name":  options.Name,
		//},
	})
	if err != nil {
		return nil, err
	}
	b, err := unstructuredList.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var reportList security.DescriptorScanReportList
	err = json.Unmarshal(b, &reportList)
	if err != nil {
		return nil, err
	}
	var reports []security.DescriptorScanReport
	for _, i := range reportList.Items {
		if i.Labels["risky.workload.kind"] == options.Kind &&
			i.Labels["risky.workload.name"] == options.Name {
			reports = append(reports, i)
		}
	}
	if len(reports) == 0 {
		return nil, nil
	}
	return &reports[0], nil
}

func UnstructuredToPod(u *unstructured.Unstructured) (core.Pod, error) {
	b, err := u.MarshalJSON()
	if err != nil {
		return core.Pod{}, err
	}
	var pod core.Pod
	err = json.Unmarshal(b, &pod)
	if err != nil {
		return core.Pod{}, err
	}
	return pod, nil
}
