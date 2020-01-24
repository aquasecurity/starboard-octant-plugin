package data

import (
	"context"
	"encoding/json"
	security "github.com/danielpacak/k8s-security-crds/pkg/apis/security/v1"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

type Repository struct {
	client service.Dashboard
}

func NewRepository(client service.Dashboard) *Repository {
	return &Repository{
		client: client,
	}
}

func (r *Repository) GetImageScanReportFor(ctx context.Context, imageRef string) (*security.ImageScanReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: "security.danielpacak.github.com/v1",
		Kind:       "ImageScanReport",
		Selector: &labels.Set{
			"image-ref": imageRef,
		},
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
	if len(reportList.Items) == 0 {
		return nil, nil
	}
	return &reportList.Items[0], nil
}

func (r *Repository) GetDescriptorScanReportFor(ctx context.Context, imageRef string) (*security.DescriptorScanReport, error) {
	unstructuredList, err := r.client.List(ctx, store.Key{
		APIVersion: "security.danielpacak.github.com/v1",
		Kind:       "DescriptorScanReport",
		Selector: &labels.Set{
			"image-ref": imageRef,
		},
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
	if len(reportList.Items) == 0 {
		return nil, nil
	}
	return &reportList.Items[0], nil
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
