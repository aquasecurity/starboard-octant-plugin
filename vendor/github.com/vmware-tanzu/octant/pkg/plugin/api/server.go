/*
Copyright (c) 2019 the Octant contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"context"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/octant/internal/gvk"
	"github.com/vmware-tanzu/octant/internal/portforward"
	"github.com/vmware-tanzu/octant/pkg/plugin/api/proto"
	"github.com/vmware-tanzu/octant/pkg/store"
)

// PortForwardRequest describes a port forward request.
type PortForwardRequest struct {
	Namespace     string
	PodName       string
	ContainerName string
	Port          uint16
}

// PortForwardResponse is the response from a port forward request.
type PortForwardResponse struct {
	ID   string
	Port uint16
}

// Service is the dashboard service.
type Service interface {
	List(ctx context.Context, key store.Key) (*unstructured.UnstructuredList, error)
	Get(ctx context.Context, key store.Key) (*unstructured.Unstructured, bool, error)
	PortForward(ctx context.Context, req PortForwardRequest) (PortForwardResponse, error)
	CancelPortForward(ctx context.Context, id string)
	Update(ctx context.Context, object *unstructured.Unstructured) error
	ForceFrontendUpdate(ctx context.Context) error
}

// FrontendUpdateController can control the frontend. ie. the web gui
type FrontendUpdateController interface {
	ForceUpdate() error
}

// FrontendProxy is a proxy for messaging the frontend.
type FrontendProxy struct {
	FrontendUpdateController FrontendUpdateController
}

// ForceFrontendUpdate forces the frontend to update
func (proxy *FrontendProxy) ForceFrontendUpdate() error {
	if proxy.FrontendUpdateController == nil {
		return nil
	}

	return proxy.FrontendUpdateController.ForceUpdate()
}

// GRPCService is an implementation of the dashboard service based on GRPC.
type GRPCService struct {
	ObjectStore   store.Store
	PortForwarder portforward.PortForwarder
	FrontendProxy FrontendProxy
}

var _ Service = (*GRPCService)(nil)

// List lists objects.
func (s *GRPCService) List(ctx context.Context, key store.Key) (*unstructured.UnstructuredList, error) {
	// TODO: support hasSynced
	list, _, err := s.ObjectStore.List(ctx, key)
	return list, err
}

// Get retrieves an object.
func (s *GRPCService) Get(ctx context.Context, key store.Key) (*unstructured.Unstructured, bool, error) {
	return s.ObjectStore.Get(ctx, key)
}

func (s *GRPCService) Update(ctx context.Context, object *unstructured.Unstructured) error {
	key, err := store.KeyFromObject(object)
	if err != nil {
		return err
	}

	return s.ObjectStore.Update(ctx, key, func(u *unstructured.Unstructured) error {
		u.Object = object.Object
		return nil
	})
}

// PortForward creates a port forward.
func (s *GRPCService) PortForward(ctx context.Context, req PortForwardRequest) (PortForwardResponse, error) {
	pfResponse, err := s.PortForwarder.Create(
		ctx,
		gvk.Pod,
		req.PodName,
		req.Namespace,
		req.Port)
	if err != nil {
		return PortForwardResponse{}, err
	}

	resp := PortForwardResponse{
		ID:   pfResponse.ID,
		Port: pfResponse.Ports[0].Local,
	}

	return resp, nil
}

// CancelPortForward cancels a port forward
func (s *GRPCService) CancelPortForward(ctx context.Context, id string) {
	s.PortForwarder.StopForwarder(id)
}

func (s *GRPCService) ForceFrontendUpdate(ctx context.Context) error {
	return s.FrontendProxy.ForceFrontendUpdate()
}

type grpcServer struct {
	service Service
}

var _ proto.DashboardServer = (*grpcServer)(nil)

// List list objects.
func (c *grpcServer) List(ctx context.Context, in *proto.KeyRequest) (*proto.ListResponse, error) {
	key, err := convertToKey(in)
	if err != nil {
		return nil, err
	}

	objects, err := c.service.List(ctx, key)
	if err != nil {
		return nil, err
	}

	encodedObjects, err := convertFromObjects(objects)
	if err != nil {
		return nil, err
	}

	out := &proto.ListResponse{
		Objects: encodedObjects,
	}

	return out, nil
}

// Get gets an object.
func (c *grpcServer) Get(ctx context.Context, in *proto.KeyRequest) (*proto.GetResponse, error) {
	key, err := convertToKey(in)
	if err != nil {
		return nil, err
	}

	object, found, err := c.service.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var out *proto.GetResponse

	if found {
		encodedObject, err := convertFromObject(object)
		if err != nil {
			return nil, err
		}

		out = &proto.GetResponse{
			Object: encodedObject,
		}

	}

	return out, nil
}

// Update updates an object.
func (c *grpcServer) Update(ctx context.Context, in *proto.UpdateRequest) (*proto.UpdateResponse, error) {
	object, found, err := convertToObject(in.Object)
	if err != nil {
		return nil, err
	}

	if !found {
		return &proto.UpdateResponse{}, errors.Errorf("can't update an object that doesn't exist")
	}

	if err := c.service.Update(ctx, object); err != nil {
		return nil, err
	}

	return &proto.UpdateResponse{}, nil
}

// PortForward creates a port forward.
func (c *grpcServer) PortForward(ctx context.Context, in *proto.PortForwardRequest) (*proto.PortForwardResponse, error) {
	req, err := convertToPortForwardRequest(in)
	if err != nil {
		return nil, err
	}

	pfResp, err := c.service.PortForward(ctx, *req)
	if err != nil {
		return nil, err
	}

	resp := &proto.PortForwardResponse{
		PortForwardID: pfResp.ID,
		PortNumber:    uint32(pfResp.Port),
	}

	return resp, nil
}

// CancelPortForward cancels a port forward.
func (c *grpcServer) CancelPortForward(ctx context.Context, in *proto.CancelPortForwardRequest) (*proto.Empty, error) {
	if in == nil {
		return nil, errors.New("request is nil")
	}

	c.service.CancelPortForward(ctx, in.PortForwardID)
	return &proto.Empty{}, nil
}

// ForceFrontendUpdate forces the front end to update.
func (c *grpcServer) ForceFrontendUpdate(ctx context.Context, _ *proto.Empty) (*proto.Empty, error) {
	if err := c.service.ForceFrontendUpdate(ctx); err != nil {
		return nil, err
	}

	return &proto.Empty{}, nil
}
