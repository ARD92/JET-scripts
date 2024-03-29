// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: jnx_routing_base_service.proto

package routing

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// BaseClient is the client API for Base service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BaseClient interface {
	// [brief]: Configure purge timer for the client.
	// [detail]: Configure a purge timer for the client so that server
	// side will retain the client installed routes till this time after
	// client disconnects and provide sufficient time for the client to
	// reconnect if possible. The default purge timer is 120 seconds.
	// The valid purge timer range is between 1 and 1000 seconds.
	RoutePurgeTimerAdd(ctx context.Context, in *RoutePurgeTimerAddRequest, opts ...grpc.CallOption) (*RoutePurgeTimerAddResponse, error)
	// [brief]: Delete the purge timer for the client.
	// [detail]: Delete a previously configured purge timer for the client.
	RoutePurgeTimerDelete(ctx context.Context, in *RoutePurgeTimerDeleteRequest, opts ...grpc.CallOption) (*RoutePurgeTimerDeleteResponse, error)
	// [brief]: Retrieve the purge timer for the client.
	// [detail]: Retrieve the purge timer for the client.
	RoutePurgeTimerGet(ctx context.Context, in *RoutePurgeTimerGetRequest, opts ...grpc.CallOption) (*RoutePurgeTimerGetResponse, error)
}

type baseClient struct {
	cc grpc.ClientConnInterface
}

func NewBaseClient(cc grpc.ClientConnInterface) BaseClient {
	return &baseClient{cc}
}

func (c *baseClient) RoutePurgeTimerAdd(ctx context.Context, in *RoutePurgeTimerAddRequest, opts ...grpc.CallOption) (*RoutePurgeTimerAddResponse, error) {
	out := new(RoutePurgeTimerAddResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.base.Base/RoutePurgeTimerAdd", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *baseClient) RoutePurgeTimerDelete(ctx context.Context, in *RoutePurgeTimerDeleteRequest, opts ...grpc.CallOption) (*RoutePurgeTimerDeleteResponse, error) {
	out := new(RoutePurgeTimerDeleteResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.base.Base/RoutePurgeTimerDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *baseClient) RoutePurgeTimerGet(ctx context.Context, in *RoutePurgeTimerGetRequest, opts ...grpc.CallOption) (*RoutePurgeTimerGetResponse, error) {
	out := new(RoutePurgeTimerGetResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.base.Base/RoutePurgeTimerGet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BaseServer is the server API for Base service.
// All implementations must embed UnimplementedBaseServer
// for forward compatibility
type BaseServer interface {
	// [brief]: Configure purge timer for the client.
	// [detail]: Configure a purge timer for the client so that server
	// side will retain the client installed routes till this time after
	// client disconnects and provide sufficient time for the client to
	// reconnect if possible. The default purge timer is 120 seconds.
	// The valid purge timer range is between 1 and 1000 seconds.
	RoutePurgeTimerAdd(context.Context, *RoutePurgeTimerAddRequest) (*RoutePurgeTimerAddResponse, error)
	// [brief]: Delete the purge timer for the client.
	// [detail]: Delete a previously configured purge timer for the client.
	RoutePurgeTimerDelete(context.Context, *RoutePurgeTimerDeleteRequest) (*RoutePurgeTimerDeleteResponse, error)
	// [brief]: Retrieve the purge timer for the client.
	// [detail]: Retrieve the purge timer for the client.
	RoutePurgeTimerGet(context.Context, *RoutePurgeTimerGetRequest) (*RoutePurgeTimerGetResponse, error)
	mustEmbedUnimplementedBaseServer()
}

// UnimplementedBaseServer must be embedded to have forward compatible implementations.
type UnimplementedBaseServer struct {
}

func (UnimplementedBaseServer) RoutePurgeTimerAdd(context.Context, *RoutePurgeTimerAddRequest) (*RoutePurgeTimerAddResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RoutePurgeTimerAdd not implemented")
}
func (UnimplementedBaseServer) RoutePurgeTimerDelete(context.Context, *RoutePurgeTimerDeleteRequest) (*RoutePurgeTimerDeleteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RoutePurgeTimerDelete not implemented")
}
func (UnimplementedBaseServer) RoutePurgeTimerGet(context.Context, *RoutePurgeTimerGetRequest) (*RoutePurgeTimerGetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RoutePurgeTimerGet not implemented")
}
func (UnimplementedBaseServer) mustEmbedUnimplementedBaseServer() {}

// UnsafeBaseServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BaseServer will
// result in compilation errors.
type UnsafeBaseServer interface {
	mustEmbedUnimplementedBaseServer()
}

func RegisterBaseServer(s grpc.ServiceRegistrar, srv BaseServer) {
	s.RegisterService(&Base_ServiceDesc, srv)
}

func _Base_RoutePurgeTimerAdd_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RoutePurgeTimerAddRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BaseServer).RoutePurgeTimerAdd(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.base.Base/RoutePurgeTimerAdd",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BaseServer).RoutePurgeTimerAdd(ctx, req.(*RoutePurgeTimerAddRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Base_RoutePurgeTimerDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RoutePurgeTimerDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BaseServer).RoutePurgeTimerDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.base.Base/RoutePurgeTimerDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BaseServer).RoutePurgeTimerDelete(ctx, req.(*RoutePurgeTimerDeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Base_RoutePurgeTimerGet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RoutePurgeTimerGetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BaseServer).RoutePurgeTimerGet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.base.Base/RoutePurgeTimerGet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BaseServer).RoutePurgeTimerGet(ctx, req.(*RoutePurgeTimerGetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Base_ServiceDesc is the grpc.ServiceDesc for Base service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Base_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "jnx.jet.routing.base.Base",
	HandlerType: (*BaseServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RoutePurgeTimerAdd",
			Handler:    _Base_RoutePurgeTimerAdd_Handler,
		},
		{
			MethodName: "RoutePurgeTimerDelete",
			Handler:    _Base_RoutePurgeTimerDelete_Handler,
		},
		{
			MethodName: "RoutePurgeTimerGet",
			Handler:    _Base_RoutePurgeTimerGet_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "jnx_routing_base_service.proto",
}
