// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: jnx_management_service.proto

package mgmt

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

// ManagementClient is the client API for Management service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ManagementClient interface {
	// [brief]: Run an operational command
	// [detail]: This RPC returns the operational command output as a streamed response
	OpCommandGet(ctx context.Context, in *OpCommandGetRequest, opts ...grpc.CallOption) (Management_OpCommandGetClient, error)
	// [brief]: Perform configuration operation on static database
	// [detail]: Load and commit configuration onto a Junos device
	ConfigSet(ctx context.Context, in *ConfigSetRequest, opts ...grpc.CallOption) (*ConfigSetResponse, error)
	// [brief]: Retrieve epehemral configuration from the device
	// [detail]: Retrieve epehemral configuration from the device
	EphemeralConfigGet(ctx context.Context, in *EphemeralConfigGetRequest, opts ...grpc.CallOption) (*EphemeralConfigGetResponse, error)
	// [brief]: Perform configuration operation on the ephemeral database
	// [detail]: Load and commit configuration onto Junos device's epehemral database
	EphemeralConfigSet(ctx context.Context, in *EphemeralConfigSetRequest, opts ...grpc.CallOption) (*EphemeralConfigSetResponse, error)
}

type managementClient struct {
	cc grpc.ClientConnInterface
}

func NewManagementClient(cc grpc.ClientConnInterface) ManagementClient {
	return &managementClient{cc}
}

func (c *managementClient) OpCommandGet(ctx context.Context, in *OpCommandGetRequest, opts ...grpc.CallOption) (Management_OpCommandGetClient, error) {
	stream, err := c.cc.NewStream(ctx, &Management_ServiceDesc.Streams[0], "/jnx.jet.management.Management/OpCommandGet", opts...)
	if err != nil {
		return nil, err
	}
	x := &managementOpCommandGetClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Management_OpCommandGetClient interface {
	Recv() (*OpCommandGetResponse, error)
	grpc.ClientStream
}

type managementOpCommandGetClient struct {
	grpc.ClientStream
}

func (x *managementOpCommandGetClient) Recv() (*OpCommandGetResponse, error) {
	m := new(OpCommandGetResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *managementClient) ConfigSet(ctx context.Context, in *ConfigSetRequest, opts ...grpc.CallOption) (*ConfigSetResponse, error) {
	out := new(ConfigSetResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.management.Management/ConfigSet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementClient) EphemeralConfigGet(ctx context.Context, in *EphemeralConfigGetRequest, opts ...grpc.CallOption) (*EphemeralConfigGetResponse, error) {
	out := new(EphemeralConfigGetResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.management.Management/EphemeralConfigGet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementClient) EphemeralConfigSet(ctx context.Context, in *EphemeralConfigSetRequest, opts ...grpc.CallOption) (*EphemeralConfigSetResponse, error) {
	out := new(EphemeralConfigSetResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.management.Management/EphemeralConfigSet", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ManagementServer is the server API for Management service.
// All implementations must embed UnimplementedManagementServer
// for forward compatibility
type ManagementServer interface {
	// [brief]: Run an operational command
	// [detail]: This RPC returns the operational command output as a streamed response
	OpCommandGet(*OpCommandGetRequest, Management_OpCommandGetServer) error
	// [brief]: Perform configuration operation on static database
	// [detail]: Load and commit configuration onto a Junos device
	ConfigSet(context.Context, *ConfigSetRequest) (*ConfigSetResponse, error)
	// [brief]: Retrieve epehemral configuration from the device
	// [detail]: Retrieve epehemral configuration from the device
	EphemeralConfigGet(context.Context, *EphemeralConfigGetRequest) (*EphemeralConfigGetResponse, error)
	// [brief]: Perform configuration operation on the ephemeral database
	// [detail]: Load and commit configuration onto Junos device's epehemral database
	EphemeralConfigSet(context.Context, *EphemeralConfigSetRequest) (*EphemeralConfigSetResponse, error)
	mustEmbedUnimplementedManagementServer()
}

// UnimplementedManagementServer must be embedded to have forward compatible implementations.
type UnimplementedManagementServer struct {
}

func (UnimplementedManagementServer) OpCommandGet(*OpCommandGetRequest, Management_OpCommandGetServer) error {
	return status.Errorf(codes.Unimplemented, "method OpCommandGet not implemented")
}
func (UnimplementedManagementServer) ConfigSet(context.Context, *ConfigSetRequest) (*ConfigSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConfigSet not implemented")
}
func (UnimplementedManagementServer) EphemeralConfigGet(context.Context, *EphemeralConfigGetRequest) (*EphemeralConfigGetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EphemeralConfigGet not implemented")
}
func (UnimplementedManagementServer) EphemeralConfigSet(context.Context, *EphemeralConfigSetRequest) (*EphemeralConfigSetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EphemeralConfigSet not implemented")
}
func (UnimplementedManagementServer) mustEmbedUnimplementedManagementServer() {}

// UnsafeManagementServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ManagementServer will
// result in compilation errors.
type UnsafeManagementServer interface {
	mustEmbedUnimplementedManagementServer()
}

func RegisterManagementServer(s grpc.ServiceRegistrar, srv ManagementServer) {
	s.RegisterService(&Management_ServiceDesc, srv)
}

func _Management_OpCommandGet_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(OpCommandGetRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ManagementServer).OpCommandGet(m, &managementOpCommandGetServer{stream})
}

type Management_OpCommandGetServer interface {
	Send(*OpCommandGetResponse) error
	grpc.ServerStream
}

type managementOpCommandGetServer struct {
	grpc.ServerStream
}

func (x *managementOpCommandGetServer) Send(m *OpCommandGetResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _Management_ConfigSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConfigSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServer).ConfigSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.management.Management/ConfigSet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServer).ConfigSet(ctx, req.(*ConfigSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Management_EphemeralConfigGet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EphemeralConfigGetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServer).EphemeralConfigGet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.management.Management/EphemeralConfigGet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServer).EphemeralConfigGet(ctx, req.(*EphemeralConfigGetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Management_EphemeralConfigSet_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EphemeralConfigSetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServer).EphemeralConfigSet(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.management.Management/EphemeralConfigSet",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServer).EphemeralConfigSet(ctx, req.(*EphemeralConfigSetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Management_ServiceDesc is the grpc.ServiceDesc for Management service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Management_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "jnx.jet.management.Management",
	HandlerType: (*ManagementServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ConfigSet",
			Handler:    _Management_ConfigSet_Handler,
		},
		{
			MethodName: "EphemeralConfigGet",
			Handler:    _Management_EphemeralConfigGet_Handler,
		},
		{
			MethodName: "EphemeralConfigSet",
			Handler:    _Management_EphemeralConfigSet_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "OpCommandGet",
			Handler:       _Management_OpCommandGet_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "jnx_management_service.proto",
}
