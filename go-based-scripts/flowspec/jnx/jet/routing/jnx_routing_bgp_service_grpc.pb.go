// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: jnx_routing_bgp_service.proto

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

// BgpClient is the client API for Bgp service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BgpClient interface {
	// [brief]: BGP Routing Initialize operation.
	// [detail]: Initialize RPC must be called upon connection or reconnection
	// to the server. If the client is connecting for the first time, the
	// server will initialize per-client state for the connection.
	//
	// If the client is reconnecting with the same client name following a
	// connection fault (having not closed a previous connection with
	// Cleanup), then gateway and route state will be rebound to
	// the new connection.
	//
	// In this case, the return status will indicate that state was rebound
	// and the client need not reply the previous routing state to the
	// server.
	//
	// Initialization RPC can be called multiple times and the default parameters
	// will be updated with the latest values from the initialization request.
	Initialize(ctx context.Context, in *InitializeRequest, opts ...grpc.CallOption) (*InitializeResponse, error)
	// [brief]: BGP Routing Cleanup operation.
	// [detail]: Cleanup will purge all gateway and route state for the
	// client.
	Cleanup(ctx context.Context, in *CleanupRequest, opts ...grpc.CallOption) (*CleanupResponse, error)
	// [brief]: BGP Route Add operation.
	// [detail]: Add a BGP-Static route to the routing table.
	// RouteAdd may be called multiple times for the same prefix to add
	// multiple paths with distinct path_cookie for the same destination.
	// If a matching route already exists in the given table, then an error
	// will be returned.
	//
	// RouteUpdateRequest may contain from one to 1000 routes
	// to be added.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully created
	// prior to any error or full completion of the request.
	RouteAdd(ctx context.Context, in *RouteUpdateRequest, opts ...grpc.CallOption) (*RouteOperResponse, error)
	// [brief]: BGP Route Modify operation.
	// [detail]: Modify an existing BGP-Static route in the routing table.
	// For each route in the request, if the key is matched, the matched
	// route will be updated with the supplied route attributes.
	// If a matching route does not exist in the given table, then an error
	// will be returned.
	//
	// RouteUpdateRequest may contain from one to 1000 routes
	// to be added.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully modified
	// prior to any error or full completion of the request.
	RouteModify(ctx context.Context, in *RouteUpdateRequest, opts ...grpc.CallOption) (*RouteOperResponse, error)
	// [brief]: BGP Route Update operation.
	// [detail]: Create a new BGP-Static route if a matching route does not exist, OR
	// modify an existing BGP-Static route if it is already present in the
	// routing table.
	//
	// RouteUpdateRequest may contain from one to 1000 routes
	// to be added.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully modified
	// prior to any error or full completion of the request.
	RouteUpdate(ctx context.Context, in *RouteUpdateRequest, opts ...grpc.CallOption) (*RouteOperResponse, error)
	// [brief]: BGP Route Delete operation.
	// [detail]: Delete a BGP-Static route from the routing table.
	// RouteDelete may be called multiple times for the same prefix
	// to delete multiple paths with distinct path_cookie for the same
	// destination.
	//
	// The request may contain from one to 1000 routes
	// to be deleted.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully modified
	// prior to any error or full completion of the request.
	RouteDelete(ctx context.Context, in *RouteDeleteRequest, opts ...grpc.CallOption) (*RouteOperResponse, error)
	// [brief]: BGP Route Get operation.
	// [detail]: Lookup a BGP or BGP-Static protocol route from the routing
	// table. All match parameters are optional.
	// Match fields that are not specified or that
	// may match more than one route (e.g. a less-specific destination
	// prefix) may result in multiple routes being returned in the replies.
	// Only BGP and BGP-Static routes will be matched.
	//
	// Replies are streamed until all match routes have been sent. The
	// client will receive a final null message once all routes have
	// been received.
	//
	// The server's walk of search results is not atomic so route changes
	// during streaming and consumption of replies may or may not be
	// reflected in the results.
	RouteGet(ctx context.Context, in *RouteGetRequest, opts ...grpc.CallOption) (Bgp_RouteGetClient, error)
	// [brief]: BGP Route Subscribe.
	// [detail]: Subscribe to receive updates streamed from BGP when routes
	// matching the bgp-import "analyze" policy action are added, modified,
	// or withdrawn by BGP peers.
	//
	// Updates will be streamed as RouteSubscribeResponse messages
	// after RouteSubscribe RPC is called.
	//
	// Upon initial registration, a full download of route ADD operations for
	// all routes matching the "analyze" import policy action will be
	// streamed, followed by a closing END_OF_RIB operation. Subsequently,
	// incremental updates will be streamed whenever BGP advertisements
	// from peers are added, modified, or withdrawn, or when BGP import
	// "analyze" policy is changed.
	//
	// There is no strict ordering of routes in the update stream and
	// state compression is applied when applicable to a set of operations.
	RouteSubscribe(ctx context.Context, in *RouteSubscribeRequest, opts ...grpc.CallOption) (Bgp_RouteSubscribeClient, error)
	// [brief]: BGP Route Unsubscribe.
	// [detail]: Unsubscribe to receive updates streamed from BGP when
	// routes are added, modified, or withdrawn by BGP peers.
	RouteUnsubscribe(ctx context.Context, in *RouteUnsubscribeRequest, opts ...grpc.CallOption) (*RouteUnsubscribeResponse, error)
	// [brief]: BGP Route Refresh.
	// [detail]: Request to refresh all route entries to the client.
	RouteRefresh(ctx context.Context, in *RouteRefreshRequest, opts ...grpc.CallOption) (*RouteRefreshResponse, error)
}

type bgpClient struct {
	cc grpc.ClientConnInterface
}

func NewBgpClient(cc grpc.ClientConnInterface) BgpClient {
	return &bgpClient{cc}
}

func (c *bgpClient) Initialize(ctx context.Context, in *InitializeRequest, opts ...grpc.CallOption) (*InitializeResponse, error) {
	out := new(InitializeResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/Initialize", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) Cleanup(ctx context.Context, in *CleanupRequest, opts ...grpc.CallOption) (*CleanupResponse, error) {
	out := new(CleanupResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/Cleanup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) RouteAdd(ctx context.Context, in *RouteUpdateRequest, opts ...grpc.CallOption) (*RouteOperResponse, error) {
	out := new(RouteOperResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/RouteAdd", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) RouteModify(ctx context.Context, in *RouteUpdateRequest, opts ...grpc.CallOption) (*RouteOperResponse, error) {
	out := new(RouteOperResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/RouteModify", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) RouteUpdate(ctx context.Context, in *RouteUpdateRequest, opts ...grpc.CallOption) (*RouteOperResponse, error) {
	out := new(RouteOperResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/RouteUpdate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) RouteDelete(ctx context.Context, in *RouteDeleteRequest, opts ...grpc.CallOption) (*RouteOperResponse, error) {
	out := new(RouteOperResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/RouteDelete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) RouteGet(ctx context.Context, in *RouteGetRequest, opts ...grpc.CallOption) (Bgp_RouteGetClient, error) {
	stream, err := c.cc.NewStream(ctx, &Bgp_ServiceDesc.Streams[0], "/jnx.jet.routing.bgp.Bgp/RouteGet", opts...)
	if err != nil {
		return nil, err
	}
	x := &bgpRouteGetClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Bgp_RouteGetClient interface {
	Recv() (*RouteGetResponse, error)
	grpc.ClientStream
}

type bgpRouteGetClient struct {
	grpc.ClientStream
}

func (x *bgpRouteGetClient) Recv() (*RouteGetResponse, error) {
	m := new(RouteGetResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *bgpClient) RouteSubscribe(ctx context.Context, in *RouteSubscribeRequest, opts ...grpc.CallOption) (Bgp_RouteSubscribeClient, error) {
	stream, err := c.cc.NewStream(ctx, &Bgp_ServiceDesc.Streams[1], "/jnx.jet.routing.bgp.Bgp/RouteSubscribe", opts...)
	if err != nil {
		return nil, err
	}
	x := &bgpRouteSubscribeClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Bgp_RouteSubscribeClient interface {
	Recv() (*RouteSubscribeResponse, error)
	grpc.ClientStream
}

type bgpRouteSubscribeClient struct {
	grpc.ClientStream
}

func (x *bgpRouteSubscribeClient) Recv() (*RouteSubscribeResponse, error) {
	m := new(RouteSubscribeResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *bgpClient) RouteUnsubscribe(ctx context.Context, in *RouteUnsubscribeRequest, opts ...grpc.CallOption) (*RouteUnsubscribeResponse, error) {
	out := new(RouteUnsubscribeResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/RouteUnsubscribe", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *bgpClient) RouteRefresh(ctx context.Context, in *RouteRefreshRequest, opts ...grpc.CallOption) (*RouteRefreshResponse, error) {
	out := new(RouteRefreshResponse)
	err := c.cc.Invoke(ctx, "/jnx.jet.routing.bgp.Bgp/RouteRefresh", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BgpServer is the server API for Bgp service.
// All implementations must embed UnimplementedBgpServer
// for forward compatibility
type BgpServer interface {
	// [brief]: BGP Routing Initialize operation.
	// [detail]: Initialize RPC must be called upon connection or reconnection
	// to the server. If the client is connecting for the first time, the
	// server will initialize per-client state for the connection.
	//
	// If the client is reconnecting with the same client name following a
	// connection fault (having not closed a previous connection with
	// Cleanup), then gateway and route state will be rebound to
	// the new connection.
	//
	// In this case, the return status will indicate that state was rebound
	// and the client need not reply the previous routing state to the
	// server.
	//
	// Initialization RPC can be called multiple times and the default parameters
	// will be updated with the latest values from the initialization request.
	Initialize(context.Context, *InitializeRequest) (*InitializeResponse, error)
	// [brief]: BGP Routing Cleanup operation.
	// [detail]: Cleanup will purge all gateway and route state for the
	// client.
	Cleanup(context.Context, *CleanupRequest) (*CleanupResponse, error)
	// [brief]: BGP Route Add operation.
	// [detail]: Add a BGP-Static route to the routing table.
	// RouteAdd may be called multiple times for the same prefix to add
	// multiple paths with distinct path_cookie for the same destination.
	// If a matching route already exists in the given table, then an error
	// will be returned.
	//
	// RouteUpdateRequest may contain from one to 1000 routes
	// to be added.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully created
	// prior to any error or full completion of the request.
	RouteAdd(context.Context, *RouteUpdateRequest) (*RouteOperResponse, error)
	// [brief]: BGP Route Modify operation.
	// [detail]: Modify an existing BGP-Static route in the routing table.
	// For each route in the request, if the key is matched, the matched
	// route will be updated with the supplied route attributes.
	// If a matching route does not exist in the given table, then an error
	// will be returned.
	//
	// RouteUpdateRequest may contain from one to 1000 routes
	// to be added.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully modified
	// prior to any error or full completion of the request.
	RouteModify(context.Context, *RouteUpdateRequest) (*RouteOperResponse, error)
	// [brief]: BGP Route Update operation.
	// [detail]: Create a new BGP-Static route if a matching route does not exist, OR
	// modify an existing BGP-Static route if it is already present in the
	// routing table.
	//
	// RouteUpdateRequest may contain from one to 1000 routes
	// to be added.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully modified
	// prior to any error or full completion of the request.
	RouteUpdate(context.Context, *RouteUpdateRequest) (*RouteOperResponse, error)
	// [brief]: BGP Route Delete operation.
	// [detail]: Delete a BGP-Static route from the routing table.
	// RouteDelete may be called multiple times for the same prefix
	// to delete multiple paths with distinct path_cookie for the same
	// destination.
	//
	// The request may contain from one to 1000 routes
	// to be deleted.
	// If the request contains multiple routes, the routes will
	// be processed in the order given and the first error encountered will
	// cause the request to abort.
	//
	// The API always returns the final status (success or first error
	// encountered) and the number of routes that were successfully modified
	// prior to any error or full completion of the request.
	RouteDelete(context.Context, *RouteDeleteRequest) (*RouteOperResponse, error)
	// [brief]: BGP Route Get operation.
	// [detail]: Lookup a BGP or BGP-Static protocol route from the routing
	// table. All match parameters are optional.
	// Match fields that are not specified or that
	// may match more than one route (e.g. a less-specific destination
	// prefix) may result in multiple routes being returned in the replies.
	// Only BGP and BGP-Static routes will be matched.
	//
	// Replies are streamed until all match routes have been sent. The
	// client will receive a final null message once all routes have
	// been received.
	//
	// The server's walk of search results is not atomic so route changes
	// during streaming and consumption of replies may or may not be
	// reflected in the results.
	RouteGet(*RouteGetRequest, Bgp_RouteGetServer) error
	// [brief]: BGP Route Subscribe.
	// [detail]: Subscribe to receive updates streamed from BGP when routes
	// matching the bgp-import "analyze" policy action are added, modified,
	// or withdrawn by BGP peers.
	//
	// Updates will be streamed as RouteSubscribeResponse messages
	// after RouteSubscribe RPC is called.
	//
	// Upon initial registration, a full download of route ADD operations for
	// all routes matching the "analyze" import policy action will be
	// streamed, followed by a closing END_OF_RIB operation. Subsequently,
	// incremental updates will be streamed whenever BGP advertisements
	// from peers are added, modified, or withdrawn, or when BGP import
	// "analyze" policy is changed.
	//
	// There is no strict ordering of routes in the update stream and
	// state compression is applied when applicable to a set of operations.
	RouteSubscribe(*RouteSubscribeRequest, Bgp_RouteSubscribeServer) error
	// [brief]: BGP Route Unsubscribe.
	// [detail]: Unsubscribe to receive updates streamed from BGP when
	// routes are added, modified, or withdrawn by BGP peers.
	RouteUnsubscribe(context.Context, *RouteUnsubscribeRequest) (*RouteUnsubscribeResponse, error)
	// [brief]: BGP Route Refresh.
	// [detail]: Request to refresh all route entries to the client.
	RouteRefresh(context.Context, *RouteRefreshRequest) (*RouteRefreshResponse, error)
	mustEmbedUnimplementedBgpServer()
}

// UnimplementedBgpServer must be embedded to have forward compatible implementations.
type UnimplementedBgpServer struct {
}

func (UnimplementedBgpServer) Initialize(context.Context, *InitializeRequest) (*InitializeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Initialize not implemented")
}
func (UnimplementedBgpServer) Cleanup(context.Context, *CleanupRequest) (*CleanupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Cleanup not implemented")
}
func (UnimplementedBgpServer) RouteAdd(context.Context, *RouteUpdateRequest) (*RouteOperResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteAdd not implemented")
}
func (UnimplementedBgpServer) RouteModify(context.Context, *RouteUpdateRequest) (*RouteOperResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteModify not implemented")
}
func (UnimplementedBgpServer) RouteUpdate(context.Context, *RouteUpdateRequest) (*RouteOperResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteUpdate not implemented")
}
func (UnimplementedBgpServer) RouteDelete(context.Context, *RouteDeleteRequest) (*RouteOperResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteDelete not implemented")
}
func (UnimplementedBgpServer) RouteGet(*RouteGetRequest, Bgp_RouteGetServer) error {
	return status.Errorf(codes.Unimplemented, "method RouteGet not implemented")
}
func (UnimplementedBgpServer) RouteSubscribe(*RouteSubscribeRequest, Bgp_RouteSubscribeServer) error {
	return status.Errorf(codes.Unimplemented, "method RouteSubscribe not implemented")
}
func (UnimplementedBgpServer) RouteUnsubscribe(context.Context, *RouteUnsubscribeRequest) (*RouteUnsubscribeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteUnsubscribe not implemented")
}
func (UnimplementedBgpServer) RouteRefresh(context.Context, *RouteRefreshRequest) (*RouteRefreshResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RouteRefresh not implemented")
}
func (UnimplementedBgpServer) mustEmbedUnimplementedBgpServer() {}

// UnsafeBgpServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BgpServer will
// result in compilation errors.
type UnsafeBgpServer interface {
	mustEmbedUnimplementedBgpServer()
}

func RegisterBgpServer(s grpc.ServiceRegistrar, srv BgpServer) {
	s.RegisterService(&Bgp_ServiceDesc, srv)
}

func _Bgp_Initialize_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InitializeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).Initialize(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/Initialize",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).Initialize(ctx, req.(*InitializeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_Cleanup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CleanupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).Cleanup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/Cleanup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).Cleanup(ctx, req.(*CleanupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_RouteAdd_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).RouteAdd(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/RouteAdd",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).RouteAdd(ctx, req.(*RouteUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_RouteModify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).RouteModify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/RouteModify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).RouteModify(ctx, req.(*RouteUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_RouteUpdate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).RouteUpdate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/RouteUpdate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).RouteUpdate(ctx, req.(*RouteUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_RouteDelete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).RouteDelete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/RouteDelete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).RouteDelete(ctx, req.(*RouteDeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_RouteGet_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(RouteGetRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(BgpServer).RouteGet(m, &bgpRouteGetServer{stream})
}

type Bgp_RouteGetServer interface {
	Send(*RouteGetResponse) error
	grpc.ServerStream
}

type bgpRouteGetServer struct {
	grpc.ServerStream
}

func (x *bgpRouteGetServer) Send(m *RouteGetResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _Bgp_RouteSubscribe_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(RouteSubscribeRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(BgpServer).RouteSubscribe(m, &bgpRouteSubscribeServer{stream})
}

type Bgp_RouteSubscribeServer interface {
	Send(*RouteSubscribeResponse) error
	grpc.ServerStream
}

type bgpRouteSubscribeServer struct {
	grpc.ServerStream
}

func (x *bgpRouteSubscribeServer) Send(m *RouteSubscribeResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _Bgp_RouteUnsubscribe_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteUnsubscribeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).RouteUnsubscribe(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/RouteUnsubscribe",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).RouteUnsubscribe(ctx, req.(*RouteUnsubscribeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Bgp_RouteRefresh_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RouteRefreshRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BgpServer).RouteRefresh(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/jnx.jet.routing.bgp.Bgp/RouteRefresh",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BgpServer).RouteRefresh(ctx, req.(*RouteRefreshRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Bgp_ServiceDesc is the grpc.ServiceDesc for Bgp service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Bgp_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "jnx.jet.routing.bgp.Bgp",
	HandlerType: (*BgpServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Initialize",
			Handler:    _Bgp_Initialize_Handler,
		},
		{
			MethodName: "Cleanup",
			Handler:    _Bgp_Cleanup_Handler,
		},
		{
			MethodName: "RouteAdd",
			Handler:    _Bgp_RouteAdd_Handler,
		},
		{
			MethodName: "RouteModify",
			Handler:    _Bgp_RouteModify_Handler,
		},
		{
			MethodName: "RouteUpdate",
			Handler:    _Bgp_RouteUpdate_Handler,
		},
		{
			MethodName: "RouteDelete",
			Handler:    _Bgp_RouteDelete_Handler,
		},
		{
			MethodName: "RouteUnsubscribe",
			Handler:    _Bgp_RouteUnsubscribe_Handler,
		},
		{
			MethodName: "RouteRefresh",
			Handler:    _Bgp_RouteRefresh_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RouteGet",
			Handler:       _Bgp_RouteGet_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "RouteSubscribe",
			Handler:       _Bgp_RouteSubscribe_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "jnx_routing_bgp_service.proto",
}