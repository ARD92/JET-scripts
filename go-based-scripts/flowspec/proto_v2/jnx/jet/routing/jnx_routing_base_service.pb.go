//
// Copyright 2018-2019, Juniper Networks, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: jnx_routing_base_service.proto

// [brief]: JET Routing Base Package

package routing

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	common "jnx/jet/common"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// [brief]: response status code used by sub-code.
// [detail]: response status code used by sub-code.
// [default]: SUCCESS.
type StatusCode int32

const (
	// [brief]: Success.
	StatusCode_SUCCESS StatusCode = 0
	// [brief]: Invalid parameters.
	StatusCode_INVALID_PARAMS StatusCode = 1
)

// Enum value maps for StatusCode.
var (
	StatusCode_name = map[int32]string{
		0: "SUCCESS",
		1: "INVALID_PARAMS",
	}
	StatusCode_value = map[string]int32{
		"SUCCESS":        0,
		"INVALID_PARAMS": 1,
	}
)

func (x StatusCode) Enum() *StatusCode {
	p := new(StatusCode)
	*p = x
	return p
}

func (x StatusCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (StatusCode) Descriptor() protoreflect.EnumDescriptor {
	return file_jnx_routing_base_service_proto_enumTypes[0].Descriptor()
}

func (StatusCode) Type() protoreflect.EnumType {
	return &file_jnx_routing_base_service_proto_enumTypes[0]
}

func (x StatusCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use StatusCode.Descriptor instead.
func (StatusCode) EnumDescriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{0}
}

// [brief]: Route purge timer add request message.
// [detail]: Route purge timer add request message to set purge timer
// for the client.
type RoutePurgeTimerAddRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: Purge time to be configured for the client.
	// [detail]: The default purge timer is 120 seconds.
	// [range]: 1:1000
	Time uint32 `protobuf:"varint,1,opt,name=time,proto3" json:"time,omitempty"`
}

func (x *RoutePurgeTimerAddRequest) Reset() {
	*x = RoutePurgeTimerAddRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_routing_base_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutePurgeTimerAddRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutePurgeTimerAddRequest) ProtoMessage() {}

func (x *RoutePurgeTimerAddRequest) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_routing_base_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutePurgeTimerAddRequest.ProtoReflect.Descriptor instead.
func (*RoutePurgeTimerAddRequest) Descriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{0}
}

func (x *RoutePurgeTimerAddRequest) GetTime() uint32 {
	if x != nil {
		return x.Time
	}
	return 0
}

// [brief]: Route purge timer get request message.
// [detail]: Route purge timer get request message.
type RoutePurgeTimerGetRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RoutePurgeTimerGetRequest) Reset() {
	*x = RoutePurgeTimerGetRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_routing_base_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutePurgeTimerGetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutePurgeTimerGetRequest) ProtoMessage() {}

func (x *RoutePurgeTimerGetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_routing_base_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutePurgeTimerGetRequest.ProtoReflect.Descriptor instead.
func (*RoutePurgeTimerGetRequest) Descriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{1}
}

// [brief]: Route purge timer delete request message.
// [detail]: Route purge timer delete request message to delete.
// purge timer for the client.
type RoutePurgeTimerDeleteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RoutePurgeTimerDeleteRequest) Reset() {
	*x = RoutePurgeTimerDeleteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_routing_base_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutePurgeTimerDeleteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutePurgeTimerDeleteRequest) ProtoMessage() {}

func (x *RoutePurgeTimerDeleteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_routing_base_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutePurgeTimerDeleteRequest.ProtoReflect.Descriptor instead.
func (*RoutePurgeTimerDeleteRequest) Descriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{2}
}

// [brief]: Route purge timer add response message.
// [detail]: Response message for the purget timer add request.
type RoutePurgeTimerAddResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: Purge Timer add response status.
	Status *common.RpcStatus `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	// [brief]: Purge Timer add response sub_code.
	SubCode StatusCode `protobuf:"varint,2,opt,name=sub_code,json=subCode,proto3,enum=jnx.jet.routing.base.StatusCode" json:"sub_code,omitempty"`
}

func (x *RoutePurgeTimerAddResponse) Reset() {
	*x = RoutePurgeTimerAddResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_routing_base_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutePurgeTimerAddResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutePurgeTimerAddResponse) ProtoMessage() {}

func (x *RoutePurgeTimerAddResponse) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_routing_base_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutePurgeTimerAddResponse.ProtoReflect.Descriptor instead.
func (*RoutePurgeTimerAddResponse) Descriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{3}
}

func (x *RoutePurgeTimerAddResponse) GetStatus() *common.RpcStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *RoutePurgeTimerAddResponse) GetSubCode() StatusCode {
	if x != nil {
		return x.SubCode
	}
	return StatusCode_SUCCESS
}

// [brief]: Route purge timer delete response message.
// [detail]: Route purge timer delete response message.
type RoutePurgeTimerDeleteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: Purge Timer delete response status.
	Status *common.RpcStatus `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	// [brief]: Purge Timer delete response sub_code.
	SubCode StatusCode `protobuf:"varint,2,opt,name=sub_code,json=subCode,proto3,enum=jnx.jet.routing.base.StatusCode" json:"sub_code,omitempty"`
}

func (x *RoutePurgeTimerDeleteResponse) Reset() {
	*x = RoutePurgeTimerDeleteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_routing_base_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutePurgeTimerDeleteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutePurgeTimerDeleteResponse) ProtoMessage() {}

func (x *RoutePurgeTimerDeleteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_routing_base_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutePurgeTimerDeleteResponse.ProtoReflect.Descriptor instead.
func (*RoutePurgeTimerDeleteResponse) Descriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{4}
}

func (x *RoutePurgeTimerDeleteResponse) GetStatus() *common.RpcStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *RoutePurgeTimerDeleteResponse) GetSubCode() StatusCode {
	if x != nil {
		return x.SubCode
	}
	return StatusCode_SUCCESS
}

// [brief]: Route purge timer get response message to get purge timer.
// [detail]: Route purge timer get response message to get purge timer for
// the client.
type RoutePurgeTimerGetResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: Purge Timer get response status.
	Status *common.RpcStatus `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	// [brief]: Purge Timer get response sub_code.
	SubCode StatusCode `protobuf:"varint,2,opt,name=sub_code,json=subCode,proto3,enum=jnx.jet.routing.base.StatusCode" json:"sub_code,omitempty"`
	// [brief]: Purge time in seconds configured for the client.
	// [range]: 1:1000
	Time uint32 `protobuf:"varint,3,opt,name=time,proto3" json:"time,omitempty"`
}

func (x *RoutePurgeTimerGetResponse) Reset() {
	*x = RoutePurgeTimerGetResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_routing_base_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutePurgeTimerGetResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutePurgeTimerGetResponse) ProtoMessage() {}

func (x *RoutePurgeTimerGetResponse) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_routing_base_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutePurgeTimerGetResponse.ProtoReflect.Descriptor instead.
func (*RoutePurgeTimerGetResponse) Descriptor() ([]byte, []int) {
	return file_jnx_routing_base_service_proto_rawDescGZIP(), []int{5}
}

func (x *RoutePurgeTimerGetResponse) GetStatus() *common.RpcStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *RoutePurgeTimerGetResponse) GetSubCode() StatusCode {
	if x != nil {
		return x.SubCode
	}
	return StatusCode_SUCCESS
}

func (x *RoutePurgeTimerGetResponse) GetTime() uint32 {
	if x != nil {
		return x.Time
	}
	return 0
}

var File_jnx_routing_base_service_proto protoreflect.FileDescriptor

var file_jnx_routing_base_service_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x6a, 0x6e, 0x78, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x62, 0x61,
	0x73, 0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x14, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e,
	0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x1a, 0x1b, 0x6a, 0x6e, 0x78, 0x5f, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x5f, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x2f, 0x0a, 0x19, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67,
	0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x41, 0x64, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04,
	0x74, 0x69, 0x6d, 0x65, 0x22, 0x1b, 0x0a, 0x19, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72,
	0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x22, 0x1e, 0x0a, 0x1c, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54,
	0x69, 0x6d, 0x65, 0x72, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x22, 0x8c, 0x01, 0x0a, 0x1a, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65,
	0x54, 0x69, 0x6d, 0x65, 0x72, 0x41, 0x64, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x31, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x52, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x3b, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e,
	0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x07, 0x73, 0x75, 0x62, 0x43, 0x6f, 0x64, 0x65,
	0x22, 0x8f, 0x01, 0x0a, 0x1d, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54,
	0x69, 0x6d, 0x65, 0x72, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x31, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x52, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x3b, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65,
	0x74, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x07, 0x73, 0x75, 0x62, 0x43, 0x6f,
	0x64, 0x65, 0x22, 0xa0, 0x01, 0x0a, 0x1a, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67,
	0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x31, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x19, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x52, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x3b, 0x0a, 0x08, 0x73, 0x75, 0x62, 0x5f, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74,
	0x2e, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x53, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x07, 0x73, 0x75, 0x62, 0x43, 0x6f, 0x64,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x04, 0x74, 0x69, 0x6d, 0x65, 0x2a, 0x2d, 0x0a, 0x0a, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43,
	0x6f, 0x64, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x10, 0x00,
	0x12, 0x12, 0x0a, 0x0e, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x50, 0x41, 0x52, 0x41,
	0x4d, 0x53, 0x10, 0x01, 0x32, 0x81, 0x03, 0x0a, 0x04, 0x42, 0x61, 0x73, 0x65, 0x12, 0x79, 0x0a,
	0x12, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72,
	0x41, 0x64, 0x64, 0x12, 0x2f, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x72, 0x6f,
	0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65,
	0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x41, 0x64, 0x64, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x72,
	0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x41, 0x64, 0x64, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x82, 0x01, 0x0a, 0x15, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x44, 0x65, 0x6c, 0x65,
	0x74, 0x65, 0x12, 0x32, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x72, 0x6f, 0x75,
	0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50,
	0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x33, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74,
	0x2e, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x52, 0x6f,
	0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x44, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x79, 0x0a,
	0x12, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72,
	0x47, 0x65, 0x74, 0x12, 0x2f, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x72, 0x6f,
	0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65,
	0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e, 0x6a, 0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x72,
	0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x50, 0x75, 0x72, 0x67, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x72, 0x47, 0x65, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x22, 0x5a, 0x0f, 0x6a, 0x6e, 0x78, 0x2f,
	0x6a, 0x65, 0x74, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x82, 0xb5, 0x18, 0x05, 0x30,
	0x2e, 0x30, 0x2e, 0x30, 0x8a, 0xb5, 0x18, 0x04, 0x31, 0x39, 0x2e, 0x32, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_jnx_routing_base_service_proto_rawDescOnce sync.Once
	file_jnx_routing_base_service_proto_rawDescData = file_jnx_routing_base_service_proto_rawDesc
)

func file_jnx_routing_base_service_proto_rawDescGZIP() []byte {
	file_jnx_routing_base_service_proto_rawDescOnce.Do(func() {
		file_jnx_routing_base_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_jnx_routing_base_service_proto_rawDescData)
	})
	return file_jnx_routing_base_service_proto_rawDescData
}

var file_jnx_routing_base_service_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_jnx_routing_base_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_jnx_routing_base_service_proto_goTypes = []interface{}{
	(StatusCode)(0),                       // 0: jnx.jet.routing.base.StatusCode
	(*RoutePurgeTimerAddRequest)(nil),     // 1: jnx.jet.routing.base.RoutePurgeTimerAddRequest
	(*RoutePurgeTimerGetRequest)(nil),     // 2: jnx.jet.routing.base.RoutePurgeTimerGetRequest
	(*RoutePurgeTimerDeleteRequest)(nil),  // 3: jnx.jet.routing.base.RoutePurgeTimerDeleteRequest
	(*RoutePurgeTimerAddResponse)(nil),    // 4: jnx.jet.routing.base.RoutePurgeTimerAddResponse
	(*RoutePurgeTimerDeleteResponse)(nil), // 5: jnx.jet.routing.base.RoutePurgeTimerDeleteResponse
	(*RoutePurgeTimerGetResponse)(nil),    // 6: jnx.jet.routing.base.RoutePurgeTimerGetResponse
	(*common.RpcStatus)(nil),              // 7: jnx.jet.common.RpcStatus
}
var file_jnx_routing_base_service_proto_depIdxs = []int32{
	7, // 0: jnx.jet.routing.base.RoutePurgeTimerAddResponse.status:type_name -> jnx.jet.common.RpcStatus
	0, // 1: jnx.jet.routing.base.RoutePurgeTimerAddResponse.sub_code:type_name -> jnx.jet.routing.base.StatusCode
	7, // 2: jnx.jet.routing.base.RoutePurgeTimerDeleteResponse.status:type_name -> jnx.jet.common.RpcStatus
	0, // 3: jnx.jet.routing.base.RoutePurgeTimerDeleteResponse.sub_code:type_name -> jnx.jet.routing.base.StatusCode
	7, // 4: jnx.jet.routing.base.RoutePurgeTimerGetResponse.status:type_name -> jnx.jet.common.RpcStatus
	0, // 5: jnx.jet.routing.base.RoutePurgeTimerGetResponse.sub_code:type_name -> jnx.jet.routing.base.StatusCode
	1, // 6: jnx.jet.routing.base.Base.RoutePurgeTimerAdd:input_type -> jnx.jet.routing.base.RoutePurgeTimerAddRequest
	3, // 7: jnx.jet.routing.base.Base.RoutePurgeTimerDelete:input_type -> jnx.jet.routing.base.RoutePurgeTimerDeleteRequest
	2, // 8: jnx.jet.routing.base.Base.RoutePurgeTimerGet:input_type -> jnx.jet.routing.base.RoutePurgeTimerGetRequest
	4, // 9: jnx.jet.routing.base.Base.RoutePurgeTimerAdd:output_type -> jnx.jet.routing.base.RoutePurgeTimerAddResponse
	5, // 10: jnx.jet.routing.base.Base.RoutePurgeTimerDelete:output_type -> jnx.jet.routing.base.RoutePurgeTimerDeleteResponse
	6, // 11: jnx.jet.routing.base.Base.RoutePurgeTimerGet:output_type -> jnx.jet.routing.base.RoutePurgeTimerGetResponse
	9, // [9:12] is the sub-list for method output_type
	6, // [6:9] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_jnx_routing_base_service_proto_init() }
func file_jnx_routing_base_service_proto_init() {
	if File_jnx_routing_base_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_jnx_routing_base_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutePurgeTimerAddRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_jnx_routing_base_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutePurgeTimerGetRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_jnx_routing_base_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutePurgeTimerDeleteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_jnx_routing_base_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutePurgeTimerAddResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_jnx_routing_base_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutePurgeTimerDeleteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_jnx_routing_base_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutePurgeTimerGetResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_jnx_routing_base_service_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_jnx_routing_base_service_proto_goTypes,
		DependencyIndexes: file_jnx_routing_base_service_proto_depIdxs,
		EnumInfos:         file_jnx_routing_base_service_proto_enumTypes,
		MessageInfos:      file_jnx_routing_base_service_proto_msgTypes,
	}.Build()
	File_jnx_routing_base_service_proto = out.File
	file_jnx_routing_base_service_proto_rawDesc = nil
	file_jnx_routing_base_service_proto_goTypes = nil
	file_jnx_routing_base_service_proto_depIdxs = nil
}
