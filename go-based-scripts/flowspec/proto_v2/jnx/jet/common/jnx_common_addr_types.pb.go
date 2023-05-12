//
// Copyright 2018-2021, Juniper Networks, Inc.
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
// source: jnx_common_addr_types.proto

// [brief]: JET Common Package

package common

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// [brief]: Network address format used by server
// [detail]: The format of network addresses that the server is to use when
// responding to client requests.
// [default]: ADDRESS_STRING
type AddressFormat int32

const (
	// [brief]: Addreses in replies will be represented by strings
	AddressFormat_ADDRESS_STRING AddressFormat = 0
	// [brief]: Addreses in replies represented by binary data in byte arrays
	AddressFormat_ADDRESS_BYTES AddressFormat = 1
)

// Enum value maps for AddressFormat.
var (
	AddressFormat_name = map[int32]string{
		0: "ADDRESS_STRING",
		1: "ADDRESS_BYTES",
	}
	AddressFormat_value = map[string]int32{
		"ADDRESS_STRING": 0,
		"ADDRESS_BYTES":  1,
	}
)

func (x AddressFormat) Enum() *AddressFormat {
	p := new(AddressFormat)
	*p = x
	return p
}

func (x AddressFormat) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AddressFormat) Descriptor() protoreflect.EnumDescriptor {
	return file_jnx_common_addr_types_proto_enumTypes[0].Descriptor()
}

func (AddressFormat) Type() protoreflect.EnumType {
	return &file_jnx_common_addr_types_proto_enumTypes[0]
}

func (x AddressFormat) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AddressFormat.Descriptor instead.
func (AddressFormat) EnumDescriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{0}
}

// [brief]: Address family of a network address.
// [detail]: Address family of a network address.
// [default]: AF_UNSPECIFIED
type AfType int32

const (
	// [brief]: Not specified
	AfType_AF_UNSPECIFIED AfType = 0
	// [brief]: IPv4 address family
	AfType_AF_INET AfType = 1
	// [brief]: IPv6 address family
	AfType_AF_INET6 AfType = 2
	// [brief]: Ethernet MAC address family
	AfType_AF_MAC AfType = 3
	// [brief]: mpls address family
	AfType_AF_MPLS AfType = 4
	// [brief]: iso address family
	AfType_AF_ISO AfType = 5
)

// Enum value maps for AfType.
var (
	AfType_name = map[int32]string{
		0: "AF_UNSPECIFIED",
		1: "AF_INET",
		2: "AF_INET6",
		3: "AF_MAC",
		4: "AF_MPLS",
		5: "AF_ISO",
	}
	AfType_value = map[string]int32{
		"AF_UNSPECIFIED": 0,
		"AF_INET":        1,
		"AF_INET6":       2,
		"AF_MAC":         3,
		"AF_MPLS":        4,
		"AF_ISO":         5,
	}
)

func (x AfType) Enum() *AfType {
	p := new(AfType)
	*p = x
	return p
}

func (x AfType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AfType) Descriptor() protoreflect.EnumDescriptor {
	return file_jnx_common_addr_types_proto_enumTypes[1].Descriptor()
}

func (AfType) Type() protoreflect.EnumType {
	return &file_jnx_common_addr_types_proto_enumTypes[1]
}

func (x AfType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AfType.Descriptor instead.
func (AfType) EnumDescriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{1}
}

// [brief]: TCP Flags.
// [detail]: TCP flags for which TCP header can be matched.
// [default]: TCP_FLAG_INVALID
type TcpFlags int32

const (
	// [brief]: Invalid flag. This flag is not used.
	TcpFlags_TCP_FLAG_INVALID TcpFlags = 0
	// [brief]: TCP Finished flag.
	TcpFlags_TCP_FLAG_FIN TcpFlags = 1
	// [brief]: TCP Synchronisation flag.
	TcpFlags_TCP_FLAG_SYN TcpFlags = 2
	// [brief]: TCP Reset flag.
	TcpFlags_TCP_FLAG_RST TcpFlags = 4
	// [brief]: TCP push flag.
	TcpFlags_TCP_FLAG_PUSH TcpFlags = 8
	// [brief]: TCP acknowledgement flag.
	TcpFlags_TCP_FLAG_ACK TcpFlags = 16
	// [brief]: TCP Urgent flag.
	TcpFlags_TCP_FLAG_URGENT TcpFlags = 32
)

// Enum value maps for TcpFlags.
var (
	TcpFlags_name = map[int32]string{
		0:  "TCP_FLAG_INVALID",
		1:  "TCP_FLAG_FIN",
		2:  "TCP_FLAG_SYN",
		4:  "TCP_FLAG_RST",
		8:  "TCP_FLAG_PUSH",
		16: "TCP_FLAG_ACK",
		32: "TCP_FLAG_URGENT",
	}
	TcpFlags_value = map[string]int32{
		"TCP_FLAG_INVALID": 0,
		"TCP_FLAG_FIN":     1,
		"TCP_FLAG_SYN":     2,
		"TCP_FLAG_RST":     4,
		"TCP_FLAG_PUSH":    8,
		"TCP_FLAG_ACK":     16,
		"TCP_FLAG_URGENT":  32,
	}
)

func (x TcpFlags) Enum() *TcpFlags {
	p := new(TcpFlags)
	*p = x
	return p
}

func (x TcpFlags) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TcpFlags) Descriptor() protoreflect.EnumDescriptor {
	return file_jnx_common_addr_types_proto_enumTypes[2].Descriptor()
}

func (TcpFlags) Type() protoreflect.EnumType {
	return &file_jnx_common_addr_types_proto_enumTypes[2]
}

func (x TcpFlags) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TcpFlags.Descriptor instead.
func (TcpFlags) EnumDescriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{2}
}

// [brief]: IP Address representation
// [detail]: An IP address, which may be either IPv4 or IPv6 and be respresented
// by either a string or array of binary bytes.
type IpAddress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: IP address format
	//
	// Types that are assignable to AddrFormat:
	//
	//	*IpAddress_AddrString
	//	*IpAddress_AddrBytes
	AddrFormat isIpAddress_AddrFormat `protobuf_oneof:"addr_format"`
}

func (x *IpAddress) Reset() {
	*x = IpAddress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_common_addr_types_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpAddress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpAddress) ProtoMessage() {}

func (x *IpAddress) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_common_addr_types_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpAddress.ProtoReflect.Descriptor instead.
func (*IpAddress) Descriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{0}
}

func (m *IpAddress) GetAddrFormat() isIpAddress_AddrFormat {
	if m != nil {
		return m.AddrFormat
	}
	return nil
}

func (x *IpAddress) GetAddrString() string {
	if x, ok := x.GetAddrFormat().(*IpAddress_AddrString); ok {
		return x.AddrString
	}
	return ""
}

func (x *IpAddress) GetAddrBytes() []byte {
	if x, ok := x.GetAddrFormat().(*IpAddress_AddrBytes); ok {
		return x.AddrBytes
	}
	return nil
}

type isIpAddress_AddrFormat interface {
	isIpAddress_AddrFormat()
}

type IpAddress_AddrString struct {
	// [brief]: IP address string in standard format
	AddrString string `protobuf:"bytes,1,opt,name=addr_string,json=addrString,proto3,oneof"`
}

type IpAddress_AddrBytes struct {
	// [brief]: Binary IP address in network-ordered array of bytes
	AddrBytes []byte `protobuf:"bytes,2,opt,name=addr_bytes,json=addrBytes,proto3,oneof"`
}

func (*IpAddress_AddrString) isIpAddress_AddrFormat() {}

func (*IpAddress_AddrBytes) isIpAddress_AddrFormat() {}

// [brief]: Mac Address representation
// [detail]: An ethernet MAC address, which may be respresented by either a
// string or array of binary bytes.
type MacAddress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: MAC Address format
	//
	// Types that are assignable to AddrFormat:
	//
	//	*MacAddress_AddrString
	//	*MacAddress_AddrBytes
	AddrFormat isMacAddress_AddrFormat `protobuf_oneof:"addr_format"`
}

func (x *MacAddress) Reset() {
	*x = MacAddress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_common_addr_types_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MacAddress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MacAddress) ProtoMessage() {}

func (x *MacAddress) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_common_addr_types_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MacAddress.ProtoReflect.Descriptor instead.
func (*MacAddress) Descriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{1}
}

func (m *MacAddress) GetAddrFormat() isMacAddress_AddrFormat {
	if m != nil {
		return m.AddrFormat
	}
	return nil
}

func (x *MacAddress) GetAddrString() string {
	if x, ok := x.GetAddrFormat().(*MacAddress_AddrString); ok {
		return x.AddrString
	}
	return ""
}

func (x *MacAddress) GetAddrBytes() []byte {
	if x, ok := x.GetAddrFormat().(*MacAddress_AddrBytes); ok {
		return x.AddrBytes
	}
	return nil
}

type isMacAddress_AddrFormat interface {
	isMacAddress_AddrFormat()
}

type MacAddress_AddrString struct {
	// [brief]: MAC address string in standard format
	AddrString string `protobuf:"bytes,1,opt,name=addr_string,json=addrString,proto3,oneof"`
}

type MacAddress_AddrBytes struct {
	// [brief]: Binary MAC address in network-ordered array of bytes
	AddrBytes []byte `protobuf:"bytes,2,opt,name=addr_bytes,json=addrBytes,proto3,oneof"`
}

func (*MacAddress_AddrString) isMacAddress_AddrFormat() {}

func (*MacAddress_AddrBytes) isMacAddress_AddrFormat() {}

// [brief]: Network IP Address representation
// [detail]: An IP address, which may be either IPv4 or IPv6 and be represented
// by either a string or array of binary bytes.
// The prefix_len field should be used to specify the prefix length of the
// address.
type IpNetwork struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: Only the host address should be provided using this.
	//
	// Types that are assignable to AddrFormat:
	//
	//	*IpNetwork_HostAddrString
	//	*IpNetwork_HostAddrBytes
	AddrFormat isIpNetwork_AddrFormat `protobuf_oneof:"addr_format"`
	// [brief]: Prefix length for the address.
	// [detail]: This field is optional.
	PrefixLen uint32 `protobuf:"varint,3,opt,name=prefix_len,json=prefixLen,proto3" json:"prefix_len,omitempty"`
}

func (x *IpNetwork) Reset() {
	*x = IpNetwork{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_common_addr_types_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpNetwork) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpNetwork) ProtoMessage() {}

func (x *IpNetwork) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_common_addr_types_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpNetwork.ProtoReflect.Descriptor instead.
func (*IpNetwork) Descriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{2}
}

func (m *IpNetwork) GetAddrFormat() isIpNetwork_AddrFormat {
	if m != nil {
		return m.AddrFormat
	}
	return nil
}

func (x *IpNetwork) GetHostAddrString() string {
	if x, ok := x.GetAddrFormat().(*IpNetwork_HostAddrString); ok {
		return x.HostAddrString
	}
	return ""
}

func (x *IpNetwork) GetHostAddrBytes() []byte {
	if x, ok := x.GetAddrFormat().(*IpNetwork_HostAddrBytes); ok {
		return x.HostAddrBytes
	}
	return nil
}

func (x *IpNetwork) GetPrefixLen() uint32 {
	if x != nil {
		return x.PrefixLen
	}
	return 0
}

type isIpNetwork_AddrFormat interface {
	isIpNetwork_AddrFormat()
}

type IpNetwork_HostAddrString struct {
	// [brief]: Host address in string format
	HostAddrString string `protobuf:"bytes,1,opt,name=host_addr_string,json=hostAddrString,proto3,oneof"`
}

type IpNetwork_HostAddrBytes struct {
	// [brief]: Host address  in network-ordered array of bytes
	HostAddrBytes []byte `protobuf:"bytes,2,opt,name=host_addr_bytes,json=hostAddrBytes,proto3,oneof"`
}

func (*IpNetwork_HostAddrString) isIpNetwork_AddrFormat() {}

func (*IpNetwork_HostAddrBytes) isIpNetwork_AddrFormat() {}

// [brief]: IP Fragmentation flags.
// [detail]: This is used to set or unset the IP fragmentation
// flags. All flags are optional.
type IpFragementFlags struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: The IP fragments do not match.
	// [default_value]: FALSE
	NotMatch bool `protobuf:"varint,1,opt,name=not_match,json=notMatch,proto3" json:"not_match,omitempty"`
	// [brief]: The IP fragments match.
	// [default_value]: FALSE
	Match bool `protobuf:"varint,2,opt,name=match,proto3" json:"match,omitempty"`
	// [brief]: If this flag is set, the packets are not fragmented.
	// [default_value]: FALSE
	DontFragement bool `protobuf:"varint,3,opt,name=dont_fragement,json=dontFragement,proto3" json:"dont_fragement,omitempty"`
	// [brief]: This indicates whether the packet is a fragment.
	// [default_value]: FALSE
	IsAFragement bool `protobuf:"varint,4,opt,name=is_a_fragement,json=isAFragement,proto3" json:"is_a_fragement,omitempty"`
	// [brief]: This indicates whether the packet is first fragment.
	// [default_value]: FALSE
	FirstFragement bool `protobuf:"varint,5,opt,name=first_fragement,json=firstFragement,proto3" json:"first_fragement,omitempty"`
	// [brief]: This indicates that the packet is the last fragment.
	// [default_value]: FALSE
	LastFragement bool `protobuf:"varint,6,opt,name=last_fragement,json=lastFragement,proto3" json:"last_fragement,omitempty"`
}

func (x *IpFragementFlags) Reset() {
	*x = IpFragementFlags{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_common_addr_types_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpFragementFlags) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpFragementFlags) ProtoMessage() {}

func (x *IpFragementFlags) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_common_addr_types_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpFragementFlags.ProtoReflect.Descriptor instead.
func (*IpFragementFlags) Descriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{3}
}

func (x *IpFragementFlags) GetNotMatch() bool {
	if x != nil {
		return x.NotMatch
	}
	return false
}

func (x *IpFragementFlags) GetMatch() bool {
	if x != nil {
		return x.Match
	}
	return false
}

func (x *IpFragementFlags) GetDontFragement() bool {
	if x != nil {
		return x.DontFragement
	}
	return false
}

func (x *IpFragementFlags) GetIsAFragement() bool {
	if x != nil {
		return x.IsAFragement
	}
	return false
}

func (x *IpFragementFlags) GetFirstFragement() bool {
	if x != nil {
		return x.FirstFragement
	}
	return false
}

func (x *IpFragementFlags) GetLastFragement() bool {
	if x != nil {
		return x.LastFragement
	}
	return false
}

// [brief]: Type of tunnel.
// [detail]: This is used to set the type of tunnel
type BypassOrTerminate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// [brief]: type of tunnel
	// [detail]: tunnel type can be either bypass_loopback or
	// tunnel_terrmination
	//
	// Types that are assignable to TunnelType:
	//
	//	*BypassOrTerminate_BypassLoopback
	//	*BypassOrTerminate_TunnelTerminate
	TunnelType isBypassOrTerminate_TunnelType `protobuf_oneof:"tunnel_type"`
}

func (x *BypassOrTerminate) Reset() {
	*x = BypassOrTerminate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_jnx_common_addr_types_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BypassOrTerminate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BypassOrTerminate) ProtoMessage() {}

func (x *BypassOrTerminate) ProtoReflect() protoreflect.Message {
	mi := &file_jnx_common_addr_types_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BypassOrTerminate.ProtoReflect.Descriptor instead.
func (*BypassOrTerminate) Descriptor() ([]byte, []int) {
	return file_jnx_common_addr_types_proto_rawDescGZIP(), []int{4}
}

func (m *BypassOrTerminate) GetTunnelType() isBypassOrTerminate_TunnelType {
	if m != nil {
		return m.TunnelType
	}
	return nil
}

func (x *BypassOrTerminate) GetBypassLoopback() bool {
	if x, ok := x.GetTunnelType().(*BypassOrTerminate_BypassLoopback); ok {
		return x.BypassLoopback
	}
	return false
}

func (x *BypassOrTerminate) GetTunnelTerminate() bool {
	if x, ok := x.GetTunnelType().(*BypassOrTerminate_TunnelTerminate); ok {
		return x.TunnelTerminate
	}
	return false
}

type isBypassOrTerminate_TunnelType interface {
	isBypassOrTerminate_TunnelType()
}

type BypassOrTerminate_BypassLoopback struct {
	// [brief]: tunnel is byass_loopback type
	BypassLoopback bool `protobuf:"varint,1,opt,name=bypass_loopback,json=bypassLoopback,proto3,oneof"`
}

type BypassOrTerminate_TunnelTerminate struct {
	// [brief]: tunnel is tunnel_terminate type
	TunnelTerminate bool `protobuf:"varint,2,opt,name=tunnel_terminate,json=tunnelTerminate,proto3,oneof"`
}

func (*BypassOrTerminate_BypassLoopback) isBypassOrTerminate_TunnelType() {}

func (*BypassOrTerminate_TunnelTerminate) isBypassOrTerminate_TunnelType() {}

var File_jnx_common_addr_types_proto protoreflect.FileDescriptor

var file_jnx_common_addr_types_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x6a, 0x6e, 0x78, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5f, 0x61, 0x64, 0x64,
	0x72, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x6a,
	0x6e, 0x78, 0x2e, 0x6a, 0x65, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x1a, 0x1b, 0x6a,
	0x6e, 0x78, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5f, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5e, 0x0a, 0x09, 0x49, 0x70,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x21, 0x0a, 0x0b, 0x61, 0x64, 0x64, 0x72, 0x5f,
	0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0a,
	0x61, 0x64, 0x64, 0x72, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x1f, 0x0a, 0x0a, 0x61, 0x64,
	0x64, 0x72, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00,
	0x52, 0x09, 0x61, 0x64, 0x64, 0x72, 0x42, 0x79, 0x74, 0x65, 0x73, 0x42, 0x0d, 0x0a, 0x0b, 0x61,
	0x64, 0x64, 0x72, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x22, 0x5f, 0x0a, 0x0a, 0x4d, 0x61,
	0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x21, 0x0a, 0x0b, 0x61, 0x64, 0x64, 0x72,
	0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x0a, 0x61, 0x64, 0x64, 0x72, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x1f, 0x0a, 0x0a, 0x61,
	0x64, 0x64, 0x72, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x48,
	0x00, 0x52, 0x09, 0x61, 0x64, 0x64, 0x72, 0x42, 0x79, 0x74, 0x65, 0x73, 0x42, 0x0d, 0x0a, 0x0b,
	0x61, 0x64, 0x64, 0x72, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x22, 0x8f, 0x01, 0x0a, 0x09,
	0x49, 0x70, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x2a, 0x0a, 0x10, 0x68, 0x6f, 0x73,
	0x74, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x5f, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0e, 0x68, 0x6f, 0x73, 0x74, 0x41, 0x64, 0x64, 0x72, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x28, 0x0a, 0x0f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x61, 0x64,
	0x64, 0x72, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00,
	0x52, 0x0d, 0x68, 0x6f, 0x73, 0x74, 0x41, 0x64, 0x64, 0x72, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12,
	0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x5f, 0x6c, 0x65, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x4c, 0x65, 0x6e, 0x42, 0x0d,
	0x0a, 0x0b, 0x61, 0x64, 0x64, 0x72, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x22, 0xe2, 0x01,
	0x0a, 0x10, 0x49, 0x70, 0x46, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x46, 0x6c, 0x61,
	0x67, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x6e, 0x6f, 0x74, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x6e, 0x6f, 0x74, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x12,
	0x14, 0x0a, 0x05, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x25, 0x0a, 0x0e, 0x64, 0x6f, 0x6e, 0x74, 0x5f, 0x66, 0x72,
	0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x64,
	0x6f, 0x6e, 0x74, 0x46, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x24, 0x0a, 0x0e,
	0x69, 0x73, 0x5f, 0x61, 0x5f, 0x66, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x69, 0x73, 0x41, 0x46, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x66, 0x69, 0x72, 0x73, 0x74, 0x5f, 0x66, 0x72, 0x61, 0x67,
	0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x66, 0x69, 0x72,
	0x73, 0x74, 0x46, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x25, 0x0a, 0x0e, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x66, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x46, 0x72, 0x61, 0x67, 0x65, 0x6d, 0x65,
	0x6e, 0x74, 0x22, 0x7a, 0x0a, 0x11, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x4f, 0x72, 0x54, 0x65,
	0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x12, 0x29, 0x0a, 0x0f, 0x62, 0x79, 0x70, 0x61, 0x73,
	0x73, 0x5f, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08,
	0x48, 0x00, 0x52, 0x0e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x4c, 0x6f, 0x6f, 0x70, 0x62, 0x61,
	0x63, 0x6b, 0x12, 0x2b, 0x0a, 0x10, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x65, 0x72,
	0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x0f,
	0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x42,
	0x0d, 0x0a, 0x0b, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x2a, 0x36,
	0x0a, 0x0d, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12,
	0x12, 0x0a, 0x0e, 0x41, 0x44, 0x44, 0x52, 0x45, 0x53, 0x53, 0x5f, 0x53, 0x54, 0x52, 0x49, 0x4e,
	0x47, 0x10, 0x00, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x44, 0x44, 0x52, 0x45, 0x53, 0x53, 0x5f, 0x42,
	0x59, 0x54, 0x45, 0x53, 0x10, 0x01, 0x2a, 0x5c, 0x0a, 0x06, 0x41, 0x66, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x12, 0x0a, 0x0e, 0x41, 0x46, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49,
	0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x41, 0x46, 0x5f, 0x49, 0x4e, 0x45, 0x54, 0x10,
	0x01, 0x12, 0x0c, 0x0a, 0x08, 0x41, 0x46, 0x5f, 0x49, 0x4e, 0x45, 0x54, 0x36, 0x10, 0x02, 0x12,
	0x0a, 0x0a, 0x06, 0x41, 0x46, 0x5f, 0x4d, 0x41, 0x43, 0x10, 0x03, 0x12, 0x0b, 0x0a, 0x07, 0x41,
	0x46, 0x5f, 0x4d, 0x50, 0x4c, 0x53, 0x10, 0x04, 0x12, 0x0a, 0x0a, 0x06, 0x41, 0x46, 0x5f, 0x49,
	0x53, 0x4f, 0x10, 0x05, 0x2a, 0x90, 0x01, 0x0a, 0x08, 0x54, 0x63, 0x70, 0x46, 0x6c, 0x61, 0x67,
	0x73, 0x12, 0x14, 0x0a, 0x10, 0x54, 0x43, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x49, 0x4e,
	0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x00, 0x12, 0x10, 0x0a, 0x0c, 0x54, 0x43, 0x50, 0x5f, 0x46,
	0x4c, 0x41, 0x47, 0x5f, 0x46, 0x49, 0x4e, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x54, 0x43, 0x50,
	0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x53, 0x59, 0x4e, 0x10, 0x02, 0x12, 0x10, 0x0a, 0x0c, 0x54,
	0x43, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x52, 0x53, 0x54, 0x10, 0x04, 0x12, 0x11, 0x0a,
	0x0d, 0x54, 0x43, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x50, 0x55, 0x53, 0x48, 0x10, 0x08,
	0x12, 0x10, 0x0a, 0x0c, 0x54, 0x43, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x41, 0x43, 0x4b,
	0x10, 0x10, 0x12, 0x13, 0x0a, 0x0f, 0x54, 0x43, 0x50, 0x5f, 0x46, 0x4c, 0x41, 0x47, 0x5f, 0x55,
	0x52, 0x47, 0x45, 0x4e, 0x54, 0x10, 0x20, 0x42, 0x21, 0x5a, 0x0e, 0x6a, 0x6e, 0x78, 0x2f, 0x6a,
	0x65, 0x74, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x82, 0xb5, 0x18, 0x05, 0x30, 0x2e, 0x32,
	0x2e, 0x30, 0x8a, 0xb5, 0x18, 0x04, 0x31, 0x39, 0x2e, 0x34, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_jnx_common_addr_types_proto_rawDescOnce sync.Once
	file_jnx_common_addr_types_proto_rawDescData = file_jnx_common_addr_types_proto_rawDesc
)

func file_jnx_common_addr_types_proto_rawDescGZIP() []byte {
	file_jnx_common_addr_types_proto_rawDescOnce.Do(func() {
		file_jnx_common_addr_types_proto_rawDescData = protoimpl.X.CompressGZIP(file_jnx_common_addr_types_proto_rawDescData)
	})
	return file_jnx_common_addr_types_proto_rawDescData
}

var file_jnx_common_addr_types_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_jnx_common_addr_types_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_jnx_common_addr_types_proto_goTypes = []interface{}{
	(AddressFormat)(0),        // 0: jnx.jet.common.AddressFormat
	(AfType)(0),               // 1: jnx.jet.common.AfType
	(TcpFlags)(0),             // 2: jnx.jet.common.TcpFlags
	(*IpAddress)(nil),         // 3: jnx.jet.common.IpAddress
	(*MacAddress)(nil),        // 4: jnx.jet.common.MacAddress
	(*IpNetwork)(nil),         // 5: jnx.jet.common.IpNetwork
	(*IpFragementFlags)(nil),  // 6: jnx.jet.common.IpFragementFlags
	(*BypassOrTerminate)(nil), // 7: jnx.jet.common.BypassOrTerminate
}
var file_jnx_common_addr_types_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_jnx_common_addr_types_proto_init() }
func file_jnx_common_addr_types_proto_init() {
	if File_jnx_common_addr_types_proto != nil {
		return
	}
	file_jnx_common_base_types_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_jnx_common_addr_types_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpAddress); i {
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
		file_jnx_common_addr_types_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MacAddress); i {
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
		file_jnx_common_addr_types_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpNetwork); i {
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
		file_jnx_common_addr_types_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpFragementFlags); i {
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
		file_jnx_common_addr_types_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BypassOrTerminate); i {
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
	file_jnx_common_addr_types_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*IpAddress_AddrString)(nil),
		(*IpAddress_AddrBytes)(nil),
	}
	file_jnx_common_addr_types_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*MacAddress_AddrString)(nil),
		(*MacAddress_AddrBytes)(nil),
	}
	file_jnx_common_addr_types_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*IpNetwork_HostAddrString)(nil),
		(*IpNetwork_HostAddrBytes)(nil),
	}
	file_jnx_common_addr_types_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*BypassOrTerminate_BypassLoopback)(nil),
		(*BypassOrTerminate_TunnelTerminate)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_jnx_common_addr_types_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_jnx_common_addr_types_proto_goTypes,
		DependencyIndexes: file_jnx_common_addr_types_proto_depIdxs,
		EnumInfos:         file_jnx_common_addr_types_proto_enumTypes,
		MessageInfos:      file_jnx_common_addr_types_proto_msgTypes,
	}.Build()
	File_jnx_common_addr_types_proto = out.File
	file_jnx_common_addr_types_proto_rawDesc = nil
	file_jnx_common_addr_types_proto_goTypes = nil
	file_jnx_common_addr_types_proto_depIdxs = nil
}
