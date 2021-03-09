// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.13.0
// source: rpc/common/version.proto

package common

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// VersionInfo is the type that both `telepresence daemon` (the super-user
// daemon) and `telepresence conector` (the normal-user daemon) use
// when reporting their version to the user-facing CLI.
type VersionInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ApiVersion int32  `protobuf:"varint,1,opt,name=api_version,json=apiVersion,proto3" json:"api_version,omitempty"`
	Version    string `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *VersionInfo) Reset() {
	*x = VersionInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_common_version_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VersionInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VersionInfo) ProtoMessage() {}

func (x *VersionInfo) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_common_version_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VersionInfo.ProtoReflect.Descriptor instead.
func (*VersionInfo) Descriptor() ([]byte, []int) {
	return file_rpc_common_version_proto_rawDescGZIP(), []int{0}
}

func (x *VersionInfo) GetApiVersion() int32 {
	if x != nil {
		return x.ApiVersion
	}
	return 0
}

func (x *VersionInfo) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

var File_rpc_common_version_proto protoreflect.FileDescriptor

var file_rpc_common_version_proto_rawDesc = []byte{
	0x0a, 0x18, 0x72, 0x70, 0x63, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x63, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x22,
	0x48, 0x0a, 0x0b, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1f,
	0x0a, 0x0b, 0x61, 0x70, 0x69, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x0a, 0x61, 0x70, 0x69, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x42, 0x36, 0x5a, 0x34, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x72, 0x65, 0x73,
	0x65, 0x6e, 0x63, 0x65, 0x69, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x72, 0x65, 0x73, 0x65,
	0x6e, 0x63, 0x65, 0x2f, 0x72, 0x70, 0x63, 0x2f, 0x76, 0x32, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rpc_common_version_proto_rawDescOnce sync.Once
	file_rpc_common_version_proto_rawDescData = file_rpc_common_version_proto_rawDesc
)

func file_rpc_common_version_proto_rawDescGZIP() []byte {
	file_rpc_common_version_proto_rawDescOnce.Do(func() {
		file_rpc_common_version_proto_rawDescData = protoimpl.X.CompressGZIP(file_rpc_common_version_proto_rawDescData)
	})
	return file_rpc_common_version_proto_rawDescData
}

var file_rpc_common_version_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_rpc_common_version_proto_goTypes = []interface{}{
	(*VersionInfo)(nil), // 0: telepresence.common.VersionInfo
}
var file_rpc_common_version_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_rpc_common_version_proto_init() }
func file_rpc_common_version_proto_init() {
	if File_rpc_common_version_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rpc_common_version_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VersionInfo); i {
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
			RawDescriptor: file_rpc_common_version_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_rpc_common_version_proto_goTypes,
		DependencyIndexes: file_rpc_common_version_proto_depIdxs,
		MessageInfos:      file_rpc_common_version_proto_msgTypes,
	}.Build()
	File_rpc_common_version_proto = out.File
	file_rpc_common_version_proto_rawDesc = nil
	file_rpc_common_version_proto_goTypes = nil
	file_rpc_common_version_proto_depIdxs = nil
}
