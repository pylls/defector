// Code generated by protoc-gen-go.
// source: collect.proto
// DO NOT EDIT!

/*
Package defector is a generated protocol buffer package.

It is generated from these files:
	collect.proto

It has these top-level messages:
	Req
	Browse
*/
package defector

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Req struct {
	WorkerID string  `protobuf:"bytes,1,opt,name=WorkerID,json=workerID" json:"WorkerID,omitempty"`
	Browse   *Browse `protobuf:"bytes,2,opt,name=Browse,json=browse" json:"Browse,omitempty"`
}

func (m *Req) Reset()                    { *m = Req{} }
func (m *Req) String() string            { return proto.CompactTextString(m) }
func (*Req) ProtoMessage()               {}
func (*Req) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Req) GetBrowse() *Browse {
	if m != nil {
		return m.Browse
	}
	return nil
}

// Browse is a work item.
// If ID == "", then no work has been done (request) or is needed (reply).
type Browse struct {
	ID         string `protobuf:"bytes,1,opt,name=ID,json=iD" json:"ID,omitempty"`
	URL        string `protobuf:"bytes,2,opt,name=URL,json=uRL" json:"URL,omitempty"`
	Timeout    int64  `protobuf:"varint,3,opt,name=Timeout,json=timeout" json:"Timeout,omitempty"`
	Data       []byte `protobuf:"bytes,4,opt,name=Data,json=data,proto3" json:"Data,omitempty"`
	AllTraffic bool   `protobuf:"varint,5,opt,name=AllTraffic,json=allTraffic" json:"AllTraffic,omitempty"`
}

func (m *Browse) Reset()                    { *m = Browse{} }
func (m *Browse) String() string            { return proto.CompactTextString(m) }
func (*Browse) ProtoMessage()               {}
func (*Browse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func init() {
	proto.RegisterType((*Req)(nil), "defector.Req")
	proto.RegisterType((*Browse)(nil), "defector.Browse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion3

// Client API for Collect service

type CollectClient interface {
	Work(ctx context.Context, in *Req, opts ...grpc.CallOption) (*Browse, error)
}

type collectClient struct {
	cc *grpc.ClientConn
}

func NewCollectClient(cc *grpc.ClientConn) CollectClient {
	return &collectClient{cc}
}

func (c *collectClient) Work(ctx context.Context, in *Req, opts ...grpc.CallOption) (*Browse, error) {
	out := new(Browse)
	err := grpc.Invoke(ctx, "/defector.Collect/Work", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Collect service

type CollectServer interface {
	Work(context.Context, *Req) (*Browse, error)
}

func RegisterCollectServer(s *grpc.Server, srv CollectServer) {
	s.RegisterService(&_Collect_serviceDesc, srv)
}

func _Collect_Work_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Req)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CollectServer).Work(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/defector.Collect/Work",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CollectServer).Work(ctx, req.(*Req))
	}
	return interceptor(ctx, in, info, handler)
}

var _Collect_serviceDesc = grpc.ServiceDesc{
	ServiceName: "defector.Collect",
	HandlerType: (*CollectServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Work",
			Handler:    _Collect_Work_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: fileDescriptor0,
}

func init() { proto.RegisterFile("collect.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 227 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x64, 0x90, 0x31, 0x4f, 0xc3, 0x30,
	0x10, 0x85, 0x71, 0x1c, 0x92, 0xf4, 0xa0, 0xa8, 0xba, 0xc9, 0xea, 0x80, 0xac, 0x4c, 0x66, 0xc9,
	0x50, 0xf8, 0x03, 0x40, 0x16, 0x44, 0xa7, 0x53, 0x11, 0xb3, 0xeb, 0x5e, 0xa4, 0x08, 0x23, 0x53,
	0xe3, 0xaa, 0xfc, 0x7c, 0x44, 0x42, 0xc3, 0xc0, 0x74, 0x7a, 0x4f, 0x77, 0x4f, 0xef, 0x3b, 0x98,
	0xbb, 0xe0, 0x3d, 0xbb, 0xd4, 0x7c, 0xc4, 0x90, 0x02, 0x56, 0x3b, 0xee, 0xd8, 0xa5, 0x10, 0xeb,
	0x67, 0x90, 0xc4, 0x7b, 0x5c, 0x42, 0xf5, 0x1a, 0xe2, 0x1b, 0xc7, 0xa7, 0x56, 0x09, 0x2d, 0xcc,
	0x8c, 0xaa, 0xe3, 0xaf, 0x46, 0x03, 0xc5, 0x43, 0x0c, 0xc7, 0x4f, 0x56, 0x99, 0x16, 0xe6, 0x62,
	0xb5, 0x68, 0x4e, 0xd7, 0xcd, 0xe8, 0x53, 0xb1, 0x1d, 0x66, 0xfd, 0x75, 0xda, 0xc4, 0x2b, 0xc8,
	0xa6, 0xa4, 0xac, 0x6f, 0x71, 0x01, 0xf2, 0x85, 0xd6, 0x43, 0xc0, 0x8c, 0xe4, 0x81, 0xd6, 0xa8,
	0xa0, 0xdc, 0xf4, 0xef, 0x1c, 0x0e, 0x49, 0x49, 0x2d, 0x8c, 0xa4, 0x32, 0x8d, 0x12, 0x11, 0xf2,
	0xd6, 0x26, 0xab, 0x72, 0x2d, 0xcc, 0x25, 0xe5, 0x3b, 0x9b, 0x2c, 0x5e, 0x03, 0xdc, 0x7b, 0xbf,
	0x89, 0xb6, 0xeb, 0x7a, 0xa7, 0xce, 0xb5, 0x30, 0x15, 0x81, 0x9d, 0x9c, 0xd5, 0x1d, 0x94, 0x8f,
	0x23, 0x21, 0xde, 0x40, 0xfe, 0x83, 0x82, 0xf3, 0xbf, 0x9a, 0xc4, 0xfb, 0xe5, 0xbf, 0xd6, 0xf5,
	0xd9, 0xb6, 0x18, 0xbe, 0x71, 0xfb, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x08, 0x63, 0xe5, 0xcc, 0x1e,
	0x01, 0x00, 0x00,
}
