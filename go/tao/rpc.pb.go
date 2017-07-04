// Code generated by protoc-gen-go. DO NOT EDIT.
// source: rpc.proto

package tao

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type RPCRequest struct {
	Data             []byte  `protobuf:"bytes,1,opt,name=data" json:"data,omitempty"`
	Size             *int32  `protobuf:"varint,2,opt,name=size" json:"size,omitempty"`
	Policy           *string `protobuf:"bytes,3,opt,name=policy" json:"policy,omitempty"`
	Time             *int64  `protobuf:"varint,4,opt,name=time" json:"time,omitempty"`
	Expiration       *int64  `protobuf:"varint,5,opt,name=expiration" json:"expiration,omitempty"`
	Issuer           []byte  `protobuf:"bytes,6,opt,name=issuer" json:"issuer,omitempty"`
	Level            *int32  `protobuf:"varint,7,opt,name=level" json:"level,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *RPCRequest) Reset()                    { *m = RPCRequest{} }
func (m *RPCRequest) String() string            { return proto.CompactTextString(m) }
func (*RPCRequest) ProtoMessage()               {}
func (*RPCRequest) Descriptor() ([]byte, []int) { return fileDescriptor8, []int{0} }

func (m *RPCRequest) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *RPCRequest) GetSize() int32 {
	if m != nil && m.Size != nil {
		return *m.Size
	}
	return 0
}

func (m *RPCRequest) GetPolicy() string {
	if m != nil && m.Policy != nil {
		return *m.Policy
	}
	return ""
}

func (m *RPCRequest) GetTime() int64 {
	if m != nil && m.Time != nil {
		return *m.Time
	}
	return 0
}

func (m *RPCRequest) GetExpiration() int64 {
	if m != nil && m.Expiration != nil {
		return *m.Expiration
	}
	return 0
}

func (m *RPCRequest) GetIssuer() []byte {
	if m != nil {
		return m.Issuer
	}
	return nil
}

func (m *RPCRequest) GetLevel() int32 {
	if m != nil && m.Level != nil {
		return *m.Level
	}
	return 0
}

type RPCResponse struct {
	Data             []byte  `protobuf:"bytes,1,opt,name=data" json:"data,omitempty"`
	Policy           *string `protobuf:"bytes,2,opt,name=policy" json:"policy,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *RPCResponse) Reset()                    { *m = RPCResponse{} }
func (m *RPCResponse) String() string            { return proto.CompactTextString(m) }
func (*RPCResponse) ProtoMessage()               {}
func (*RPCResponse) Descriptor() ([]byte, []int) { return fileDescriptor8, []int{1} }

func (m *RPCResponse) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *RPCResponse) GetPolicy() string {
	if m != nil && m.Policy != nil {
		return *m.Policy
	}
	return ""
}

func init() {
	proto.RegisterType((*RPCRequest)(nil), "tao.RPCRequest")
	proto.RegisterType((*RPCResponse)(nil), "tao.RPCResponse")
}

func init() { proto.RegisterFile("rpc.proto", fileDescriptor8) }

var fileDescriptor8 = []byte{
	// 165 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0xcd, 0x4f, 0xaa, 0xc2, 0x30,
	0x10, 0xc7, 0x71, 0xf2, 0xfa, 0xe7, 0xd1, 0xb1, 0x76, 0x91, 0xd5, 0x2c, 0x43, 0x57, 0x01, 0xc1,
	0x4b, 0x78, 0x01, 0xe9, 0x0d, 0x42, 0x9d, 0x45, 0xa0, 0x36, 0x31, 0x33, 0x15, 0xeb, 0xe9, 0x25,
	0xd9, 0x08, 0x2e, 0x67, 0x7e, 0xf0, 0xfd, 0x40, 0x97, 0xe2, 0x7c, 0x8e, 0x29, 0x48, 0xd0, 0x95,
	0xb8, 0x30, 0xee, 0x00, 0xd3, 0xf5, 0x32, 0xd1, 0x63, 0x23, 0x16, 0xdd, 0x43, 0x7d, 0x73, 0xe2,
	0x50, 0x19, 0x65, 0xfb, 0x7c, 0xb1, 0x7f, 0x13, 0xfe, 0x19, 0x65, 0x1b, 0x3d, 0x40, 0x1b, 0xc3,
	0xe2, 0xe7, 0x1d, 0x2b, 0xa3, 0x6c, 0x97, 0x57, 0xf1, 0x77, 0xc2, 0xda, 0x28, 0x5b, 0x69, 0x0d,
	0x40, 0xaf, 0xe8, 0x93, 0x13, 0x1f, 0x56, 0x6c, 0xca, 0x6f, 0x80, 0xd6, 0x33, 0x6f, 0x94, 0xb0,
	0x2d, 0xbd, 0x23, 0x34, 0x0b, 0x3d, 0x69, 0xc1, 0xff, 0x1c, 0x1c, 0x4f, 0x70, 0x28, 0x34, 0xc7,
	0xb0, 0x32, 0xfd, 0xd8, 0x5f, 0x2d, 0xeb, 0xdd, 0x27, 0x00, 0x00, 0xff, 0xff, 0xef, 0xc5, 0x57,
	0x07, 0xb8, 0x00, 0x00, 0x00,
}
