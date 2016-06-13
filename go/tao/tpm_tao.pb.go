// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tpm_tao.proto

package tao

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type HybridSealedData struct {
	SealedKey        []byte `protobuf:"bytes,1,req,name=SealedKey" json:"SealedKey,omitempty"`
	EncryptedData    []byte `protobuf:"bytes,2,req,name=EncryptedData" json:"EncryptedData,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *HybridSealedData) Reset()                    { *m = HybridSealedData{} }
func (m *HybridSealedData) String() string            { return proto.CompactTextString(m) }
func (*HybridSealedData) ProtoMessage()               {}
func (*HybridSealedData) Descriptor() ([]byte, []int) { return fileDescriptor9, []int{0} }

func (m *HybridSealedData) GetSealedKey() []byte {
	if m != nil {
		return m.SealedKey
	}
	return nil
}

func (m *HybridSealedData) GetEncryptedData() []byte {
	if m != nil {
		return m.EncryptedData
	}
	return nil
}

func init() {
	proto.RegisterType((*HybridSealedData)(nil), "tao.HybridSealedData")
}

func init() { proto.RegisterFile("tpm_tao.proto", fileDescriptor9) }

var fileDescriptor9 = []byte{
	// 96 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2d, 0x29, 0xc8, 0x8d,
	0x2f, 0x49, 0xcc, 0xd7, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x2e, 0x49, 0xcc, 0x57, 0xb2,
	0xe1, 0x12, 0xf0, 0xa8, 0x4c, 0x2a, 0xca, 0x4c, 0x09, 0x4e, 0x4d, 0xcc, 0x49, 0x4d, 0x71, 0x49,
	0x2c, 0x49, 0x14, 0x12, 0xe4, 0xe2, 0x84, 0xf0, 0xbc, 0x53, 0x2b, 0x25, 0x18, 0x15, 0x98, 0x34,
	0x78, 0x84, 0x44, 0xb9, 0x78, 0x5d, 0xf3, 0x92, 0x8b, 0x2a, 0x0b, 0x4a, 0x20, 0x6a, 0x24, 0x98,
	0x40, 0xc2, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x89, 0x0f, 0xf2, 0x27, 0x52, 0x00, 0x00, 0x00,
}
