// Code generated by protoc-gen-go. DO NOT EDIT.
// source: linux_host_admin_rpc.proto

package tao

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type LinuxHostAdminRPCRequest struct {
	Subprin          []byte   `protobuf:"bytes,1,opt,name=subprin" json:"subprin,omitempty"`
	Path             *string  `protobuf:"bytes,2,opt,name=path" json:"path,omitempty"`
	Args             []string `protobuf:"bytes,3,rep,name=args" json:"args,omitempty"`
	Pid              *int32   `protobuf:"varint,4,opt,name=pid" json:"pid,omitempty"`
	Dir              *string  `protobuf:"bytes,5,opt,name=dir" json:"dir,omitempty"`
	ContainerType    *string  `protobuf:"bytes,6,opt,name=container_type" json:"container_type,omitempty"`
	ContainerArgs    []string `protobuf:"bytes,7,rep,name=container_args" json:"container_args,omitempty"`
	Stdin            *int32   `protobuf:"varint,8,opt,name=stdin" json:"stdin,omitempty"`
	Stdout           *int32   `protobuf:"varint,9,opt,name=stdout" json:"stdout,omitempty"`
	Stderr           *int32   `protobuf:"varint,10,opt,name=stderr" json:"stderr,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *LinuxHostAdminRPCRequest) Reset()                    { *m = LinuxHostAdminRPCRequest{} }
func (m *LinuxHostAdminRPCRequest) String() string            { return proto.CompactTextString(m) }
func (*LinuxHostAdminRPCRequest) ProtoMessage()               {}
func (*LinuxHostAdminRPCRequest) Descriptor() ([]byte, []int) { return fileDescriptor6, []int{0} }

func (m *LinuxHostAdminRPCRequest) GetSubprin() []byte {
	if m != nil {
		return m.Subprin
	}
	return nil
}

func (m *LinuxHostAdminRPCRequest) GetPath() string {
	if m != nil && m.Path != nil {
		return *m.Path
	}
	return ""
}

func (m *LinuxHostAdminRPCRequest) GetArgs() []string {
	if m != nil {
		return m.Args
	}
	return nil
}

func (m *LinuxHostAdminRPCRequest) GetPid() int32 {
	if m != nil && m.Pid != nil {
		return *m.Pid
	}
	return 0
}

func (m *LinuxHostAdminRPCRequest) GetDir() string {
	if m != nil && m.Dir != nil {
		return *m.Dir
	}
	return ""
}

func (m *LinuxHostAdminRPCRequest) GetContainerType() string {
	if m != nil && m.ContainerType != nil {
		return *m.ContainerType
	}
	return ""
}

func (m *LinuxHostAdminRPCRequest) GetContainerArgs() []string {
	if m != nil {
		return m.ContainerArgs
	}
	return nil
}

func (m *LinuxHostAdminRPCRequest) GetStdin() int32 {
	if m != nil && m.Stdin != nil {
		return *m.Stdin
	}
	return 0
}

func (m *LinuxHostAdminRPCRequest) GetStdout() int32 {
	if m != nil && m.Stdout != nil {
		return *m.Stdout
	}
	return 0
}

func (m *LinuxHostAdminRPCRequest) GetStderr() int32 {
	if m != nil && m.Stderr != nil {
		return *m.Stderr
	}
	return 0
}

type LinuxHostAdminRPCHostedProgram struct {
	Subprin          []byte `protobuf:"bytes,1,req,name=subprin" json:"subprin,omitempty"`
	Pid              *int32 `protobuf:"varint,2,req,name=pid" json:"pid,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (m *LinuxHostAdminRPCHostedProgram) Reset()                    { *m = LinuxHostAdminRPCHostedProgram{} }
func (m *LinuxHostAdminRPCHostedProgram) String() string            { return proto.CompactTextString(m) }
func (*LinuxHostAdminRPCHostedProgram) ProtoMessage()               {}
func (*LinuxHostAdminRPCHostedProgram) Descriptor() ([]byte, []int) { return fileDescriptor6, []int{1} }

func (m *LinuxHostAdminRPCHostedProgram) GetSubprin() []byte {
	if m != nil {
		return m.Subprin
	}
	return nil
}

func (m *LinuxHostAdminRPCHostedProgram) GetPid() int32 {
	if m != nil && m.Pid != nil {
		return *m.Pid
	}
	return 0
}

type LinuxHostAdminRPCResponse struct {
	Child            []*LinuxHostAdminRPCHostedProgram `protobuf:"bytes,1,rep,name=child" json:"child,omitempty"`
	Prin             []byte                            `protobuf:"bytes,2,opt,name=prin" json:"prin,omitempty"`
	Status           *int32                            `protobuf:"varint,3,opt,name=status" json:"status,omitempty"`
	XXX_unrecognized []byte                            `json:"-"`
}

func (m *LinuxHostAdminRPCResponse) Reset()                    { *m = LinuxHostAdminRPCResponse{} }
func (m *LinuxHostAdminRPCResponse) String() string            { return proto.CompactTextString(m) }
func (*LinuxHostAdminRPCResponse) ProtoMessage()               {}
func (*LinuxHostAdminRPCResponse) Descriptor() ([]byte, []int) { return fileDescriptor6, []int{2} }

func (m *LinuxHostAdminRPCResponse) GetChild() []*LinuxHostAdminRPCHostedProgram {
	if m != nil {
		return m.Child
	}
	return nil
}

func (m *LinuxHostAdminRPCResponse) GetPrin() []byte {
	if m != nil {
		return m.Prin
	}
	return nil
}

func (m *LinuxHostAdminRPCResponse) GetStatus() int32 {
	if m != nil && m.Status != nil {
		return *m.Status
	}
	return 0
}

func init() {
	proto.RegisterType((*LinuxHostAdminRPCRequest)(nil), "tao.LinuxHostAdminRPCRequest")
	proto.RegisterType((*LinuxHostAdminRPCHostedProgram)(nil), "tao.LinuxHostAdminRPCHostedProgram")
	proto.RegisterType((*LinuxHostAdminRPCResponse)(nil), "tao.LinuxHostAdminRPCResponse")
}

func init() { proto.RegisterFile("linux_host_admin_rpc.proto", fileDescriptor6) }

var fileDescriptor6 = []byte{
	// 270 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x90, 0xc1, 0x4a, 0x03, 0x31,
	0x10, 0x86, 0xc9, 0x6e, 0xd3, 0xda, 0x69, 0xad, 0xb0, 0x07, 0x19, 0x3d, 0x48, 0xa8, 0x97, 0x9c,
	0xf6, 0xd0, 0x07, 0x10, 0xc4, 0x8b, 0x07, 0x0f, 0xa5, 0x2f, 0xb0, 0xc4, 0x4d, 0xe8, 0x06, 0xba,
	0x49, 0x4c, 0x66, 0x41, 0xdf, 0xce, 0x47, 0x93, 0x04, 0x04, 0xa5, 0x82, 0xb7, 0x7c, 0xe1, 0xe7,
	0x9f, 0x99, 0x0f, 0x6e, 0x4f, 0xd6, 0x4d, 0xef, 0xdd, 0xe0, 0x13, 0x75, 0x4a, 0x8f, 0xd6, 0x75,
	0x31, 0xf4, 0x6d, 0x88, 0x9e, 0x7c, 0x53, 0x93, 0xf2, 0xdb, 0x4f, 0x06, 0xf8, 0x92, 0x33, 0xcf,
	0x3e, 0xd1, 0x63, 0x4e, 0x1c, 0xf6, 0x4f, 0x07, 0xf3, 0x36, 0x99, 0x44, 0xcd, 0x15, 0x2c, 0xd2,
	0xf4, 0x1a, 0xa2, 0x75, 0xc8, 0x04, 0x93, 0xeb, 0x66, 0x0d, 0xb3, 0xa0, 0x68, 0xc0, 0x4a, 0x30,
	0xb9, 0xcc, 0xa4, 0xe2, 0x31, 0x61, 0x2d, 0x6a, 0xb9, 0x6c, 0x56, 0x50, 0x07, 0xab, 0x71, 0x26,
	0x98, 0xe4, 0x19, 0xb4, 0x8d, 0xc8, 0x4b, 0xee, 0x1a, 0x36, 0xbd, 0x77, 0xa4, 0xac, 0x33, 0xb1,
	0xa3, 0x8f, 0x60, 0x70, 0x7e, 0xfe, 0x5f, 0x9a, 0x16, 0xa5, 0xe9, 0x12, 0x78, 0x22, 0x6d, 0x1d,
	0x5e, 0x94, 0xae, 0x0d, 0xcc, 0x13, 0x69, 0x3f, 0x11, 0x2e, 0x7f, 0xb0, 0x89, 0x11, 0x21, 0xf3,
	0xf6, 0x01, 0xee, 0xce, 0x2e, 0xc8, 0x6f, 0xa3, 0xf7, 0xd1, 0x1f, 0xa3, 0x1a, 0x7f, 0xdf, 0x51,
	0xc9, 0xf5, 0xf7, 0xae, 0x95, 0xa8, 0x24, 0xdf, 0x8e, 0x70, 0xf3, 0x87, 0x81, 0x14, 0xbc, 0x4b,
	0xa6, 0xd9, 0x01, 0xef, 0x07, 0x7b, 0xd2, 0xc8, 0x44, 0x2d, 0x57, 0xbb, 0xfb, 0x96, 0x94, 0x6f,
	0xff, 0x19, 0x97, 0x2d, 0xe5, 0x59, 0x55, 0x71, 0x56, 0xd6, 0x55, 0x34, 0x65, 0x4f, 0x4c, 0xf2,
	0xaf, 0x00, 0x00, 0x00, 0xff, 0xff, 0xd8, 0x5d, 0x57, 0x62, 0x93, 0x01, 0x00, 0x00,
}
