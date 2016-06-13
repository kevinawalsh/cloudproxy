// Code generated by protoc-gen-go. DO NOT EDIT.
// source: domain.proto

package tao

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type DomainDetails struct {
	Name             *string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	PolicyKeysPath   *string `protobuf:"bytes,2,opt,name=policy_keys_path" json:"policy_keys_path,omitempty"`
	GuardType        *string `protobuf:"bytes,3,opt,name=guard_type" json:"guard_type,omitempty"`
	GuardNetwork     *string `protobuf:"bytes,4,opt,name=guard_network" json:"guard_network,omitempty"`
	GuardAddress     *string `protobuf:"bytes,5,opt,name=guard_address" json:"guard_address,omitempty"`
	GuardTtl         *int64  `protobuf:"varint,6,opt,name=guard_ttl" json:"guard_ttl,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *DomainDetails) Reset()                    { *m = DomainDetails{} }
func (m *DomainDetails) String() string            { return proto.CompactTextString(m) }
func (*DomainDetails) ProtoMessage()               {}
func (*DomainDetails) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{0} }

func (m *DomainDetails) GetName() string {
	if m != nil && m.Name != nil {
		return *m.Name
	}
	return ""
}

func (m *DomainDetails) GetPolicyKeysPath() string {
	if m != nil && m.PolicyKeysPath != nil {
		return *m.PolicyKeysPath
	}
	return ""
}

func (m *DomainDetails) GetGuardType() string {
	if m != nil && m.GuardType != nil {
		return *m.GuardType
	}
	return ""
}

func (m *DomainDetails) GetGuardNetwork() string {
	if m != nil && m.GuardNetwork != nil {
		return *m.GuardNetwork
	}
	return ""
}

func (m *DomainDetails) GetGuardAddress() string {
	if m != nil && m.GuardAddress != nil {
		return *m.GuardAddress
	}
	return ""
}

func (m *DomainDetails) GetGuardTtl() int64 {
	if m != nil && m.GuardTtl != nil {
		return *m.GuardTtl
	}
	return 0
}

type X509Details struct {
	CommonName         *string `protobuf:"bytes,1,opt,name=common_name" json:"common_name,omitempty"`
	Country            *string `protobuf:"bytes,2,opt,name=country" json:"country,omitempty"`
	State              *string `protobuf:"bytes,3,opt,name=state" json:"state,omitempty"`
	City               *string `protobuf:"bytes,4,opt,name=city" json:"city,omitempty"`
	Organization       *string `protobuf:"bytes,5,opt,name=organization" json:"organization,omitempty"`
	OrganizationalUnit *string `protobuf:"bytes,6,opt,name=organizational_unit" json:"organizational_unit,omitempty"`
	SerialNumber       *int32  `protobuf:"varint,7,opt,name=serial_number" json:"serial_number,omitempty"`
	XXX_unrecognized   []byte  `json:"-"`
}

func (m *X509Details) Reset()                    { *m = X509Details{} }
func (m *X509Details) String() string            { return proto.CompactTextString(m) }
func (*X509Details) ProtoMessage()               {}
func (*X509Details) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{1} }

func (m *X509Details) GetCommonName() string {
	if m != nil && m.CommonName != nil {
		return *m.CommonName
	}
	return ""
}

func (m *X509Details) GetCountry() string {
	if m != nil && m.Country != nil {
		return *m.Country
	}
	return ""
}

func (m *X509Details) GetState() string {
	if m != nil && m.State != nil {
		return *m.State
	}
	return ""
}

func (m *X509Details) GetCity() string {
	if m != nil && m.City != nil {
		return *m.City
	}
	return ""
}

func (m *X509Details) GetOrganization() string {
	if m != nil && m.Organization != nil {
		return *m.Organization
	}
	return ""
}

func (m *X509Details) GetOrganizationalUnit() string {
	if m != nil && m.OrganizationalUnit != nil {
		return *m.OrganizationalUnit
	}
	return ""
}

func (m *X509Details) GetSerialNumber() int32 {
	if m != nil && m.SerialNumber != nil {
		return *m.SerialNumber
	}
	return 0
}

type ACLGuardDetails struct {
	SignedAclsPath   *string `protobuf:"bytes,1,opt,name=signed_acls_path" json:"signed_acls_path,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *ACLGuardDetails) Reset()                    { *m = ACLGuardDetails{} }
func (m *ACLGuardDetails) String() string            { return proto.CompactTextString(m) }
func (*ACLGuardDetails) ProtoMessage()               {}
func (*ACLGuardDetails) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{2} }

func (m *ACLGuardDetails) GetSignedAclsPath() string {
	if m != nil && m.SignedAclsPath != nil {
		return *m.SignedAclsPath
	}
	return ""
}

type DatalogGuardDetails struct {
	SignedRulesPath  *string `protobuf:"bytes,2,opt,name=signed_rules_path" json:"signed_rules_path,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *DatalogGuardDetails) Reset()                    { *m = DatalogGuardDetails{} }
func (m *DatalogGuardDetails) String() string            { return proto.CompactTextString(m) }
func (*DatalogGuardDetails) ProtoMessage()               {}
func (*DatalogGuardDetails) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{3} }

func (m *DatalogGuardDetails) GetSignedRulesPath() string {
	if m != nil && m.SignedRulesPath != nil {
		return *m.SignedRulesPath
	}
	return ""
}

type TPMDetails struct {
	TpmPath *string `protobuf:"bytes,1,opt,name=tpm_path" json:"tpm_path,omitempty"`
	AikPath *string `protobuf:"bytes,2,opt,name=aik_path" json:"aik_path,omitempty"`
	// A string representing the IDs of PCRs, like "17,18".
	Pcrs             *string `protobuf:"bytes,3,opt,name=pcrs" json:"pcrs,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *TPMDetails) Reset()                    { *m = TPMDetails{} }
func (m *TPMDetails) String() string            { return proto.CompactTextString(m) }
func (*TPMDetails) ProtoMessage()               {}
func (*TPMDetails) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{4} }

func (m *TPMDetails) GetTpmPath() string {
	if m != nil && m.TpmPath != nil {
		return *m.TpmPath
	}
	return ""
}

func (m *TPMDetails) GetAikPath() string {
	if m != nil && m.AikPath != nil {
		return *m.AikPath
	}
	return ""
}

func (m *TPMDetails) GetPcrs() string {
	if m != nil && m.Pcrs != nil {
		return *m.Pcrs
	}
	return ""
}

type DomainConfig struct {
	DomainInfo       *DomainDetails       `protobuf:"bytes,1,opt,name=domain_info" json:"domain_info,omitempty"`
	X509Info         *X509Details         `protobuf:"bytes,2,opt,name=x509_info" json:"x509_info,omitempty"`
	AclGuardInfo     *ACLGuardDetails     `protobuf:"bytes,3,opt,name=acl_guard_info" json:"acl_guard_info,omitempty"`
	DatalogGuardInfo *DatalogGuardDetails `protobuf:"bytes,4,opt,name=datalog_guard_info" json:"datalog_guard_info,omitempty"`
	TpmInfo          *TPMDetails          `protobuf:"bytes,5,opt,name=tpm_info" json:"tpm_info,omitempty"`
	XXX_unrecognized []byte               `json:"-"`
}

func (m *DomainConfig) Reset()                    { *m = DomainConfig{} }
func (m *DomainConfig) String() string            { return proto.CompactTextString(m) }
func (*DomainConfig) ProtoMessage()               {}
func (*DomainConfig) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{5} }

func (m *DomainConfig) GetDomainInfo() *DomainDetails {
	if m != nil {
		return m.DomainInfo
	}
	return nil
}

func (m *DomainConfig) GetX509Info() *X509Details {
	if m != nil {
		return m.X509Info
	}
	return nil
}

func (m *DomainConfig) GetAclGuardInfo() *ACLGuardDetails {
	if m != nil {
		return m.AclGuardInfo
	}
	return nil
}

func (m *DomainConfig) GetDatalogGuardInfo() *DatalogGuardDetails {
	if m != nil {
		return m.DatalogGuardInfo
	}
	return nil
}

func (m *DomainConfig) GetTpmInfo() *TPMDetails {
	if m != nil {
		return m.TpmInfo
	}
	return nil
}

type DomainTemplate struct {
	Config       *DomainConfig `protobuf:"bytes,1,opt,name=config" json:"config,omitempty"`
	DatalogRules []string      `protobuf:"bytes,2,rep,name=datalog_rules" json:"datalog_rules,omitempty"`
	AclRules     []string      `protobuf:"bytes,3,rep,name=acl_rules" json:"acl_rules,omitempty"`
	// The name of the host (used for policy statements)
	HostName          *string `protobuf:"bytes,4,opt,name=host_name" json:"host_name,omitempty"`
	HostPredicateName *string `protobuf:"bytes,5,opt,name=host_predicate_name" json:"host_predicate_name,omitempty"`
	// Program names (as paths to binaries)
	ProgramPaths         []string `protobuf:"bytes,6,rep,name=program_paths" json:"program_paths,omitempty"`
	ProgramPredicateName *string  `protobuf:"bytes,7,opt,name=program_predicate_name" json:"program_predicate_name,omitempty"`
	// Container names (as paths to images)
	ContainerPaths         []string `protobuf:"bytes,8,rep,name=container_paths" json:"container_paths,omitempty"`
	ContainerPredicateName *string  `protobuf:"bytes,9,opt,name=container_predicate_name" json:"container_predicate_name,omitempty"`
	// VM names (as paths to images)
	VmPaths         []string `protobuf:"bytes,10,rep,name=vm_paths" json:"vm_paths,omitempty"`
	VmPredicateName *string  `protobuf:"bytes,11,opt,name=vm_predicate_name" json:"vm_predicate_name,omitempty"`
	// LinuxHost names (as paths to images)
	LinuxHostPaths         []string `protobuf:"bytes,12,rep,name=linux_host_paths" json:"linux_host_paths,omitempty"`
	LinuxHostPredicateName *string  `protobuf:"bytes,13,opt,name=linux_host_predicate_name" json:"linux_host_predicate_name,omitempty"`
	// The name of the predicate to use for trusted guards.
	GuardPredicateName *string `protobuf:"bytes,14,opt,name=guard_predicate_name" json:"guard_predicate_name,omitempty"`
	// The name of the predicate to use for trusted TPMs.
	TpmPredicateName *string `protobuf:"bytes,15,opt,name=tpm_predicate_name" json:"tpm_predicate_name,omitempty"`
	// The name of the predicate to use for trusted OSs.
	OsPredicateName  *string `protobuf:"bytes,16,opt,name=os_predicate_name" json:"os_predicate_name,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *DomainTemplate) Reset()                    { *m = DomainTemplate{} }
func (m *DomainTemplate) String() string            { return proto.CompactTextString(m) }
func (*DomainTemplate) ProtoMessage()               {}
func (*DomainTemplate) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{6} }

func (m *DomainTemplate) GetConfig() *DomainConfig {
	if m != nil {
		return m.Config
	}
	return nil
}

func (m *DomainTemplate) GetDatalogRules() []string {
	if m != nil {
		return m.DatalogRules
	}
	return nil
}

func (m *DomainTemplate) GetAclRules() []string {
	if m != nil {
		return m.AclRules
	}
	return nil
}

func (m *DomainTemplate) GetHostName() string {
	if m != nil && m.HostName != nil {
		return *m.HostName
	}
	return ""
}

func (m *DomainTemplate) GetHostPredicateName() string {
	if m != nil && m.HostPredicateName != nil {
		return *m.HostPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetProgramPaths() []string {
	if m != nil {
		return m.ProgramPaths
	}
	return nil
}

func (m *DomainTemplate) GetProgramPredicateName() string {
	if m != nil && m.ProgramPredicateName != nil {
		return *m.ProgramPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetContainerPaths() []string {
	if m != nil {
		return m.ContainerPaths
	}
	return nil
}

func (m *DomainTemplate) GetContainerPredicateName() string {
	if m != nil && m.ContainerPredicateName != nil {
		return *m.ContainerPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetVmPaths() []string {
	if m != nil {
		return m.VmPaths
	}
	return nil
}

func (m *DomainTemplate) GetVmPredicateName() string {
	if m != nil && m.VmPredicateName != nil {
		return *m.VmPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetLinuxHostPaths() []string {
	if m != nil {
		return m.LinuxHostPaths
	}
	return nil
}

func (m *DomainTemplate) GetLinuxHostPredicateName() string {
	if m != nil && m.LinuxHostPredicateName != nil {
		return *m.LinuxHostPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetGuardPredicateName() string {
	if m != nil && m.GuardPredicateName != nil {
		return *m.GuardPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetTpmPredicateName() string {
	if m != nil && m.TpmPredicateName != nil {
		return *m.TpmPredicateName
	}
	return ""
}

func (m *DomainTemplate) GetOsPredicateName() string {
	if m != nil && m.OsPredicateName != nil {
		return *m.OsPredicateName
	}
	return ""
}

func init() {
	proto.RegisterType((*DomainDetails)(nil), "tao.DomainDetails")
	proto.RegisterType((*X509Details)(nil), "tao.X509Details")
	proto.RegisterType((*ACLGuardDetails)(nil), "tao.ACLGuardDetails")
	proto.RegisterType((*DatalogGuardDetails)(nil), "tao.DatalogGuardDetails")
	proto.RegisterType((*TPMDetails)(nil), "tao.TPMDetails")
	proto.RegisterType((*DomainConfig)(nil), "tao.DomainConfig")
	proto.RegisterType((*DomainTemplate)(nil), "tao.DomainTemplate")
}

func init() { proto.RegisterFile("domain.proto", fileDescriptor4) }

var fileDescriptor4 = []byte{
	// 576 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x53, 0xcb, 0x8e, 0xd3, 0x3c,
	0x14, 0x56, 0x26, 0x69, 0x3b, 0x3d, 0x4d, 0x6f, 0x69, 0xe7, 0xff, 0x5d, 0x40, 0xa8, 0x0d, 0x0b,
	0x2a, 0x81, 0xaa, 0x0a, 0x31, 0x8b, 0xd9, 0x20, 0xa1, 0xa9, 0xc4, 0x06, 0x24, 0x16, 0xb3, 0x60,
	0x17, 0x99, 0xc4, 0x93, 0xb1, 0x9a, 0xd8, 0x91, 0xe3, 0x0c, 0x53, 0x9e, 0x81, 0x27, 0xe0, 0x61,
	0x78, 0x19, 0x5e, 0x04, 0xf5, 0x38, 0x86, 0xa4, 0xb0, 0xfd, 0x2e, 0x3e, 0xdf, 0xb9, 0x18, 0xfc,
	0x44, 0xe6, 0x94, 0x8b, 0x4d, 0xa1, 0xa4, 0x96, 0x81, 0xab, 0xa9, 0x0c, 0xbf, 0x39, 0x30, 0xdc,
	0x21, 0xba, 0x63, 0x9a, 0xf2, 0xac, 0x0c, 0x7c, 0xf0, 0x04, 0xcd, 0x19, 0x71, 0x96, 0xce, 0xba,
	0x1f, 0x10, 0x98, 0x14, 0x32, 0xe3, 0xf1, 0x21, 0xda, 0xb3, 0x43, 0x19, 0x15, 0x54, 0xdf, 0x91,
	0x33, 0x64, 0x02, 0x80, 0xb4, 0xa2, 0x2a, 0x89, 0xf4, 0xa1, 0x60, 0xc4, 0x45, 0xec, 0x02, 0x86,
	0x06, 0x13, 0x4c, 0x7f, 0x91, 0x6a, 0x4f, 0xbc, 0x36, 0x4c, 0x93, 0x44, 0xb1, 0xb2, 0x24, 0x1d,
	0x84, 0xa7, 0xd0, 0xaf, 0x5f, 0xd0, 0x19, 0xe9, 0x2e, 0x9d, 0xb5, 0x1b, 0x7e, 0x77, 0x60, 0xf0,
	0xe9, 0x72, 0x7b, 0x65, 0xc3, 0xcc, 0x60, 0x10, 0xcb, 0x3c, 0x97, 0x22, 0x6a, 0x64, 0x1a, 0x43,
	0x2f, 0x96, 0x95, 0xd0, 0xea, 0x50, 0x47, 0x19, 0x42, 0xa7, 0xd4, 0x54, 0xdb, 0x14, 0x3e, 0x78,
	0x31, 0xd7, 0x87, 0xba, 0xf8, 0x1c, 0x7c, 0xa9, 0x52, 0x2a, 0xf8, 0x57, 0xaa, 0xb9, 0x14, 0x75,
	0xed, 0xc7, 0x30, 0x6b, 0xa2, 0x34, 0x8b, 0x2a, 0xc1, 0x35, 0xa6, 0xc0, 0xbc, 0x25, 0x53, 0x9c,
	0x66, 0x91, 0xa8, 0xf2, 0xcf, 0x4c, 0x91, 0xde, 0xd2, 0x59, 0x77, 0xc2, 0x17, 0x30, 0x7e, 0x7b,
	0xfd, 0xfe, 0xdd, 0x31, 0xb2, 0xcd, 0x47, 0x60, 0x52, 0xf2, 0x54, 0xb0, 0x24, 0xa2, 0x71, 0x56,
	0x8f, 0x07, 0x43, 0x86, 0x5b, 0x98, 0xed, 0xa8, 0xa6, 0x99, 0x4c, 0x5b, 0x86, 0x05, 0x4c, 0x6b,
	0x83, 0xaa, 0x32, 0xd6, 0x1c, 0x68, 0xf8, 0x06, 0xe0, 0xe6, 0xe3, 0x07, 0x2b, 0x9c, 0xc0, 0xb9,
	0x2e, 0xf2, 0xc6, 0x8b, 0x47, 0x84, 0xf2, 0x7d, 0x73, 0x05, 0x3e, 0x78, 0x45, 0xac, 0x4a, 0xd3,
	0x76, 0xf8, 0xd3, 0x01, 0xdf, 0xac, 0xf2, 0x5a, 0x8a, 0x5b, 0x9e, 0x06, 0xcf, 0x61, 0x60, 0x16,
	0x1e, 0x71, 0x71, 0x2b, 0xf1, 0x95, 0xc1, 0xab, 0x60, 0xa3, 0xa9, 0xdc, 0xb4, 0x57, 0xfe, 0x0c,
	0xfa, 0x0f, 0x97, 0xdb, 0x2b, 0x23, 0x3b, 0x43, 0xd9, 0x04, 0x65, 0xcd, 0x55, 0xbc, 0x84, 0x11,
	0x8d, 0xb3, 0xc8, 0x6c, 0x0c, 0x95, 0x2e, 0x2a, 0xe7, 0xa8, 0x3c, 0x1d, 0xcc, 0x6b, 0x08, 0x12,
	0xd3, 0x7e, 0xd3, 0xe1, 0xa1, 0x83, 0x98, 0x08, 0xff, 0x98, 0xce, 0xca, 0x34, 0x8d, 0xda, 0x0e,
	0x6a, 0xc7, 0xa8, 0xfd, 0x33, 0x97, 0xf0, 0x87, 0x0b, 0x23, 0x93, 0xfe, 0x86, 0xe5, 0x45, 0x46,
	0x35, 0x0b, 0x56, 0xd0, 0x8d, 0xb1, 0xe3, 0xba, 0xc5, 0x69, 0xa3, 0xc5, 0x7a, 0x14, 0x17, 0x30,
	0xb4, 0x71, 0x70, 0xee, 0xe4, 0x6c, 0xe9, 0x9a, 0x0b, 0x3c, 0xf6, 0x64, 0x20, 0xd7, 0x42, 0x77,
	0xb2, 0xd4, 0xe6, 0xde, 0x3c, 0x7b, 0x2b, 0x08, 0x15, 0x8a, 0x25, 0x3c, 0xa6, 0x9a, 0x19, 0xb2,
	0x63, 0x6f, 0xa5, 0x50, 0x32, 0x55, 0xd4, 0xec, 0xaa, 0x24, 0x5d, 0x7c, 0xe6, 0x29, 0xfc, 0xf7,
	0x1b, 0x6e, 0xdb, 0x7a, 0x68, 0xfb, 0x1f, 0xc6, 0xb1, 0x14, 0x9a, 0x72, 0xc1, 0x54, 0x6d, 0x3c,
	0x47, 0xe3, 0x12, 0x48, 0x83, 0x68, 0x5b, 0xfb, 0xf6, 0x0e, 0xee, 0x6d, 0x31, 0x40, 0xcf, 0x02,
	0xa6, 0xf7, 0x7f, 0xd5, 0x19, 0xd8, 0xff, 0x9b, 0x71, 0x51, 0x3d, 0x44, 0xa6, 0x03, 0x34, 0xf9,
	0x68, 0x5a, 0xc1, 0xa2, 0xc9, 0xb4, 0xcd, 0x43, 0x34, 0x3f, 0x81, 0xb9, 0x59, 0xde, 0x09, 0x3b,
	0x42, 0xf6, 0x11, 0x04, 0x78, 0xa1, 0x6d, 0x6e, 0x8c, 0xdc, 0x02, 0xa6, 0xb2, 0x3c, 0xa5, 0x26,
	0x47, 0xea, 0x57, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2f, 0x7b, 0x3e, 0xf5, 0x85, 0x04, 0x00, 0x00,
}
