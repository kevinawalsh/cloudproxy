//  Copyright (c) 2014, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tao

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// A KeyType represent the type(s) of keys held by a Keys struct.
type KeyType int

// These are the types of supported keys.
const (
	Signing KeyType = 1 << iota
	Crypting
	Deriving
)

var DefaultEphemeralX509Name = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"Massachusetts"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy Ephemeral Key"},
	CommonName:         "Experimental Google CloudProxy Ephemeral Key",
}

const aesKeySize = 32 // 256-bit AES
const deriverSecretSize = 32
const hmacKeySize = 32 // SHA-256

// A Signer is used to sign and verify signatures
type Signer struct {
	ec *ecdsa.PrivateKey
}

// A Verifier is used to verify signatures.
type Verifier struct {
	ec *ecdsa.PublicKey
}

// A Crypter is used to encrypt and decrypt data.
type Crypter struct {
	aesKey  []byte
	hmacKey []byte
}

// A Deriver is used to derive key material from a context using HKDF.
type Deriver struct {
	secret []byte
}

// GenerateSigner creates a new Signer with a fresh key.
func GenerateSigner() (*Signer, error) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Signer{ec}, nil
}

// ToPrincipal produces a "key" type Prin for this signer. This contains a
// serialized CryptoKey for the public half of this signing key.
func (s *Signer) ToPrincipal() auth.Prin {
	ck := MarshalPublicSignerProto(s)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	data, _ := proto.Marshal(ck)

	return auth.NewKeyPrin(data)
}

// MarshalSignerDER serializes the signer to DER.
func MarshalSignerDER(s *Signer) ([]byte, error) {
	return x509.MarshalECPrivateKey(s.ec)
}

// UnmarshalSignerDER deserializes a Signer from DER.
func UnmarshalSignerDER(signer []byte) (*Signer, error) {
	k := new(Signer)
	var err error
	if k.ec, err = x509.ParseECPrivateKey(signer); err != nil {
		return nil, err
	}

	return k, nil
}

// NewX509Name returns a new pkix.Name.
func NewX509Name(p *X509Details) *pkix.Name {
	return &pkix.Name{
		Country:            []string{p.GetCountry()},
		Organization:       []string{p.GetOrganization()},
		OrganizationalUnit: []string{p.GetOrganizationalUnit()},
		Province:           []string{p.GetState()},
		Locality:           []string{p.GetCity()},
		CommonName:         string(p.GetCommonName()),
	}
}

func NewX509Details(name *pkix.Name) *X509Details {
	return &X509Details{
		Country:            proto.String(name.Country[0]),
		Organization:       proto.String(name.Organization[0]),
		OrganizationalUnit: proto.String(name.OrganizationalUnit[0]),
		State:              proto.String(name.Province[0]),
		City:               proto.String(name.Locality[0]),
		CommonName:         proto.String(name.CommonName),
	}
}

// X509Template creates an unsigned X.509 template with default values suitable
// for signing by this key.
func (s *Signer) X509Template(subjectName *pkix.Name, ext ...pkix.Extension) *x509.Certificate {
	return &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		Version:            2, // x509v3
		// It's always allowed for self-signed certs to have serial 1.
		SerialNumber:          new(big.Int).SetInt64(1),
		Subject:               *subjectName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1 /* years */, 0 /* months */, 0 /* days */),
		BasicConstraintsValid: true,
		IsCA: false,
		// TODO(tmroeder): I'm not sure which of these I need to make
		// OpenSSL happy.
		// KeyUsageKeyAgreement: for Chrome https x509 leaf validation (?)
		// KeyUsageCertSign: for Chrome https x509 parent validation (?)
		// KeyUsageDigitalSignature: for wget and curl x509 validation
		KeyUsage:        x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: ext,
	}
}

// CreateSignedX509 creates a signed X.509 certificate based on a template.
func (s *Signer) CreateSignedX509(subject *Verifier, template, issuer *x509.Certificate) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, subject.ec, s.ec)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (s *Signer) CreateSelfSignedX509(template *x509.Certificate) (*x509.Certificate, error) {
	return s.CreateSignedX509(s.GetVerifier(), template, template)
}

func (keys *Keys) CreateSignedX509(subject *Verifier, template *x509.Certificate, issuer string) (*x509.Certificate, error) {
	return keys.SigningKey.CreateSignedX509(subject, template, keys.Cert[issuer])
}

// marshalECDSASHASigningKeyV1 encodes a private key as a protobuf message.
func marshalECDSASHASigningKeyV1(k *ecdsa.PrivateKey) *ECDSA_SHA_SigningKeyV1 {
	return &ECDSA_SHA_SigningKeyV1{
		Curve:     NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPrivate: k.D.Bytes(),
		EcPublic:  elliptic.Marshal(k.Curve, k.X, k.Y),
	}
}

// MarshalSignerProto encodes a signing key as a CryptoKey protobuf message.
func MarshalSignerProto(s *Signer) (*CryptoKey, error) {
	m := marshalECDSASHASigningKeyV1(s.ec)
	defer ZeroBytes(m.EcPrivate)

	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_SIGNING.Enum(),
		Algorithm: CryptoKey_ECDSA_SHA.Enum(),
		Key:       b,
	}
	return ck, nil
}

// marshalECDSASHAVerifyingKeyV1 encodes a public key as a protobuf message.
func marshalECDSASHAVerifyingKeyV1(k *ecdsa.PublicKey) *ECDSA_SHA_VerifyingKeyV1 {
	return &ECDSA_SHA_VerifyingKeyV1{
		Curve:    NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPublic: elliptic.Marshal(k.Curve, k.X, k.Y),
	}

}

func unmarshalECDSASHAVerifyingKeyV1(v *ECDSA_SHA_VerifyingKeyV1) (*ecdsa.PublicKey, error) {
	if *v.Curve != NamedEllipticCurve_PRIME256_V1 {
		return nil, newError("bad curve")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), v.EcPublic)
	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return pk, nil
}

func marshalPublicKeyProto(k *ecdsa.PublicKey) *CryptoKey {
	m := marshalECDSASHAVerifyingKeyV1(k)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	b, _ := proto.Marshal(m)

	return &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_VERIFYING.Enum(),
		Algorithm: CryptoKey_ECDSA_SHA.Enum(),
		Key:       b,
	}
}

// MarshalPublicSignerProto encodes the public half of a signing key as a
// CryptoKey protobuf message.
func MarshalPublicSignerProto(s *Signer) *CryptoKey {
	return marshalPublicKeyProto(&s.ec.PublicKey)
}

// MarshalVerifierProto encodes the public verifier key as a CryptoKey protobuf
// message.
func MarshalVerifierProto(v *Verifier) *CryptoKey {
	return marshalPublicKeyProto(v.ec)
}

// UnmarshalSignerProto decodes a signing key from a CryptoKey protobuf
// message.
func UnmarshalSignerProto(ck *CryptoKey) (*Signer, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_SIGNING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_ECDSA_SHA {
		return nil, newError("bad algorithm")
	}

	var k ECDSA_SHA_SigningKeyV1
	defer ZeroBytes(k.EcPrivate)
	if err := proto.Unmarshal(ck.Key, &k); err != nil {
		return nil, err
	}

	if *k.Curve != NamedEllipticCurve_PRIME256_V1 {
		return nil, newError("bad Curve")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), k.EcPublic)
	pk := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(k.EcPrivate),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
	}

	return &Signer{pk}, nil
}

// CreateHeader encodes the version and a key hint into a CryptoHeader.
func (s *Signer) CreateHeader() (*CryptoHeader, error) {
	k := marshalECDSASHAVerifyingKeyV1(&s.ec.PublicKey)
	b, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(b)
	ch := &CryptoHeader{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		KeyHint: h[:4],
	}

	return ch, nil
}

// An ecdsaSignature wraps the two components of the signature from an ECDSA
// private key. This is copied from the Go crypto/x509 source: it just uses a
// simple two-element structure to marshal a DSA signature as ASN.1 in an X.509
// certificate.
type ecdsaSignature struct {
	R, S *big.Int
}

// Sign computes an ECDSA sigature over the contextualized data, using the
// private key of the signer.
func (s *Signer) Sign(data []byte, context string) ([]byte, error) {
	ch, err := s.CreateHeader()
	if err != nil {
		return nil, err
	}

	// TODO(tmroeder): for compatibility with the C++ version, we should
	// compute ECDSA signatures over hashes truncated to fit in the ECDSA
	// signature.
	b, err := contextualizedSHA256(ch, data, context, sha256.Size)
	if err != nil {
		return nil, err
	}

	R, S, err := ecdsa.Sign(rand.Reader, s.ec, b)
	if err != nil {
		return nil, err
	}

	m, err := asn1.Marshal(ecdsaSignature{R, S})
	if err != nil {
		return nil, err
	}

	sd := &SignedData{
		Header:    ch,
		Signature: m,
	}

	return proto.Marshal(sd)
}

// GetVerifier returns a Verifier from Signer.
func (s *Signer) GetVerifier() *Verifier {
	return &Verifier{&s.ec.PublicKey}
}

// Verify checks an ECDSA signature over the contextualized data, using the
// public key of the verifier.
func (v *Verifier) Verify(data []byte, context string, sig []byte) (bool, error) {
	// Deserialize the data and extract the CryptoHeader.
	var sd SignedData
	if err := proto.Unmarshal(sig, &sd); err != nil {
		return false, err
	}

	var ecSig ecdsaSignature
	// We ignore the first parameter, since we don't mind if there's more
	// data after the signature.
	if _, err := asn1.Unmarshal(sd.Signature, &ecSig); err != nil {
		return false, err
	}

	b, err := contextualizedSHA256(sd.Header, data, context, sha256.Size)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(v.ec, b, ecSig.R, ecSig.S), nil
}

// ToPrincipal produces a "key" type Prin for this verifier. This contains a
// hash of a serialized CryptoKey for this key.
func (v *Verifier) ToPrincipal() auth.Prin {
	return auth.NewKeyPrin(v.MarshalKey())
}

// MarshalKey serializes a Verifier.
func (v *Verifier) MarshalKey() []byte {
	ck := MarshalVerifierProto(v)

	// proto.Marshal won't fail here since we fill all required fields of the
	// message. Propagating impossible errors just leads to clutter later.
	data, _ := proto.Marshal(ck)

	return data
}

// PublicKey returns the internal cryptographic public key for a Verifier.
func (v *Verifier) PublicKey() interface{} {
	return v.ec
}

// UnmarshalKey deserializes a Verifier.
func UnmarshalKey(material []byte) (*Verifier, error) {
	var ck CryptoKey
	if err := proto.Unmarshal(material, &ck); err != nil {
		return nil, err
	}
	return UnmarshalVerifierProto(&ck)
}

// SignsForPrincipal returns true when prin is (or is a subprincipal of) this verifier key.
func (v *Verifier) SignsForPrincipal(prin auth.Prin) bool {
	return auth.SubprinOrIdentical(prin, v.ToPrincipal())
}

// FromX509 creates a Verifier from an X509 certificate.
func FromX509(cert *x509.Certificate) (*Verifier, error) {
	ecpk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, newError("invalid key type in certificate: must be ECDSA")
	}

	return &Verifier{ecpk}, nil
}

// Equals checks to see if the public key in the X.509 certificate matches the
// public key in the verifier.
func (v *Verifier) Equals(cert *x509.Certificate) bool {
	v2, err := FromX509(cert)
	if err != nil {
		return false
	}

	p := v.ToPrincipal()
	p2 := v2.ToPrincipal()
	return p.Identical(p2)
}

// UnmarshalVerifierProto decodes a verifying key from a CryptoKey protobuf
// message.
func UnmarshalVerifierProto(ck *CryptoKey) (*Verifier, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_VERIFYING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_ECDSA_SHA {
		return nil, newError("bad algorithm")
	}

	var ecvk ECDSA_SHA_VerifyingKeyV1
	if err := proto.Unmarshal(ck.Key, &ecvk); err != nil {
		return nil, err
	}

	ec, err := unmarshalECDSASHAVerifyingKeyV1(&ecvk)
	if err != nil {
		return nil, err
	}

	return &Verifier{ec}, nil
}

// CreateHeader instantiates and fills in a header for this verifying key.
func (v *Verifier) CreateHeader() (*CryptoHeader, error) {
	k := marshalECDSASHAVerifyingKeyV1(v.ec)
	b, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	h := sha1.Sum(b)
	ch := &CryptoHeader{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		KeyHint: h[:4],
	}

	return ch, nil
}

// contextualizeData produces a single string from a header, data, and a context.
func contextualizeData(h *CryptoHeader, data []byte, context string) ([]byte, error) {
	s := &SignaturePDU{
		Header:  h,
		Context: proto.String(context),
		Data:    data,
	}

	return proto.Marshal(s)
}

// contextualizedSHA256 performs a SHA-256 sum over contextualized data.
func contextualizedSHA256(h *CryptoHeader, data []byte, context string, digestLen int) ([]byte, error) {
	b, err := contextualizeData(h, data, context)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(b)
	return hash[:digestLen], nil
}

// GenerateCrypter instantiates a new Crypter with fresh keys.
func GenerateCrypter() (*Crypter, error) {
	c := &Crypter{
		aesKey:  make([]byte, aesKeySize),
		hmacKey: make([]byte, hmacKeySize),
	}

	if _, err := rand.Read(c.aesKey); err != nil {
		return nil, err
	}

	if _, err := rand.Read(c.hmacKey); err != nil {
		return nil, err
	}

	return c, nil
}

// Encrypt encrypts plaintext into ciphertext and protects ciphertext integrity
// with a MAC.
func (c *Crypter) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return nil, err
	}

	ch, err := c.CreateHeader()
	if err != nil {
		return nil, err
	}

	// A ciphertext consists of an IV, encrypted bytes, and the output of
	// HMAC-SHA256.
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, iv)
	s.XORKeyStream(ciphertext[aes.BlockSize:], data)

	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(ciphertext)
	m := mac.Sum(nil)

	ed := &EncryptedData{
		Header:     ch,
		Iv:         iv,
		Ciphertext: ciphertext[aes.BlockSize:],
		Mac:        m,
	}

	return proto.Marshal(ed)
}

// Decrypt checks the MAC then decrypts ciphertext into plaintext.
func (c *Crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	var ed EncryptedData
	if err := proto.Unmarshal(ciphertext, &ed); err != nil {
		return nil, err
	}

	// TODO(tmroeder): we're currently mostly ignoring the CryptoHeader,
	// since we only have one key.
	if *ed.Header.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	// Check the HMAC before touching the ciphertext.
	fullCiphertext := make([]byte, len(ed.Iv)+len(ed.Ciphertext))
	copy(fullCiphertext, ed.Iv)
	copy(fullCiphertext[len(ed.Iv):], ed.Ciphertext)

	mac := hmac.New(sha256.New, c.hmacKey)
	mac.Write(fullCiphertext)
	m := mac.Sum(nil)
	if !hmac.Equal(m, ed.Mac) {
		return nil, newError("bad HMAC")
	}

	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return nil, err
	}

	s := cipher.NewCTR(block, ed.Iv)
	data := make([]byte, len(ed.Ciphertext))
	s.XORKeyStream(data, ed.Ciphertext)
	return data, nil
}

// marshalAESCTRHMACSHACryptingKeyV1 encodes a private AES/HMAC key pair
// into a protobuf message.
func marshalAESCTRHMACSHACryptingKeyV1(c *Crypter) *AES_CTR_HMAC_SHA_CryptingKeyV1 {
	return &AES_CTR_HMAC_SHA_CryptingKeyV1{
		Mode:        CryptoCipherMode_CIPHER_MODE_CTR.Enum(),
		AesPrivate:  c.aesKey,
		HmacPrivate: c.hmacKey,
	}
}

// MarshalCrypterProto encodes a Crypter as a CryptoKey protobuf message.
func MarshalCrypterProto(c *Crypter) (*CryptoKey, error) {
	k := marshalAESCTRHMACSHACryptingKeyV1(c)

	// Note that we don't need to call ZeroBytes on k.AesPrivate or
	// k.HmacPrivate, since they're just slice references to the underlying
	// keys.
	m, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_CRYPTING.Enum(),
		Algorithm: CryptoKey_AES_CTR_HMAC_SHA.Enum(),
		Key:       m,
	}

	return ck, nil
}

// UnmarshalCrypterProto decodes a crypting key from a CryptoKey protobuf
// message.
func UnmarshalCrypterProto(ck *CryptoKey) (*Crypter, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_CRYPTING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_AES_CTR_HMAC_SHA {
		return nil, newError("bad algorithm")
	}

	var k AES_CTR_HMAC_SHA_CryptingKeyV1
	if err := proto.Unmarshal(ck.Key, &k); err != nil {
		return nil, err
	}

	if *k.Mode != CryptoCipherMode_CIPHER_MODE_CTR {
		return nil, newError("bad cipher mode")
	}

	c := new(Crypter)
	c.aesKey = k.AesPrivate
	c.hmacKey = k.HmacPrivate
	return c, nil
}

// CreateHeader instantiates and fills in a header for this crypting key.
func (c *Crypter) CreateHeader() (*CryptoHeader, error) {
	k := marshalAESCTRHMACSHACryptingKeyV1(c)
	b, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(b)

	h := sha1.Sum(b)
	ch := &CryptoHeader{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		KeyHint: h[:4],
	}

	return ch, nil

}

// GenerateDeriver generates a deriver with a fresh secret.
func GenerateDeriver() (*Deriver, error) {
	d := new(Deriver)
	d.secret = make([]byte, deriverSecretSize)
	if _, err := rand.Read(d.secret); err != nil {
		return nil, err
	}

	return d, nil
}

// Derive uses HKDF with HMAC-SHA256 to derive key bytes in its material
// parameter.
func (d *Deriver) Derive(salt, context, material []byte) error {
	f := hkdf.New(sha256.New, d.secret, salt, context)
	if _, err := f.Read(material); err != nil {
		return err
	}

	return nil
}

// marshalHMACSHADerivingKeyV1 encodes a deriving key as a protobuf message.
func marshalHMACSHADerivingKeyV1(d *Deriver) *HMAC_SHA_DerivingKeyV1 {
	return &HMAC_SHA_DerivingKeyV1{
		Mode:        CryptoDerivingMode_DERIVING_MODE_HKDF.Enum(),
		HmacPrivate: d.secret,
	}
}

// MarshalDeriverProto encodes a Deriver as a CryptoKey protobuf message.
func MarshalDeriverProto(d *Deriver) (*CryptoKey, error) {
	k := marshalHMACSHADerivingKeyV1(d)

	// Note that we don't need to call ZeroBytes on k.HmacPrivate since
	// it's just a slice reference to the underlying keys.
	m, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	ck := &CryptoKey{
		Version:   CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   CryptoKey_DERIVING.Enum(),
		Algorithm: CryptoKey_HMAC_SHA.Enum(),
		Key:       m,
	}

	return ck, nil
}

// UnmarshalDeriverProto decodes a deriving key from a CryptoKey protobuf
// message.
func UnmarshalDeriverProto(ck *CryptoKey) (*Deriver, error) {
	if *ck.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *ck.Purpose != CryptoKey_DERIVING {
		return nil, newError("bad purpose")
	}

	if *ck.Algorithm != CryptoKey_HMAC_SHA {
		return nil, newError("bad algorithm")
	}

	var k HMAC_SHA_DerivingKeyV1
	if err := proto.Unmarshal(ck.Key, &k); err != nil {
		return nil, err
	}

	if *k.Mode != CryptoDerivingMode_DERIVING_MODE_HKDF {
		return nil, newError("bad deriving mode")
	}

	d := new(Deriver)
	d.secret = k.HmacPrivate
	return d, nil
}

// A Keys manages a set of signing, verifying, encrypting, and key-deriving
// keys.
type Keys struct {
	dir      string
	policy   string
	keyTypes KeyType

	SigningKey   *Signer
	CryptingKey  *Crypter
	VerifyingKey *Verifier
	DerivingKey  *Deriver
	Delegation   *Attestation
	CertificatePool
}

type CertificatePool struct {
	Cert map[string]*x509.Certificate
}

func NewCertificatePool() CertificatePool {
	return CertificatePool{make(map[string]*x509.Certificate)}
}

// The paths to the filename used by the Keys type.
const (
	X509PathDefault     = "cert.der"
	X509PathTemplate    = "cert_%s.der"
	PBEKeysetPath       = "keys"
	PBESignerPath       = "signer"
	SealedKeysetPath    = "sealed_keyset"
	PlaintextKeysetPath = "plaintext_keyset"
)

// X509Path returns the path to the verifier key, stored as an X.509
// certificate.
func (k *Keys) X509Path(name string) string {
	if k.dir == "" {
		return ""
	}
	if name == "default" {
		return path.Join(k.dir, X509PathDefault)
	} else {
		return path.Join(k.dir, fmt.Sprintf(X509PathTemplate, name))
	}
}

func (k *Keys) X509Paths() map[string]string {
	if k.dir == "" {
		return nil
	}
	fi, err := ioutil.ReadDir(k.dir)
	if err != nil {
		return nil
	}
	names := make(map[string]string)
	for _, f := range fi {
		if f.IsDir() {
			continue
		}
		fn := f.Name()
		if strings.HasPrefix(fn, "cert_") && strings.HasSuffix(fn, ".der") {
			name := fn[5 : len(fn)-4]
			if name != "default" {
				names[name] = path.Join(k.dir, fn)
			}
		} else if fn == "cert.der" {
			names["default"] = path.Join(k.dir, fn)
		}
	}
	return names
}

func (k *Keys) LoadCerts() error {
	for name, fname := range k.X509Paths() {
		f, err := os.Open(fname)
		if err != nil {
			return err
		}
		der, err := ioutil.ReadAll(f)
		f.Close()
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		k.Cert[name] = cert
	}
	return nil
}

func (k *Keys) SaveCerts() error {
	for name, cert := range k.Cert {
		if err := util.WritePath(k.X509Path(name), cert.Raw, 0777, 0666); err != nil {
			return err
		}
	}
	return nil
}

// PBEKeysetPath returns the path for stored keys.
func (k *Keys) PBEKeysetPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, PBEKeysetPath)
}

// PBESignerPath returns the path for a stored signing key.
func (k *Keys) PBESignerPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, PBESignerPath)
}

// SealedKeysetPath returns the path for a stored signing key.
func (k *Keys) SealedKeysetPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, SealedKeysetPath)
}

// PlaintextKeysetPath returns the path for a key stored in plaintext (this is
// not normally the case).
func (k *Keys) PlaintextKeysetPath() string {
	if k.dir == "" {
		return ""
	}
	return path.Join(k.dir, PlaintextKeysetPath)
}

// ZeroBytes clears the bytes in a slice.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// NewTemporaryKeys creates a new Keys structure with the specified keys. If a
// signing key is generated, a self-signed x509 certificate will be created
// using a default name.
func NewTemporaryKeys(keyTypes KeyType) (*Keys, error) {
	return NewTemporaryNamedKeys(keyTypes, nil)
}

// NewTemporaryNamedKeys creates a new Keys structure with the specified keys.
// If a signing key is generated and name is not nil, a self-signed x509
// certificate will be created using the given name.
func NewTemporaryNamedKeys(keyTypes KeyType, name *pkix.Name) (*Keys, error) {
	k := &Keys{
		keyTypes:        keyTypes,
		CertificatePool: NewCertificatePool(),
	}
	if k.keyTypes == 0 || (k.keyTypes & ^Signing & ^Crypting & ^Deriving != 0) {
		return nil, newError("bad key type")
	}

	var err error
	if k.keyTypes&Signing == Signing {
		k.SigningKey, err = GenerateSigner()
		if err != nil {
			return nil, err
		}

		k.VerifyingKey = k.SigningKey.GetVerifier()

		/*
			if name == nil {
				name = DefaultEphemeralX509Name
			}
			template := k.SigningKey.X509Template(name)
			template.IsCA = true
			cert, err := k.SigningKey.CreateSelfSignedX509(template)
			if err != nil {
				return nil, err
			}
			k.Cert["self"] = cert
			k.Cert["default"] = cert
		*/
	}

	if k.keyTypes&Crypting == Crypting {
		k.CryptingKey, err = GenerateCrypter()
		if err != nil {
			return nil, err
		}
	}

	if k.keyTypes&Deriving == Deriving {
		k.DerivingKey, err = GenerateDeriver()
		if err != nil {
			return nil, err
		}
	}

	return k, nil
}

// NewSignedOnDiskPBEKeys creates the same type of keys as NewOnDiskPBEKeys but
// uses generates a signed certificate for the keys using the provided signer,
// which must have both a SigningKey and a default certificate.
func NewSignedOnDiskPBEKeys(keyTypes KeyType, password []byte, path string, name *pkix.Name, serial int64, signer *Keys) (*Keys, error) {
	if signer == nil || name == nil {
		return nil, newError("must supply a signer and a name")
	}

	if signer.Cert["default"] == nil || signer.SigningKey == nil {
		return nil, newError("the signing key must have a SigningKey and a default Cert")
	}

	if keyTypes & ^Signing != 0 {
		return nil, newError("can't sign a key that has no signer")
	}

	k, err := NewOnDiskPBEKeys(keyTypes, password, path, nil)
	if err != nil {
		return nil, err
	}

	// Only create a new cert if we don't yet have one.
	if len(k.Cert) == 0 {
		template := signer.SigningKey.X509Template(name)
		template.SerialNumber.SetInt64(serial)
		template.IsCA = false
		cert, err := signer.CreateSignedX509(k.VerifyingKey, template, "default")
		if err != nil {
			return nil, err
		}
		k.Cert["default"] = cert

		if err = k.SaveCerts(); err != nil {
			return nil, err
		}
	}

	return k, nil
}

// InitOnDiskPBEKeys creates a new Keys structure with the specified key types
// stored under PBE on disk. If name is not nil, then a self-signed x509
// certificate will be generated and saved as well.
func InitOnDiskPBEKeys(keyTypes KeyType, password []byte, path string, name *pkix.Name) (*Keys, error) {
	if keyTypes == 0 || (keyTypes & ^Signing & ^Crypting & ^Deriving != 0) {
		return nil, newError("bad key type")
	}

	if path == "" {
		return nil, newError("bad init call: no path for keys")
	}

	if len(password) == 0 {
		return nil, newError("password may not be empty")
	}

	var k *Keys
	var err error

	if keyTypes & ^Signing != 0 {
		// There are are multiple keys, so use a custom protobuf format.
		k, err = NewTemporaryNamedKeys(keyTypes, name)
		if err != nil {
			return nil, err
		}
		k.dir = path

		cks, err := MarshalKeyset(k)
		if err != nil {
			return nil, err
		}

		// TODO(tmroeder): defer zeroKeyset(cks)

		m, err := proto.Marshal(cks)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(m)

		enc, err := PBEEncrypt(m, password)
		if err != nil {
			return nil, err
		}

		if err = util.WritePath(k.PBEKeysetPath(), enc, 0777, 0600); err != nil {
			return nil, err
		}
	} else {
		k = &Keys{
			keyTypes:        keyTypes,
			dir:             path,
			CertificatePool: NewCertificatePool(),
		}
		// Just a signer, so create fresh key and store it to PBESignerPath.
		if k.SigningKey, err = GenerateSigner(); err != nil {
			return nil, err
		}

		k.VerifyingKey = k.SigningKey.GetVerifier()
		p, err := MarshalSignerDER(k.SigningKey)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(p)

		pb, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", p, password, x509.PEMCipherAES128)
		if err != nil {
			return nil, err
		}

		pbes, err := util.CreatePath(k.PBESignerPath(), 0777, 0600)
		if err != nil {
			return nil, err
		}
		defer pbes.Close()

		if err = pem.Encode(pbes, pb); err != nil {
			return nil, err
		}

		if name == nil {
			name = DefaultEphemeralX509Name
		}
		template := k.SigningKey.X509Template(name)
		template.IsCA = true
		cert, err := k.SigningKey.CreateSelfSignedX509(template)
		if err != nil {
			return nil, err
		}
		k.Cert["self"] = cert
		k.Cert["default"] = cert
	}

	if err = k.SaveCerts(); err != nil {
		return nil, err
	}

	return k, nil
}

// LoadOnDiskPBEKeys loads a Keys structure with the specified key types
// previously stored under PBE on disk. If key type is only Signer, then
// password can be empty, in which case only the public part of the singer is
// loaded.
func LoadOnDiskPBEKeys(keyTypes KeyType, password []byte, path string) (*Keys, error) {
	if keyTypes == 0 || (keyTypes & ^Signing & ^Crypting & ^Deriving != 0) {
		return nil, newError("bad key type")
	}

	if path == "" {
		return nil, newError("bad init call: no path for keys")
	}

	if len(password) == 0 && keyTypes & ^Signing != 0 {
		return nil, newError("without a password, only a verifying key can be loaded")
	}

	k := &Keys{
		keyTypes:        keyTypes,
		dir:             path,
		CertificatePool: NewCertificatePool(),
	}
	if err := k.LoadCerts(); err != nil {
		return nil, err
	}

	// if no password and just signer, then load cert or die
	// else if more than signer, then load cert if possible
	// else just signer, load cert if possible

	if len(password) == 0 {
		// This means there's no secret information: just load a public
		// verifying key.
		if k.Cert["default"] == nil {
			return nil, newError("no password and can't load default cert: %s", k.X509Path("default"))
		}

		var err error
		if k.VerifyingKey, err = FromX509(k.Cert["default"]); err != nil {
			return nil, err
		}
	} else if k.keyTypes & ^Signing != 0 {
		// There are are multiple keys, so use a custom protobuf format.
		f, err := os.Open(k.PBEKeysetPath())
		if err != nil {
			return nil, err
		}
		defer f.Close()
		ks, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		data, err := PBEDecrypt(ks, password)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(data)

		var cks CryptoKeyset
		if err = proto.Unmarshal(data, &cks); err != nil {
			return nil, err
		}

		// TODO(tmroeder): defer zeroKeyset(&cks)

		ktemp, err := UnmarshalKeyset(&cks)
		if err != nil {
			return nil, err
		}

		k.SigningKey = ktemp.SigningKey
		k.VerifyingKey = ktemp.VerifyingKey
		k.CryptingKey = ktemp.CryptingKey
		k.DerivingKey = ktemp.DerivingKey
	} else {
		// There's just a signer, so do PEM encryption of the encoded key.
		f, err := os.Open(k.PBESignerPath())
		if err != nil {
			return nil, err
		}
		defer f.Close()
		// Read the signer.
		ss, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		pb, rest := pem.Decode(ss)
		if pb == nil || len(rest) > 0 {
			return nil, newError("decoding failure")
		}

		p, err := x509.DecryptPEMBlock(pb, password)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(p)

		if k.SigningKey, err = UnmarshalSignerDER(p); err != nil {
			return nil, err
		}
		k.VerifyingKey = k.SigningKey.GetVerifier()
	}

	return k, nil
}

// NewOnDiskPBEKeys either loads or creates a Keys structure with the specified
// key types stored under PBE on disk. If keys are created and name is not nil,
// then a self-signed x509 certificate will be generated and saved as well. If
// key type is only signer, then password can be empty, in which case keys must
// be loaded an only the public part of the signer is loaded.
func NewOnDiskPBEKeys(keyTypes KeyType, password []byte, dir string, name *pkix.Name) (*Keys, error) {
	var f string
	if keyTypes & ^Signing == 0 && len(password) == 0 {
		f = path.Join(dir, X509PathDefault)
	} else if keyTypes & ^Signing == 0 {
		f = path.Join(dir, PBESignerPath)
	} else {
		f = path.Join(dir, PBEKeysetPath)
	}
	if _, err := os.Stat(f); err == nil {
		return LoadOnDiskPBEKeys(keyTypes, password, dir)
	} else {
		return InitOnDiskPBEKeys(keyTypes, password, dir, name)
	}
}

// NewTemporaryTaoDelegatedKeys initializes a set of temporary keys under a host
// Tao, using the Tao to generate a delegation for the signing key. Since these
// keys are never stored on disk, they are not sealed to the Tao. If a signing
// key is requested, then a matching self-signed x509 certificate is generated for use by tao.Conn.
func NewTemporaryTaoDelegatedKeys(keyTypes KeyType, name *pkix.Name, t Tao) (*Keys, error) {
	k, err := NewTemporaryNamedKeys(keyTypes, name)
	if err != nil {
		return nil, err
	}

	if t != nil && k.SigningKey != nil {

		self, err := t.GetTaoName()
		if err != nil {
			return nil, err
		}

		s := &auth.Speaksfor{
			Delegate:  k.SigningKey.ToPrincipal(),
			Delegator: self,
		}
		if k.Delegation, err = t.Attest(&self, nil, nil, s); err != nil {
			return nil, err
		}
	}

	return k, nil
}

// PBEEncrypt encrypts plaintext using a password to generate a key. Note that
// since this is for private program data, we don't try for compatibility with
// the C++ Tao version of the code.
func PBEEncrypt(plaintext, password []byte) ([]byte, error) {
	if password == nil || len(password) == 0 {
		return nil, newError("null or empty password")
	}

	pbed := &PBEData{
		Version: CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Cipher:  proto.String("aes128-ctr"),
		Hmac:    proto.String("sha256"),
		// The IV is required, so we include it, but this algorithm doesn't use it.
		Iv:         make([]byte, aes.BlockSize),
		Iterations: proto.Int32(4096),
		Salt:       make([]byte, aes.BlockSize),
	}

	// We use the first half of the salt for the AES key and the second
	// half for the HMAC key, since the standard recommends at least 8
	// bytes of salt.
	if _, err := rand.Read(pbed.Salt); err != nil {
		return nil, err
	}

	// 128-bit AES key.
	aesKey := pbkdf2.Key(password, pbed.Salt[:8], int(*pbed.Iterations), 16, sha256.New)
	defer ZeroBytes(aesKey)

	// 64-byte HMAC-SHA256 key.
	hmacKey := pbkdf2.Key(password, pbed.Salt[8:], int(*pbed.Iterations), 64, sha256.New)
	defer ZeroBytes(hmacKey)
	c := &Crypter{aesKey, hmacKey}

	// Note that we're abusing the PBEData format here, since the IV and
	// the MAC are actually contained in the ciphertext from Encrypt().
	var err error
	if pbed.Ciphertext, err = c.Encrypt(plaintext); err != nil {
		return nil, err
	}

	return proto.Marshal(pbed)
}

// PBEDecrypt decrypts ciphertext using a password to generate a key. Note that
// since this is for private program data, we don't try for compatibility with
// the C++ Tao version of the code.
func PBEDecrypt(ciphertext, password []byte) ([]byte, error) {
	if password == nil || len(password) == 0 {
		return nil, newError("null or empty password")
	}

	var pbed PBEData
	if err := proto.Unmarshal(ciphertext, &pbed); err != nil {
		return nil, err
	}

	// Recover the keys from the password and the PBE header.
	if *pbed.Version != CryptoVersion_CRYPTO_VERSION_1 {
		return nil, newError("bad version")
	}

	if *pbed.Cipher != "aes128-ctr" {
		return nil, newError("bad cipher")
	}

	if *pbed.Hmac != "sha256" {
		return nil, newError("bad hmac")
	}

	// 128-bit AES key.
	aesKey := pbkdf2.Key(password, pbed.Salt[:8], int(*pbed.Iterations), 16, sha256.New)
	defer ZeroBytes(aesKey)

	// 64-byte HMAC-SHA256 key.
	hmacKey := pbkdf2.Key(password, pbed.Salt[8:], int(*pbed.Iterations), 64, sha256.New)
	defer ZeroBytes(hmacKey)
	c := &Crypter{aesKey, hmacKey}

	// Note that we're abusing the PBEData format here, since the IV and
	// the MAC are actually contained in the ciphertext from Encrypt().
	data, err := c.Decrypt(pbed.Ciphertext)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// MarshalKeyset encodes the keys into a protobuf message.
func MarshalKeyset(k *Keys) (*CryptoKeyset, error) {
	var cks []*CryptoKey
	if k.keyTypes&Signing == Signing {
		ck, err := MarshalSignerProto(k.SigningKey)
		if err != nil {
			return nil, err
		}

		cks = append(cks, ck)
	}

	if k.keyTypes&Crypting == Crypting {
		ck, err := MarshalCrypterProto(k.CryptingKey)
		if err != nil {
			return nil, err
		}

		cks = append(cks, ck)
	}

	if k.keyTypes&Deriving == Deriving {
		ck, err := MarshalDeriverProto(k.DerivingKey)
		if err != nil {
			return nil, err
		}

		cks = append(cks, ck)
	}

	ckset := &CryptoKeyset{
		Keys: cks,
	}

	return ckset, nil
}

// UnmarshalKeyset decodes a CryptoKeyset into a temporary Keys structure. Note
// that this Keys structure doesn't have any of its variables set.
func UnmarshalKeyset(cks *CryptoKeyset) (*Keys, error) {
	k := new(Keys)
	var err error
	for i := range cks.Keys {
		if *cks.Keys[i].Purpose == CryptoKey_SIGNING {
			if k.SigningKey, err = UnmarshalSignerProto(cks.Keys[i]); err != nil {
				return nil, err
			}

			k.VerifyingKey = k.SigningKey.GetVerifier()
		}

		if *cks.Keys[i].Purpose == CryptoKey_CRYPTING {
			if k.CryptingKey, err = UnmarshalCrypterProto(cks.Keys[i]); err != nil {
				return nil, err
			}
		}

		if *cks.Keys[i].Purpose == CryptoKey_DERIVING {
			if k.DerivingKey, err = UnmarshalDeriverProto(cks.Keys[i]); err != nil {
				return nil, err
			}
		}
	}

	return k, nil
}

// InitOnDiskTaoSealedKeys sets up the keys sealed under a host Tao.
func InitOnDiskTaoSealedKeys(keyTypes KeyType, name *pkix.Name, t Tao, path, policy string) (*Keys, error) {
	// Fail if no parent Tao exists (otherwise t.Seal() would not be called).
	if t == nil {
		return nil, errors.New("parent tao is nil")
	}

	k, err := NewTemporaryTaoDelegatedKeys(keyTypes, name, t)
	if err != nil {
		return nil, err
	}
	k.dir = path
	k.policy = policy

	return k, k.Save(t)
}

// LoadOnDiskTaoSealedKeys loads keys sealed under a host Tao.
func LoadOnDiskTaoSealedKeys(keyTypes KeyType, t Tao, path, policy string) (*Keys, error) {
	// Fail if no parent Tao exists (otherwise t.Unseal() would not be called).
	if t == nil {
		return nil, errors.New("parent tao is nil")
	}

	return LoadKeys(keyTypes, t, path, policy)
}

// NewOnDiskTaoSealedKeys sets up the keys sealed under a host Tao or reads sealed keys.
func NewOnDiskTaoSealedKeys(keyTypes KeyType, name *pkix.Name, t Tao, dir, policy string) (*Keys, error) {
	// Fail if no parent Tao exists (otherwise t.Seal() would not be called).
	if t == nil {
		return nil, errors.New("parent tao is nil")
	}
	f := path.Join(dir, SealedKeysetPath)
	if _, err := os.Stat(f); err == nil {
		return LoadOnDiskTaoSealedKeys(keyTypes, t, dir, policy)
	} else {
		return InitOnDiskTaoSealedKeys(keyTypes, name, t, dir, policy)
	}
}

// Save serializes, seals, and writes a key set to disk. It calls t.Seal().
func (k *Keys) Save(t Tao) error {
	// Marshal key set.
	cks, err := MarshalKeyset(k)
	if err != nil {
		return err
	}
	cks.Delegation = k.Delegation

	// TODO(tmroeder): defer zeroKeyset(cks)

	m, err := proto.Marshal(cks)
	if err != nil {
		return err
	}
	defer ZeroBytes(m)

	data, err := t.Seal(m, k.policy)
	if err != nil {
		return err
	}

	if err = util.WritePath(k.SealedKeysetPath(), data, 0700, 0600); err != nil {
		return err
	}

	if err = k.SaveCerts(); err != nil {
		return err
	}

	return nil
}

// LoadKeys reads a key set from file. If there is a parent tao (t!=nil), then
// expect the keys are sealed and call t.Unseal(); otherwise, expect the key
// set to be plaintext.
func LoadKeys(keyTypes KeyType, t Tao, path, policy string) (*Keys, error) {
	k := &Keys{
		keyTypes:        keyTypes,
		dir:             path,
		policy:          policy,
		CertificatePool: NewCertificatePool(),
	}

	// Check to see if there are already keys.
	var keysetPath string
	if t == nil {
		keysetPath = k.PlaintextKeysetPath()
	} else {
		keysetPath = k.SealedKeysetPath()
	}
	f, err := os.Open(keysetPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ks, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var cks CryptoKeyset
	if t != nil {
		data, p, err := t.Unseal(ks)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(data)

		if p != policy {
			return nil, errors.New("invalid policy from Unseal")
		}
		if err = proto.Unmarshal(data, &cks); err != nil {
			return nil, err
		}

	} else {
		if err = proto.Unmarshal(ks, &cks); err != nil {
			return nil, err
		}
	}

	// TODO(tmroeder): defer zeroKeyset(&cks)

	ktemp, err := UnmarshalKeyset(&cks)
	if err != nil {
		return nil, err
	}

	k.SigningKey = ktemp.SigningKey
	k.VerifyingKey = ktemp.VerifyingKey
	k.CryptingKey = ktemp.CryptingKey
	k.DerivingKey = ktemp.DerivingKey

	// Read the delegation.
	k.Delegation = cks.Delegation

	// Read all certs.
	if err := k.LoadCerts(); err != nil {
		return nil, err
	}

	return k, nil
}

// NewSecret creates and encrypts a new secret value of the given length, or it
// reads and decrypts the value and checks that it's the right length. It
// creates the file and its parent directories if these directories do not
// exist.
func (k *Keys) NewSecret(file string, length int) ([]byte, error) {
	if _, err := os.Stat(file); err != nil {
		// Create the parent directories and the file.
		if err := util.MkdirAll(path.Dir(file), 0700); err != nil {
			return nil, err
		}

		secret := make([]byte, length)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}

		enc, err := k.CryptingKey.Encrypt(secret)
		if err != nil {
			return nil, err
		}

		if err := ioutil.WriteFile(file, enc, 0700); err != nil {
			return nil, err
		}

		return secret, nil
	}

	enc, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	dec, err := k.CryptingKey.Decrypt(enc)
	if err != nil {
		return nil, err
	}

	if len(dec) != length {
		ZeroBytes(dec)
		return nil, newError("The decrypted value had length %d, but it should have had length %d", len(dec), length)
	}

	return dec, nil
}

// SaveKeyset serializes and saves a Keys object to disk in plaintext.
func SaveKeyset(k *Keys, dir string) error {
	k.dir = dir
	cks, err := MarshalKeyset(k)
	if err != nil {
		return err
	}
	cks.Delegation = k.Delegation

	m, err := proto.Marshal(cks)
	if err != nil {
		return err
	}

	if err = util.WritePath(k.PlaintextKeysetPath(), m, 0700, 0600); err != nil {
		return err
	}

	return nil
}
