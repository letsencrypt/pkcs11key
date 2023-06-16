package pkcs11key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/miekg/pkcs11"
)

func init() {
	var err error
	ecKey, err = genECPubKey()
	if err != nil {
		log.Fatal(err)
	}
	ecKeyID, err = getECPoint(ecKey.(*ecdsa.PublicKey))
	if err != nil {
		log.Fatal(err)
	}
}

// Generate an ephemeral ECDSA key pair and return the public key corresponding
// to the private key. If a key pair cannot be generated, an error is returned.
func genECPubKey() (crypto.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return privateKey.Public(), nil
}

// Retrieve the DER-encoding of ANSI X9.62 ECPoint value 'Q' from a given ECDSA
// public key to match against a PKCS#11 CKA_EC_POINT attribute. If the
// point cannot be marshalled, an error will be returned.
func getECPoint(e *ecdsa.PublicKey) ([]byte, error) {
	rawValue := asn1.RawValue{
		Tag:   4,
		Bytes: elliptic.Marshal(e.Curve, e.X, e.Y),
	}
	marshalledPoint, err := asn1.Marshal(rawValue)
	if err != nil {
		return nil, err
	}

	return marshalledPoint, nil
}

type mockCtx struct {
	currentSearch []*pkcs11.Attribute
}

const sessionHandle = pkcs11.SessionHandle(17)

// A trivial RSA public key for use in testing. We provide a CKA_ID and a
// marshalled copy so we can return the relevent items from the mocked pkcs11
// module.
var rsaKey = &rsa.PublicKey{N: big.NewInt(1), E: 1}

const rsaPrivateKeyHandle = pkcs11.ObjectHandle(23)
const rsaPublicKeyHandle = pkcs11.ObjectHandle(24)
const rsaKeyID = byte(0x04)

var ecKey crypto.PublicKey
var ecKeyID []byte

const ecPrivateKeyHandle = pkcs11.ObjectHandle(32)
const ecPublicKeyHandle = pkcs11.ObjectHandle(33)

var slots = []uint{7, 8, 9}
var tokenInfo = pkcs11.TokenInfo{
	Label: "token label",
}

func (c *mockCtx) CloseSession(sh pkcs11.SessionHandle) error {
	return nil
}

func (c *mockCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	c.currentSearch = []*pkcs11.Attribute{}
	return nil
}

func (c *mockCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	c.currentSearch = temp
	return nil
}

func (c *mockCtx) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	if reflect.DeepEqual(c.currentSearch, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsaKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaKey.E)).Bytes()),
	}) {
		return []pkcs11.ObjectHandle{rsaPublicKeyHandle}, false, nil
	}
	if reflect.DeepEqual(c.currentSearch, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{rsaKeyID}),
	}) {
		return []pkcs11.ObjectHandle{rsaPrivateKeyHandle}, false, nil
	}

	if reflect.DeepEqual(c.currentSearch, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []uint8{0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7}),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecKeyID),
		//pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []uint8{0x4, 0x41, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}),
	}) {
		return []pkcs11.ObjectHandle{ecPublicKeyHandle}, false, nil
	}
	if reflect.DeepEqual(c.currentSearch, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ecKeyID),
	}) {
		return []pkcs11.ObjectHandle{ecPrivateKeyHandle}, false, nil
	}
	fmt.Println("unrecognized search:")
	for _, v := range c.currentSearch {
		fmt.Printf("  Type: %x, Value: %x\n", v.Type, v.Value)
	}
	return nil, false, nil
}

func p11Attribute(Type uint, Value []byte) *pkcs11.Attribute {
	return &pkcs11.Attribute{
		Type:  Type,
		Value: Value,
	}
}

func rsaPublicAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		if a.Type == pkcs11.CKA_ID {
			output = append(output, p11Attribute(a.Type, []byte{rsaKeyID}))
		}
	}
	return output, nil
}

func rsaPrivateAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		// Return CKA_ALWAYS_AUTHENTICATE = 1 (true)
		if a.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			output = append(output, p11Attribute(a.Type, []byte{byte(1)}))
		}
	}
	return output, nil
}

func ecPublicKeyAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		switch a.Type {
		case pkcs11.CKA_ID:
			output = append(output, p11Attribute(a.Type, ecKeyID))
		}
	}
	return output, nil
}

func (c *mockCtx) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	switch o {
	case rsaPrivateKeyHandle:
		return rsaPrivateAttributes(template)
	case rsaPublicKeyHandle:
		return rsaPublicAttributes(template)
	case ecPublicKeyHandle:
		return ecPublicKeyAttributes(template)
	default:
		return nil, nil
	}
}

func (c *mockCtx) GetSlotList(tokenPresent bool) ([]uint, error) {
	return slots, nil
}

func (c *mockCtx) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	return tokenInfo, nil
}

func (c *mockCtx) Initialize() error {
	return nil
}

func (c *mockCtx) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	return nil
}

func (c *mockCtx) Logout(sh pkcs11.SessionHandle) error {
	return nil
}

func (c *mockCtx) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	return sessionHandle, nil
}

func (c *mockCtx) SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return nil
}

func (c *mockCtx) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	return message, nil
}

func setup(t *testing.T, pubKey crypto.PublicKey) *Key {
	ps := Key{
		module:     &mockCtx{},
		tokenLabel: "token label",
		pin:        "unused",
		publicKey:  pubKey,
	}
	err := ps.setup()
	if err != nil {
		t.Fatalf("Failed to set up Key of type %T: %s", pubKey, err)
	}
	return &ps
}

var signInput = []byte("1234567890 1234567890 1234567890")

func sign(t *testing.T, ps *Key, opts crypto.SignerOpts) []byte {
	// Sign input must be exactly 32 bytes to match SHA256 size. In normally
	// usage, Sign would be called by e.g. x509.CreateCertificate, which would
	// handle padding to the necessary size.
	output, err := ps.Sign(rand.Reader, signInput, opts)
	if err != nil {
		t.Fatalf("Failed to sign: %s", err)
	}

	if len(output) < len(signInput) {
		t.Fatalf("Invalid signature size %d, expected at least %d", len(output), len(signInput))
	}

	i := len(output) - len(signInput)
	_, isECDSA := ps.Public().(*ecdsa.PublicKey)

	if !bytes.Equal(output[i:], signInput) && !isECDSA {
		t.Fatal("Incorrect sign output")
	}
	return output
}

func TestInitializeBadModule(t *testing.T) {
	ctx, err := initialize("/dev/null")
	if err == nil {
		t.Errorf("Expected failure when initializing modulePath /dev/null, got none")
	}
	if ctx != nil {
		t.Errorf("Expected nil ctx when initializing modulePath /dev/null")
	}
}

func TestInitializeKeyNotFound(t *testing.T) {
	pubKey := &rsa.PublicKey{N: big.NewInt(2), E: 2}
	ps := Key{
		module:     &mockCtx{},
		tokenLabel: "token label",
		pin:        "unused",
		publicKey:  pubKey,
	}
	err := ps.setup()
	expectedText := "looking up public key: no objects found"
	if err == nil {
		t.Errorf("Expected error looking up nonexistent key")
	} else if err.Error() != expectedText {
		t.Errorf("Expected error to contain %q, got %q", expectedText, err)
	}
}

func TestSignECDSA(t *testing.T) {
	ps := setup(t, ecKey)
	sig := sign(t, ps, crypto.SHA256)

	expected, err := ecdsaPKCS11ToRFC5480(signInput)
	if err != nil {
		t.Fatal(err)
	}

	if !(bytes.Equal(expected, sig)) {
		t.Fatal("ECDSA signature error")
	}
}

func TestSignPKCS1(t *testing.T) {
	ps := setup(t, rsaKey)
	sig := sign(t, ps, crypto.SHA256)

	// Check that the RSA signature starts with the SHA256 hash prefix
	var sha256Pre = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	if !(bytes.Equal(sha256Pre, sig[0:19])) {
		t.Fatal("RSA signature doesn't start with prefix")
	}

	pub := ps.Public()
	// Check public key is of right type
	_, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Attempted to get RSA key from Key, got key of type %s. Expected *rsa.PublicKey", reflect.TypeOf(pub))
	}
}

func TestSignPSS(t *testing.T) {
	opts := &rsa.PSSOptions{
		Hash:       crypto.SHA256,
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	}
	ps := setup(t, rsaKey)
	sig := sign(t, ps, opts)

	if !(bytes.Equal(signInput, sig)) {
		t.Fatal("ECDSA signature error")
	}
}

// This is a version of the mock that gives CKR_ATTRIBUTE_TYPE_INVALID when
// asked about the CKA_ALWAYS_AUTHENTICATE attribute.
type mockCtxFailsAlwaysAuthenticate struct {
	mockCtx
}

func (c *mockCtxFailsAlwaysAuthenticate) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	for _, a := range template {
		if a.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			return nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
		}
	}
	return c.mockCtx.GetAttributeValue(sh, o, template)
}

func TestAttributeTypeInvalid(t *testing.T) {
	ps := &Key{
		module:     &mockCtxFailsAlwaysAuthenticate{},
		tokenLabel: "token label",
		pin:        "unused",
		publicKey:  rsaKey,
	}
	err := ps.setup()
	if err != nil {
		t.Errorf("Failed to set up with a token that returns CKR_ATTRIBUTE_TYPE_INVALID: %s", err)
	}
}

func TestRSAPKCS1Params(t *testing.T) {
	mech, _, err := rsaPKCS1Mechanism(crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to set up mechanism for RSA-PSS: %s", err)
	}

	if mech[0].Mechanism != pkcs11.CKM_RSA_PKCS {
		t.Fatalf("Failed to set up mechanism for RSA-PKCS1v1.5, found CKM value mismatch (got: %d)", mech[0].Mechanism)
	}

	if mech[0].Parameter != nil {
		t.Fatalf("Failed to set up mechanism for RSA-PKCS1v1.5, found parameter value mismatch (got: %v)", mech[0].Parameter)
	}
}

func TestRSAPSSParams(t *testing.T) {
	mech, err := rsaPSSMechanism(crypto.SHA256, rsa.PSSSaltLengthEqualsHash)
	if err != nil {
		t.Fatalf("Failed to set up mechanism for RSA-PSS: %s", err)
	}

	if mech[0].Mechanism != pkcs11.CKM_RSA_PKCS_PSS {
		t.Fatalf("Failed to set up mechanism for RSA-PSS, found CKM value mismatch (got: %d)", mech[0].Mechanism)
	}

	// Make sure params has salt length 32, since we passed "equals hash" as the salt length
	expected := pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32)
	if !bytes.Equal(mech[0].Parameter, expected) {
		t.Fatalf("Failed to set up mechanism for RSA-PSS, found parameter value mismatch (got: %v)", mech[0].Parameter)
	}
}

func TestPKCS11ToRFC5480Signature(t *testing.T) {
	// Build a PKCS#11 signature with r = i and s = i +1, convert it
	// to RFC 5480 format and check that we got the expected values.
	roundtrip := func(i uint64) {
		pkcs11 := make([]byte, 16)
		rfc5480 := rfc5480ECDSASignature{}

		binary.BigEndian.PutUint64(pkcs11[:8], i)
		binary.BigEndian.PutUint64(pkcs11[8:], i+1)

		out, err := ecdsaPKCS11ToRFC5480(pkcs11)
		if err != nil {
			t.Fatal(err)
		}

		rest, err := asn1.Unmarshal(out, &rfc5480)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) != 0 {
			t.Fatalf("Conversion from PKCS11 signature to RFC5480 returned extra data? (%d bytes)", len(rest))
		}

		r := uint64(rfc5480.R.Int64())
		s := uint64(rfc5480.S.Int64())
		if r != i {
			t.Fatalf("Error converting PKCS11 signature to RFC5480, r value mismatch (expected: %d, got: %d)", i, r)
		}
		if s != i+1 {
			t.Fatalf("Error converting PKCS11 signature to RFC5480, s value mismatch (expected: %d, got: %d)", (i + 1), s)
		}
	}

	for i := uint64(0); i < ((1 << 16) - 1); i++ {
		roundtrip(i)
		roundtrip(math.MaxUint64 - i - 1)
	}
}
