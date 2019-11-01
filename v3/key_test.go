package pkcs11key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/miekg/pkcs11"
)

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

// A fake EC public key for use in testing. See RSA above.
var ecKey = &ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1), Curve: elliptic.P256()}

const ecPrivateKeyHandle = pkcs11.ObjectHandle(32)
const ecPublicKeyHandle = pkcs11.ObjectHandle(33)
const ecKeyID = byte(0x03)

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
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []uint8{0x4, 0x41, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}),
	}) {
		return []pkcs11.ObjectHandle{ecPublicKeyHandle}, false, nil
	}
	if reflect.DeepEqual(c.currentSearch, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{ecKeyID}),
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

var ecOid = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

var ecPoint = []byte{0x04, 0x41, 0x04, 0x4C, 0xD7, 0x7B, 0x7B, 0x2E,
	0x3D, 0x57, 0x98, 0xB8, 0x2F, 0x99, 0xB4, 0x83,
	0x99, 0xE6, 0xD4, 0x4C, 0x4F, 0xBC, 0x2D, 0x60,
	0xCD, 0x08, 0x8E, 0x93, 0x65, 0x6F, 0x20, 0x51,
	0x1C, 0xE7, 0xFD, 0x59, 0x34, 0xAA, 0xA9, 0x36,
	0x26, 0xCE, 0x4A, 0xC5, 0xA2, 0x4A, 0x85, 0x6C,
	0xB3, 0x95, 0xFF, 0x92, 0x0F, 0x56, 0x76, 0x34,
	0x1F, 0x69, 0x52, 0x5F, 0x20, 0x83, 0x13, 0x50,
	0xA3, 0xDE, 0xBE}

func ecPublicKeyAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		switch a.Type {
		case pkcs11.CKA_ID:
			output = append(output, p11Attribute(a.Type, []byte{byte(ecKeyID)}))
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
	if !bytes.Equal(output[i:], signInput) {
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

	if !(bytes.Equal(signInput, sig)) {
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
