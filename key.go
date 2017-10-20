// Package pkcs11key implements crypto.Signer for PKCS #11 private keys.
// See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-30/pkcs-11v2-30b-d6.pdf for
// details of the Cryptoki PKCS#11 API.
package pkcs11key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// from src/pkg/crypto/rsa/pkcs1v15.go
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// from src/pkg/crypto/x509/x509.go
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var curveOIDs = map[string]asn1.ObjectIdentifier{
	"P-224": oidNamedCurveP224,
	"P-256": oidNamedCurveP256,
	"P-384": oidNamedCurveP384,
	"P-521": oidNamedCurveP521,
}

var appMu sync.Mutex

// Key is an implementation of the crypto.Signer interface using a key stored
// in a PKCS#11 hardware token.  This enables the use of PKCS#11 tokens with
// the Go x509 library's methods for signing certificates.
//
// Each Key represents one session. Its session handle is protected internally
// by a mutex, so at most one Sign operation can be active at a time. For best
// performance you may want to instantiate multiple Keys using pkcs11key.Pool.
// Each one will have its own session and can be used concurrently. Note that
// some smartcards like the Yubikey Neo do not support multiple simultaneous
// sessions and will error out on creation of the second Key object.
//
// Note: If you instantiate multiple Keys without using Pool, it is *highly*
// recommended that you create all your Key objects serially, on your main
// thread, checking for errors each time, and then farm them out for use by
// different goroutines. If you fail to do this, your application may attempt
// to login repeatedly with an incorrect PIN, locking the PKCS#11 token.
type Key struct {
	// The PKCS#11 library to use
	module p11.Module

	// The label of the token to be used (mandatory).
	// We will automatically search for this in the slot list.
	tokenLabel string

	// The PIN to be used to log in to the device
	pin string

	// The public key corresponding to the private key.
	publicKey crypto.PublicKey

	// An handle representing the private key on the HSM.
	privateKey p11.PrivateKey

	// A handle to the session used by this Key.
	session p11.Session

	// True if the private key has the CKA_ALWAYS_AUTHENTICATE attribute set.
	alwaysAuthenticate bool
}

// New instantiates a new handle to a PKCS #11-backed key.
func New(modulePath, tokenLabel, pin string, publicKey crypto.PublicKey) (*Key, error) {
	module, err := p11.OpenModule(modulePath)
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: %s", err)
	}

	// Initialize a partial key
	ps := &Key{
		module:     module,
		tokenLabel: tokenLabel,
		pin:        pin,
		publicKey:  publicKey,
	}

	err = ps.setup()
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: %s", err)
	}
	return ps, nil
}

func templateFromRSAPublic(key *rsa.PublicKey) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
	}
}

func templateFromECDSAPublic(key *ecdsa.PublicKey) ([]*pkcs11.Attribute, error) {
	// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
	// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be store in a DER-encoded
	// OCTET STRING.
	rawValue := asn1.RawValue{
		Tag:   4, // in Go 1.6+ this is asn1.TagOctetString
		Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
	}
	marshalledPoint, err := asn1.Marshal(rawValue)
	if err != nil {
		return nil, err
	}
	curveOID, err := asn1.Marshal(curveOIDs[key.Curve.Params().Name])
	if err != nil {
		return nil, err
	}
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curveOID),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, marshalledPoint),
	}, nil
}

// getPublicKeyID looks up the given public key in the PKCS#11 token, and
// returns its ID as a []byte, for use in looking up the corresponding private
// key.
func (ps *Key) getPublicKeyID(publicKey crypto.PublicKey) ([]byte, error) {
	var template []*pkcs11.Attribute
	var err error
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		template = templateFromRSAPublic(key)
	case *ecdsa.PublicKey:
		template, err = templateFromECDSAPublic(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported public key of type %T", publicKey)
	}

	p11PK, err := ps.session.FindObject(template)
	if err != nil {
		return nil, err
	}

	pkID, err := p11PK.Attribute(pkcs11.CKA_ID)
	if err != nil {
		return nil, err
	}
	return pkID, nil
}

func (ps *Key) setup() error {
	// Open a session
	session, err := ps.openSession()
	if err != nil {
		return fmt.Errorf("pkcs11key: opening session: %s", err)
	}
	ps.session = session

	publicKeyID, err := ps.getPublicKeyID(ps.publicKey)
	if err != nil {
		ps.session.Close()
		return fmt.Errorf("looking up public key: %s", err)
	}

	// Fetch the private key by matching its id to the public key handle.
	privateKeyObject, err := ps.getPrivateKey(publicKeyID)
	if err != nil {
		ps.session.Close()
		return fmt.Errorf("getting private key: %s", err)
	}
	ps.privateKey = p11.PrivateKey(privateKeyObject)
	return nil
}

// getPrivateKey gets a handle to the private key whose CKA_ID matches the
// provided publicKeyID.
func (ps *Key) getPrivateKey(publicKeyID []byte) (p11.Object, error) {
	privateKey, err := ps.session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publicKeyID),
	})
	if err != nil {
		return p11.Object{}, err
	}

	// Check whether the key has the CKA_ALWAYS_AUTHENTICATE attribute.
	// If so, set the ps.alwaysAuthenticate bit so we know to Login again after
	// each private key operation.
	alwaysAuthenticate, err := privateKey.Attribute(pkcs11.CKA_ALWAYS_AUTHENTICATE)
	if err != nil {
		return p11.Object{}, err
	}
	if len(alwaysAuthenticate) > 0 && alwaysAuthenticate[0] == 1 {
		ps.alwaysAuthenticate = true
	}

	return privateKey, nil
}

// Destroy tears down a Key by closing the session. It should be
// called before the key gets GC'ed, to avoid leaving dangling sessions.
func (ps *Key) Destroy() error {
	if ps.session != nil {
		// NOTE: We do not want to call module.Logout here. module.Logout applies
		// application-wide. So if there are multiple sessions active, the other ones
		// would be logged out as well, causing CKR_OBJECT_HANDLE_INVALID next
		// time they try to sign something. It's also unnecessary to log out explicitly:
		// module.CloseSession will log out once the last session in the application is
		// closed.
		err := ps.session.Close()
		ps.session = nil
		if err != nil {
			return fmt.Errorf("pkcs11key: close session: %s", err)
		}
	}
	return nil
}

func (ps *Key) openSession() (p11.Session, error) {
	slots, err := ps.module.Slots()
	if err != nil {
		return nil, err
	}

	for _, slot := range slots {
		tokenInfo, err := slot.TokenInfo()
		if err != nil {
			return nil, err
		}
		if tokenInfo.Label != ps.tokenLabel {
			continue
		}

		session, err := slot.OpenSession()
		if err != nil {
			return nil, err
		}

		// Login
		// Note: Logged-in status is application-wide, not per session. But in
		// practice it appears to be okay to login to a token multiple times with the same
		// credentials.
		if err = session.Login(p11.RegularUser, ps.pin); err != nil {
			if err == pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				// But if the token says we're already logged in, it's ok.
				err = nil
			} else {
				session.Close()
				return nil, err
			}
		}

		return session, err
	}
	return nil, fmt.Errorf("no slot found matching token label %q", ps.tokenLabel)
}

// Public returns the public key for the PKCS #11 key.
func (ps *Key) Public() crypto.PublicKey {
	return ps.publicKey
}

// Sign performs a signature using the PKCS #11 key.
func (ps *Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if ps.session == nil {
		return nil, errors.New("pkcs11key: session was nil")
	}

	// When the alwaysAuthenticate bit is true (e.g. on a Yubikey NEO in PIV mode),
	// each Sign has to include a Logout/Login, or the next Sign request will get
	// CKR_USER_NOT_LOGGED_IN. This is very slow, but on the NEO it's not possible
	// to clear the CKA_ALWAYS_AUTHENTICATE bit, so this is the only available
	// workaround.
	// Also, since logged in / logged out is application state rather than session
	// state, we take a global lock while we do the logout and login, and during
	// the signing.
	if ps.alwaysAuthenticate {
		appMu.Lock()
		defer appMu.Unlock()
		if err := ps.session.Logout(); err != nil {
			return nil, fmt.Errorf("pkcs11key: logout: %s", err)
		}
		if err := ps.session.Login(p11.RegularUser, ps.pin); err != nil {
			return nil, fmt.Errorf("pkcs11key: login: %s", err)
		}
	}

	// Verify that the length of the hash is as expected
	hash := opts.HashFunc()
	hashLen := hash.Size()
	if len(msg) != hashLen {
		return nil, fmt.Errorf(
			"pkcs11key: input size does not match hash function output size: %d vs %d",
			len(msg), hashLen)
	}

	// Add DigestInfo prefix
	var mechanism *pkcs11.Mechanism
	var signatureInput []byte

	switch ps.publicKey.(type) {
	case *rsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		prefix, ok := hashPrefixes[hash]
		if !ok {
			return nil, errors.New("pkcs11key: unknown hash function")
		}
		signatureInput = append(prefix, msg...)
	case *ecdsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
		signatureInput = msg
	default:
		return nil, fmt.Errorf("unrecognized key type %T", ps.publicKey)
	}

	return ps.privateKey.Sign(*mechanism, signatureInput)
}
