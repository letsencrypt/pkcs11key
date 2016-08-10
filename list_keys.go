package pkcs11key

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/miekg/pkcs11"
)

type KeyInfo struct {
	TokenLabel string
	KeyID      []byte
	KeyLabel   string
	PublicKey  crypto.PublicKey
}

func ListKeys(modulePath string) ([]*KeyInfo, error) {
	module, err := initialize(modulePath)
	if err != nil {
		return nil, err
	}
	if module == nil {
		return nil, fmt.Errorf("pkcs11: nil module")
	}

	slots, err := module.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	var res []*KeyInfo

	for _, slot := range slots {
		tokenInfo, err := module.GetTokenInfo(slot)
		if err != nil {
			return nil, err
		}

		// Open session
		session, err := module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return nil, err
		}
		defer module.CloseSession(session)

		// List all private keys
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		}
		if err := module.FindObjectsInit(session, template); err != nil {
			return nil, err
		}
		keyHandles, _, err := module.FindObjects(session, 1024)
		if err != nil {
			return nil, err
		}
		if err = module.FindObjectsFinal(session); err != nil {
			return nil, err
		}

		// Some devices like the Yubikey 4 don't allow listing private keys, but list certificates instead
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		}
		if err := module.FindObjectsInit(session, template); err != nil {
			return nil, err
		}
		certHandles, _, err := module.FindObjects(session, 1024)
		if err != nil {
			return nil, err
		}
		if err = module.FindObjectsFinal(session); err != nil {
			return nil, err
		}
		for _, certHandle := range certHandles {
			idAttr, err := module.GetAttributeValue(session, certHandle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if len(idAttr) == 0 {
				return nil, fmt.Errorf("pkcs11: certificate %d is missing id attribute", certHandle)
			}
			keyTemplate := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_ID, idAttr[0].Value),
			}
			if err := module.FindObjectsInit(session, keyTemplate); err != nil {
				return nil, err
			}
			certKey, _, err := module.FindObjects(session, 1)
			if err != nil {
				return nil, err
			}
			if err = module.FindObjectsFinal(session); err != nil {
				return nil, err
			}
			keyHandles = append(keyHandles, certKey...)
		}

		for _, keyHandle := range keyHandles {
			info := KeyInfo{
				TokenLabel: tokenInfo.Label,
			}

			// Get public key
			keyType, err := getKeyType(module, session, keyHandle)
			if err != nil {
				return nil, err
			}
			switch keyType {
			case pkcs11.CKK_RSA:
				info.PublicKey, err = getRSAPublicKey(module, session, keyHandle)
			case pkcs11.CKK_EC:
				info.PublicKey, err = getECPublicKey(module, session, keyHandle)
			default:
				// skip keys that are not RSA or EC
				continue
			}
			if err != nil {
				return nil, err
			}

			// Get key ID and Label
			attrs, err := module.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil {
				return nil, err
			}

			for _, a := range attrs {
				switch a.Type {
				case pkcs11.CKA_LABEL:
					info.KeyLabel = string(bytes.TrimRight(a.Value, "\x00"))
				case pkcs11.CKA_ID:
					info.KeyID = a.Value
				}
			}

			// Skip the key if we already have one with the same ID or label from this token
			for _, k := range res {
				if k.TokenLabel == info.TokenLabel &&
					((len(info.KeyID) > 0 && bytes.Equal(k.KeyID, info.KeyID)) || k.KeyLabel == info.KeyLabel) {
					continue
				}
			}

			res = append(res, &info)
		}
	}

	return res, nil
}
