package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/awnumar/memguard"
	bls "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/crypto"
	logging "github.com/ipfs/go-log/v2"
	"github.com/pkg/errors"
)

const (
	stBLS       = "bls"
	stSecp256k1 = "secp256k1"
)

var log = logging.Logger("keyinfo")

func init() {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
}

// KeyInfo is a key and its type used for signing.
type KeyInfo struct {
	// Private key.
	PrivateKey *memguard.Enclave `json:"privateKey"`
	// Cryptographic system used to generate private key.
	SigType SigType `json:"type"`
}

type keyInfo struct {
	// Private key.
	PrivateKey []byte `json:"privateKey"`
	// Cryptographic system used to generate private key.
	SigType interface{} `json:"type"`
}

func (ki *KeyInfo) UnmarshalJSON(data []byte) error {
	k := keyInfo{}
	err := json.Unmarshal(data, &k)
	if err != nil {
		return err
	}

	switch k.SigType.(type) {
	case string:
		st := k.SigType.(string)
		if st == stBLS {
			ki.SigType = crypto.SigTypeBLS
		} else if st == stSecp256k1 {
			ki.SigType = crypto.SigTypeSecp256k1
		} else {
			return fmt.Errorf("unknown sig type value: %s", st)
		}
	case byte:
		ki.SigType = crypto.SigType(k.SigType.(byte))
	case float64:
		ki.SigType = crypto.SigType(k.SigType.(float64))
	case int:
		ki.SigType = crypto.SigType(k.SigType.(int))
	case int64:
		ki.SigType = crypto.SigType(k.SigType.(int64))
	default:
		return fmt.Errorf("unknown sig type: %T", k.SigType)
	}
	ki.SetPrivateKey(k.PrivateKey)

	return nil
}

func (ki KeyInfo) MarshalJSON() ([]byte, error) {
	var err error
	k := keyInfo{}
	k.PrivateKey, err = ki.privateKey()
	if err != nil {
		return nil, err
	}
	if ki.SigType == crypto.SigTypeBLS {
		k.SigType = stBLS
	} else if ki.SigType == crypto.SigTypeSecp256k1 {
		k.SigType = stSecp256k1
	} else {
		return nil, fmt.Errorf("unsupport keystore types  %T", k.SigType)
	}
	return json.Marshal(k)
}

// Key returns the private key of KeyInfo
func (ki *KeyInfo) Key() []byte {
	pk, err := ki.privateKey()
	if err != nil {
		log.Errorf("got private key failed %v", err)
		return []byte{}
	}
	return pk
}

// Type returns the type of curve used to generate the private key
func (ki *KeyInfo) Type() SigType {
	return ki.SigType
}

// Equals returns true if the KeyInfo is equal to other.
func (ki *KeyInfo) Equals(other *KeyInfo) bool {
	if ki == nil && other == nil {
		return true
	}
	if ki == nil || other == nil {
		return false
	}
	if ki.SigType != other.SigType {
		return false
	}

	pk, err := ki.PrivateKey.Open()
	if err != nil {
		return false
	}
	defer pk.Destroy()

	otherPK, err := other.PrivateKey.Open()
	if err != nil {
		return false
	}
	defer otherPK.Destroy()

	return bytes.Equal(pk.Bytes(), otherPK.Bytes())
}

// Address returns the address for this keyinfo
func (ki *KeyInfo) Address() (address.Address, error) {
	pubKey, err := ki.PublicKey()
	if err != nil {
		return address.Undef, err
	}
	if ki.SigType == SigTypeBLS {
		return address.NewBLSAddress(pubKey)
	}
	if ki.SigType == SigTypeSecp256k1 {
		return address.NewSecp256k1Address(pubKey)
	}
	return address.Undef, errors.Errorf("can not generate address for unknown crypto system: %d", ki.SigType)
}

// Returns the public key part as uncompressed bytes.
func (ki *KeyInfo) PublicKey() ([]byte, error) {
	pk, err := ki.privateKey()
	if err != nil {
		return []byte{}, err
	}
	if ki.SigType == SigTypeBLS {
		var blsPrivateKey bls.PrivateKey
		copy(blsPrivateKey[:], pk)
		publicKey := bls.PrivateKeyPublicKey(blsPrivateKey)

		return publicKey[:], nil
	}
	if ki.SigType == SigTypeSecp256k1 {
		return PublicKeyForSecpSecretKey(pk), nil
	}
	return []byte{}, nil
}

func (ki *KeyInfo) privateKey() ([]byte, error) {
	buf, err := ki.PrivateKey.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()
	newBuf := make([]byte, buf.Size())
	copy(newBuf, buf.Bytes())

	return newBuf, nil
}

func (ki *KeyInfo) SetPrivateKey(privateKey []byte) {
	// will wipes privateKey with zeroes
	ki.PrivateKey = memguard.NewEnclave(privateKey)
}
