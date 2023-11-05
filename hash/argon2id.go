package hash

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	errInvalidHash         = errors.New("argon2id: hash is not in the correct format")
	errIncompatibleVariant = errors.New("argon2id: incompatible variant of argon2")
	errIncompatibleVersion = errors.New("argon2id: incompatible version of argon2")
)

type Params struct {
	Time        uint32
	Memory      uint32
	KeyLength   uint32
	Parallelism uint8
}

type Argon2ID struct {
	Version int
	Format  string
	Params  Params
}

func NewArgon2ID(params Params) *Argon2ID {
	return &Argon2ID{
		Format:  "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Version: argon2.Version,
		Params:  params,
	}
}

func (h Argon2ID) Hash(plain, salt string) (hash string, err error) {
	key := argon2.IDKey([]byte(plain), []byte(salt), h.Params.Time, h.Params.Memory, h.Params.Parallelism, h.Params.KeyLength)

	saltKey := base64.RawStdEncoding.EncodeToString([]byte(salt))
	hashKey := base64.RawStdEncoding.EncodeToString(key)

	hash = fmt.Sprintf(h.Format, h.Version, h.Params.Memory, h.Params.Time, h.Params.Parallelism, saltKey, hashKey)
	return
}

func (h Argon2ID) Verify(plain, hash string) (match bool, err error) {
	salt, key, err := h.DecodeHash(hash)
	if err != nil {
		return
	}

	rebuildHash := argon2.IDKey([]byte(plain), []byte(salt), h.Params.Time, h.Params.Memory, h.Params.Parallelism, h.Params.KeyLength)

	if subtle.ConstantTimeCompare(key, rebuildHash) == 1 {
		match = true

		return
	}

	return
}

func (h Argon2ID) DecodeHash(hash string) (salt, key []byte, err error) {
	vals := strings.Split(hash, "$")

	if len(vals) != 6 {
		return nil, nil, errInvalidHash
	}

	if vals[1] != "argon2id" {
		return nil, nil, errIncompatibleVariant
	}

	var version int

	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, errIncompatibleVersion
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, err
	}

	key, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, err
	}

	return salt, key, nil
}
