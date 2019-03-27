// Copyright 2019 Dragonchain, Inc. or its affiliates. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dragonchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"hash"
	"os"
	"strings"
)

var (
	// Returned if an unsupported hash algorithm was given
	UnSupportedHashMethodError = errors.New("hash method not supported")

	// Returned if no credentials where given and none could be found in the
	// system environmental variables or a Configuration file.
	NoCredentialsFoundError = errors.New("no credentials found")
)

// Supported hash functions
const (
	HashSHA256     = "SHA256"
	HashSHA3256    = "SHA3-256"
	HashBLAKE2b512 = "BLAKE2b512"
)

// Environmental variable names used to get the Dragonchain ID and Keys from the
// system environmental variables. These can be overridden before calling NewCredentials
var (
	EnvDcIdName  = "DRAGONCHAIN_ID"
	EnvKeyName   = "AUTH_KEY"
	EnvKeyIdName = "AUTH_KEY_ID"
)

// Interface used by the dragonchain client for generating the Authentication header
type Authenticator interface {
	GetDragonchainId() string
	GetAuthorization(httpVerb, path string, timestamp, contentType, content string) string
}

// Credentials implements the Authenticator interface and generates a hmac Authentication
// headers using the supported hashing algorithms SHA257, SH3-256, or BLAKE2b512
type Credentials struct {
	dcId      string
	authKey   string
	authKeyId string
	algorithm string
	hashFunc  func() hash.Hash
}

func NewCredentials(dcId, authKey, authKeyId, algorithm string) (*Credentials, error) {
	var err error
	var hashFunc func() hash.Hash

	switch algorithm {
	case "":
		// If no hash algorithm is given, we default to SHA256
		algorithm = HashSHA256
		fallthrough
	case HashSHA256:
		hashFunc = sha256.New
	case HashSHA3256:
		hashFunc = sha3.New256
	case HashBLAKE2b512:
		// blake2b does not implement 'func() hash.Hash' that is excepted from hmac.New
		// therefore we must create the following function to generate the correct func interface
		// blake2b.New512 only returns an error if an incorrect hash size is given. blake2b.New512
		// uses a hard coded hash size so a error is never returned and we can safely ignore it.
		// https://github.com/golang/go/issues/21644
		hashFunc = func() hash.Hash {
			h, _ := blake2b.New512(nil)
			return h
		}
	default:
		return nil, UnSupportedHashMethodError
	}

	if len(dcId) == 0 {
		if dcId, err = getDragonchainId(); err != nil {
			return nil, err
		}
	}
	if len(authKey) == 0 {
		if authKey, err = getAuthKey(dcId); err != nil {
			return nil, err
		}
	}
	if len(authKeyId) == 0 {
		if authKeyId, err = getAuthKeyId(dcId); err != nil {
			return nil, err
		}
	}

	// If dcId, authKey, or authKeyId are empty, we must return an error
	if len(dcId) == 0 || len(authKey) == 0 || len(authKeyId) == 0 {
		return nil, NoCredentialsFoundError
	}

	return &Credentials{
		dcId:      dcId,
		authKey:   authKey,
		authKeyId: authKeyId,
		algorithm: algorithm,
		hashFunc:  hashFunc,
	}, nil
}

func getDragonchainId() (string, error) {
	dcId := os.Getenv(EnvDcIdName)
	if len(dcId) > 0 {
		return dcId, nil
	}

	configs, err := GetCredentialConfigs()
	if err == NoConfigurationFileFoundError {
		return "", nil
	} else if err != nil {
		return "", err
	}

	return configs.DefaultDcId, nil
}

func getAuthKey(dcId string) (string, error) {
	authKey := os.Getenv(EnvKeyName)
	if len(authKey) > 0 {
		return authKey, nil
	}

	configs, err := GetCredentialConfigs()
	if err == NoConfigurationFileFoundError {
		return "", nil
	} else if err != nil {
		return "", err
	}

	if key, ok := configs.AuthKeys[dcId]; !ok {
		return "", nil
	} else {
		return key.AuthKey, nil
	}
}

func getAuthKeyId(dcId string) (string, error) {
	authKeyId := os.Getenv(EnvKeyIdName)
	if len(authKeyId) > 0 {
		return authKeyId, nil
	}

	configs, err := GetCredentialConfigs()
	if err == NoConfigurationFileFoundError {
		return "", nil
	} else if err != nil {
		return "", err
	}

	if key, ok := configs.AuthKeys[dcId]; !ok {
		return "", nil
	} else {
		return key.AuthKeyId, nil
	}
}

func (creds *Credentials) hmacMessage(httpVerb, path string, timestamp, contentType, content string) string {
	h := creds.hashFunc()

	h.Write([]byte(content))
	hashContent := h.Sum(nil)
	b64Content := base64.StdEncoding.EncodeToString(hashContent)

	msg := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		strings.ToUpper(httpVerb),
		path,
		creds.dcId,
		timestamp,
		contentType,
		b64Content,
	)

	return msg
}

func (creds *Credentials) createHmac(secret, message string) []byte {
	h := hmac.New(creds.hashFunc, []byte(secret))
	h.Write([]byte(message))
	return h.Sum(nil)
}

func (creds *Credentials) CompareHmac(hmacBytes []byte, secret, message string) bool {
	return hmac.Equal(hmacBytes, creds.createHmac(secret, message))
}

func (creds *Credentials) GetDragonchainId() string {
	return creds.dcId
}

func (creds *Credentials) GetAuthorization(httpVerb, path string, timestamp, contentType, content string) string {
	msgStr := creds.hmacMessage(httpVerb, path, timestamp, contentType, content)
	hmacMsg := creds.createHmac(creds.authKey, msgStr)
	b64hmac := base64.StdEncoding.EncodeToString(hmacMsg)
	return fmt.Sprintf("DC1-HMAC-%s %s:%s", creds.algorithm, creds.authKeyId, b64hmac)
}
