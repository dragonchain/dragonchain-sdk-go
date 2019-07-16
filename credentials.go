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
	"hash"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// ErrUnsupportedHashAlgo is thrown when an unsupported hash method is provided.
var ErrUnsupportedHashAlgo = errors.New("hash method not supported")

// ErrNoCredentials is thrown if no credentials file can be found.
var ErrNoCredentials = errors.New("no credentials found")

// Supported hash functions
const (
	HashSHA256     = "SHA256"
	HashSHA3256    = "SHA3-256"
	HashBLAKE2b512 = "BLAKE2b512"
)

// Environment variables used to get chainID and Keys. These can be overridden before calling NewCredentials.
var (
	EnvDcIDName  = "DRAGONCHAIN_ID"
	EnvKeyName   = "AUTH_KEY"
	EnvKeyIDName = "AUTH_KEY_ID"
)

// Authenticator generates the authentication header for requests to chain.
type Authenticator interface {
	GetDragonchainID() string
	GetAuthorization(httpVerb, path string, timestamp, contentType string, content []byte) string
}

// Credentials implements the Authenticator interface to generate authentication headers.
type Credentials struct {
	dcID      string
	authKey   string
	authKeyID string
	algorithm string
	hashFunc  func() hash.Hash
}

// NewCredentials uses the provided values to create a new Credentials instance for the given chain.
func NewCredentials(dcID, authKey, authKeyID, algorithm string) (*Credentials, error) {
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
		return nil, ErrUnsupportedHashAlgo
	}

	if len(dcID) == 0 {
		if dcID, err = getDragonchainID(); err != nil {
			return nil, err
		}
	}
	if len(authKey) == 0 {
		if authKey, err = getAuthKey(dcID); err != nil {
			return nil, err
		}
	}
	if len(authKeyID) == 0 {
		if authKeyID, err = getAuthKeyID(dcID); err != nil {
			return nil, err
		}
	}

	// If dcID, authKey, or authKeyID are empty, we must return an error
	if len(dcID) == 0 || len(authKey) == 0 || len(authKeyID) == 0 {
		return nil, ErrNoCredentials
	}

	return &Credentials{
		dcID:      dcID,
		authKey:   authKey,
		authKeyID: authKeyID,
		algorithm: algorithm,
		hashFunc:  hashFunc,
	}, nil
}

func getDragonchainID() (string, error) {
	dcID := os.Getenv(EnvDcIDName)
	if len(dcID) > 0 {
		return dcID, nil
	}

	configs, err := GetCredentialConfigs()
	if err == ErrNoConfigurationFileFound {
		return "", nil
	} else if err != nil {
		return "", err
	}

	return configs.DefaultDcID, nil
}

func getAuthKey(dcID string) (string, error) {
	authKey := os.Getenv(EnvKeyName)
	if len(authKey) > 0 {
		return authKey, nil
	}

	configs, err := GetCredentialConfigs()
	if err == ErrNoConfigurationFileFound {
		return "", nil
	} else if err != nil {
		return "", err
	}
	key, ok := configs.AuthKeys[dcID]
	if !ok {
		return "", nil
	}
	return key.AuthKey, nil
}

func getAuthKeyID(ID string) (string, error) {
	authKeyID := os.Getenv(EnvKeyIDName)
	if len(authKeyID) > 0 {
		return authKeyID, nil
	}

	configs, err := GetCredentialConfigs()
	if err == ErrNoConfigurationFileFound {
		return "", nil
	} else if err != nil {
		return "", err
	}
	key, ok := configs.AuthKeys[ID]
	if !ok {
		return "", nil
	}
	return key.AuthKeyID, nil
}

func (creds *Credentials) hmacMessage(httpVerb, path string, timestamp, contentType string, content []byte) string {
	h := creds.hashFunc()

	h.Write([]byte(content))
	hashContent := h.Sum(nil)
	b64Content := base64.StdEncoding.EncodeToString(hashContent)

	msg := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		strings.ToUpper(httpVerb),
		path,
		creds.dcID,
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

// GetDragonchainID returns the current chain's ID.
func (creds *Credentials) GetDragonchainID() string {
	return creds.dcID
}

// GetAuthorization returns the current chain's authorization as a string.
func (creds *Credentials) GetAuthorization(httpVerb, path string, timestamp, contentType string, content []byte) string {
	msgStr := creds.hmacMessage(httpVerb, path, timestamp, contentType, content)
	hmacMsg := creds.createHmac(creds.authKey, msgStr)
	b64hmac := base64.StdEncoding.EncodeToString(hmacMsg)
	return fmt.Sprintf("DC1-HMAC-%s %s:%s", creds.algorithm, creds.authKeyID, b64hmac)
}
