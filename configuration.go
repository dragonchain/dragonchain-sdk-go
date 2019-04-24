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
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/go-ini/ini"
)

var (
	// ConfigFilePath points to the location of the Configuration file
	// Default on windows '%LOCALAPPDATA%\dragonchain\credentials'
	// Default on linux '$HOME/.dragonchain/credentials'
	// This may be overridden before creating Credentials
	ConfigFilePath = ""

	configs *Configuration
)

var (
	// ErrNoConfigurationFileFound is returned if no config was found in ConfigFilePath.
	ErrNoConfigurationFileFound = errors.New("no Configuration file found")
)

func init() {
	if runtime.GOOS == "windows" {
		ConfigFilePath = filepath.Join(os.ExpandEnv("${LOCALAPPDATA}"), "dragonchain", "credentials")
	} else {
		ConfigFilePath = filepath.Join(os.ExpandEnv("${HOME}"), ".dragonchain", "credentials")
	}
}

// AuthKey defines the structure of the chain's HMAC authorization keys.
type AuthKey struct {
	AuthKey   string
	AuthKeyID string
}

// Configuration defines the SDK configuration of chainID and AuthKeys.
type Configuration struct {
	DefaultDcID string
	AuthKeys    map[string]*AuthKey
}

// GetCredentialConfigs returns
func GetCredentialConfigs() (*Configuration, error) {
	if configs != nil {
		return configs, nil
	}

	configBytes, err := getConfigFile()
	if err != nil {
		return nil, err
	} else if configBytes == nil {
		return nil, ErrNoConfigurationFileFound
	}

	cfg, err := ini.Load(configBytes)
	if err != nil {
		return nil, err
	}

	dcID := cfg.Section("default").Key("dragonchain_id").String()

	configs = &Configuration{
		DefaultDcID: dcID,
		AuthKeys:    make(map[string]*AuthKey),
	}

	for _, section := range cfg.Sections() {
		if isValidUUID4(section.Name()) {
			configs.AuthKeys[section.Name()] = &AuthKey{
				AuthKey:   cfg.Section(section.Name()).Key("auth_key").String(),
				AuthKeyID: cfg.Section(section.Name()).Key("auth_key_id").String(),
			}
		}
	}

	return configs, nil
}

func getConfigFile() ([]byte, error) {
	if _, err := os.Stat(ConfigFilePath); err == nil {
		configBytes, err := ioutil.ReadFile(ConfigFilePath)
		if err != nil {
			return nil, err
		}
		return configBytes, nil
	} else if os.IsNotExist(err) {
		return nil, nil
	} else {
		return nil, err
	}
}

func isValidUUID4(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}
