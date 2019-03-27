package dragonchain

import (
	"errors"
	"github.com/go-ini/ini"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
	// Returned if no Configuration file was found in the ConfigFilePath path
	NoConfigurationFileFoundError = errors.New("no Configuration file found")
)

func init() {
	if runtime.GOOS == "windows" {
		ConfigFilePath = filepath.Join(os.ExpandEnv("${LOCALAPPDATA}"), "dragonchain", "credentials")
	} else {
		ConfigFilePath = filepath.Join(os.ExpandEnv("${HOME}"), ".dragonchain", "credentials")
	}
}

type AuthKey struct {
	AuthKey   string
	AuthKeyId string
}

type Configuration struct {
	DefaultDcId string
	AuthKeys    map[string]*AuthKey
}

func GetCredentialConfigs() (*Configuration, error) {
	if configs != nil {
		return configs, nil
	}

	configBytes, err := getConfigFile()
	if err != nil {
		return nil, err
	} else if configBytes == nil {
		return nil, NoConfigurationFileFoundError
	}

	cfg, err := ini.Load(configBytes)
	if err != nil {
		return nil, err
	}

	dcId := cfg.Section("default").Key("dragonchain_id").String()

	configs = &Configuration{
		DefaultDcId: dcId,
		AuthKeys:    make(map[string]*AuthKey),
	}

	for _, section := range cfg.Sections() {
		if isValidUUID4(section.Name()) {
			configs.AuthKeys[section.Name()] = &AuthKey{
				AuthKey:   cfg.Section(section.Name()).Key("auth_key").String(),
				AuthKeyId: cfg.Section(section.Name()).Key("auth_key_id").String(),
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
