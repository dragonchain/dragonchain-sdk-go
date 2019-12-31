// Copyright 2020 Dragonchain, Inc. or its affiliates. All Rights Reserved.
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

// ContractConfiguration defines the structure of a request to create a new smart contract.
type ContractConfiguration struct {
	TransactionType           string                 `json:"txn_type"`
	Image                     string                 `json:"image"`
	Cmd                       string                 `json:"cmd"`
	Args                      []string               `json:"args"`
	ExecutionOrder            string                 `json:"execution_order"`
	Enabled                   bool                   `json:"enabled"`
	EnvironmentVariables      []string               `json:"env"`
	Secrets                   map[string]interface{} `json:"secrets"`
	ScheduleIntervalInSeconds int                    `json:"seconds"`
	CronExpression            string                 `json:"cron"`
	RegistryCredentials       string                 `json:"auth"`
}

// Contract defines the structure of a deployed smart contract.
type Contract struct {
	TransactionType string                 `json:"txn_type"`
	ContractID      string                 `json:"id"`
	Status          ContractStatus         `json:"status"`
	Image           string                 `json:"image"`
	AuthKeyID       string                 `json:"auth_key_id"`
	ImageDigest     string                 `json:"image_digest"`
	Cmd             string                 `json:"cmd"`
	Args            []string               `json:"args"`
	Env             map[string]interface{} `json:"env"`
	ExistingSecrets []string               `json:"existing_secrets"`
	Cron            string                 `json:"cron"`
	Seconds         string                 `json:"seconds"`
	ExecutionOrder  string                 `json:"execution_order"`
}

// ContractStatus defines the status object for contracts.
type ContractStatus struct {
	State     string `json:"state"`
	Msg       string `json:"msg"`
	Timestamp string `json:"timestamp"`
}
