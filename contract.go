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

// ContractConfiguration defines the structure of a request to create a new smart contract.
type ContractConfiguration struct {
	TxnType        string                 `json:"txn_type"`
	ExecutionOrder string                 `json:"execution_order"`
	Image          string                 `json:"image"`
	Cmd            string                 `json:"cmd"`
	Args           []string               `json:"args"`
	Env            []string               `json:"env"`
	Secrets        map[string]interface{} `json:"secrets"`
	Seconds        int                    `json:"seconds"`
	Cron           string                 `json:"cron"`
	Auth           string                 `json:"auth"`
}
