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

// PostTransaction defines the transaction schema for dragonchain.
type PostTransaction struct {
	Version string                 `json:"version"`
	TxnType string                 `json:"txn_type"`
	Tag     string                 `json:"tag"`
	Payload map[string]interface{} `json:"payload"`
}

// Header defines the HTTP headers required for dragonchain authentication
type Header struct {
	TxnType   string `json:"txn_type"`
	DcID      string `json:"dc_id"`
	TxnID     string `json:"txn_id"`
	BlockID   string `json:"block_id"`
	TimeStamp string `json:"timestamp"`
	Tag       string `json:"tag"`
	Invoker   string `json:"invoker"`
}

// Proof defines the proof object returned by L1 dragonchains.
type Proof struct {
	Full     string `json:"full"`
	Stripped string `json:"stripped"`
}

// Transaction defines the complete transaction on a dragonchain.
type Transaction struct {
	Version string                 `json:"version"`
	DCRN    string                 `json:"dcrn"`
	Header  Header                 `json:"header"`
	Payload map[string]interface{} `json:"payload"`
	Proof   Proof                  `json:"proof"`
}

// GetSmartContractHeap defines the request format for getting a key from a Smart Contract's heap.
type GetSmartContractHeap struct {
	SCName string `json:"sc_name"`
	Key    string `json:"key"`
}
