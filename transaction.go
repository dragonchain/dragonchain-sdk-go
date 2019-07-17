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

// CreateTransaction defines the transaction schema for dragonchain.
type CreateTransaction struct {
	Version         string                 `json:"version"`
	TransactionType string                 `json:"txn_type"`
	Tag             string                 `json:"tag"`
	Payload         map[string]interface{} `json:"payload"`
}

// Header defines the HTTP headers required for dragonchain authentication
type Header struct {
	TransactionType string `json:"txn_type"`
	DcID            string `json:"dc_id"`
	TxnID           string `json:"txn_id"`
	BlockID         string `json:"block_id"`
	TimeStamp       string `json:"timestamp"`
	Tag             string `json:"tag"`
	Invoker         string `json:"invoker"`
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

// CreateTransactionResponse defines the response from creating a transaction
type CreateTransactionResponse struct {
	TransactionID string `json:"transaction_id"`
}

// CreateBulkTransactionResponse defines the response from creating a bulk transaction
type CreateBulkTransactionResponse struct {
	Valid   []string      `json:"201,omitempty"`
	Invalid []interface{} `json:"400,omitempty"`
}

// GetSmartContractHeap defines the request format for getting a key from a Smart Contract's heap.
type GetSmartContractHeap struct {
	SCName string `json:"sc_name"`
	Key    string `json:"key"`
}

// TransactionType defines the properties of a valid Dragonchain transaction type.
type TransactionType struct {
	Version       string                 `json:"version"`
	Type          string                 `json:"txn_type"`
	CustomIndexes []CustomIndexStructure `json:"custom_indexes,omitempty"`
}

// CustomIndexStructure defines the valid format of custom indexes on a transaction type.
type CustomIndexStructure struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

// BitcoinTransaction represents a transaction on a bitcoin chain.
type BitcoinTransaction struct {
	Network         string           `json:"network"`
	SatoshisPerByte float32          `json:"satoshisPerByte,omitempty"`
	Data            string           `json:"data,omitempty"`
	ChangeAddress   string           `json:"changeAddress,omitempty"`
	Outputs         []BitcoinOutputs `json:"outputs,omitempty"`
}

type bitcoinBackEndTransaction struct {
	Network     string
	Transaction bitcoinTransactionWithoutNetwork
}

type bitcoinTransactionWithoutNetwork struct {
	SatoshisPerByte float32          `json:"satoshisPerByte,omitempty"`
	Data            string           `json:"data,omitempty"`
	ChangeAddress   string           `json:"changeAddress,omitempty"`
	Outputs         []BitcoinOutputs `json:"outputs,omitempty"`
}

// EthereumTransaction represents a transaction on an ethereum chain.
type EthereumTransaction struct {
	Network  string `json:"network"`
	To       string `json:"to"`
	Value    string `json:"value"`
	Data     string `json:"data,omitempty"`
	GasPrice string `json:"gasPrice,omitempty"`
	Gas      string `json:"gas,omitempty"`
}

type ethereumBackEndTransaction struct {
	Network     string `json:"network"`
	Transaction ethereumTransactionWithoutNetwork
}

type ethereumTransactionWithoutNetwork struct {
	To       string `json:"to"`
	Value    string `json:"value"`
	Data     string `json:"data,omitempty"`
	GasPrice string `json:"gasPrice,omitempty"`
	Gas      string `json:"gas,omitempty"`
}

// BitcoinNetworks supported for interchain capabilities
var BitcoinNetworks = map[string]bool{
	"BTC_MAINNET":  true,
	"BTC_TESTNET3": true,
}

// EthereumNetworks supported for interchain capabilities
var EthereumNetworks = map[string]bool{
	"ETH_MAINNET": true,
	"ETH_ROPSTEN": true,
	"ETC_MAINNET": true,
	"ETC_MORDEN":  true,
}

// BitcoinOutputs are optional outputs for a bitcoin transaction.
type BitcoinOutputs struct {
	ScriptPubKey string  `json:"scriptPubKey"`
	Value        float32 `json:"value,omitempty"`
}
