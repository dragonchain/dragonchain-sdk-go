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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"gotest.tools/assert"
)

var testServer *httptest.Server

func setUp() (*httptest.Server, *Client) {
	if testServer == nil {
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				if strings.Contains(r.URL.RequestURI(), "transaction-types") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"transaction_types\": [{\"version\": \"1\", \"txn_type\": \"banana\", \"custom_indexes\": [], \"contract_id\": false}]}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"version\": \"1\", \"txn_type\": \"banana\", \"custom_indexes\": [], \"contract_id\": false}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction") && r.URL.RawQuery != "" {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"results\": [{\"version\": \"1\", \"dcrn\": \"Transaction::L1::FullTransaction\", \"header\": {\"txn_type\": \"TEST\", \"dc_id\": \"banana\", \"txn_id\": \"banana-txn\", \"block_id\": \"24626984\", \"timestamp\": \"1555373138\", \"tag\": \"\", \"invoker\": \"\"}, \"payload\": {\"Hello\": \"World\"}, \"proof\": {\"full\": \"proof\", \"stripped\": \"banana=\"}}]}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"version\": \"1\", \"dcrn\": \"Transaction::L1::FullTransaction\", \"header\": {\"txn_type\": \"TEST\", \"dc_id\": \"banana\", \"txn_id\": \"banana-txn\", \"block_id\": \"24626984\", \"timestamp\": \"1555373138\", \"tag\": \"\", \"invoker\": \"\"}, \"payload\": {\"Hello\": \"World\"}, \"proof\": {\"full\": \"proof\", \"stripped\": \"banana=\"}}}")
				} else if strings.Contains(r.URL.RequestURI(), "status") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"dragonchainName\": \"banana\", \"dragonchainVersion\": \"3.0.11\", \"level\": \"1\"}}")
				} else if strings.Contains(r.URL.RequestURI(), "block") && r.URL.RawQuery != "" {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"results\": [{\"version\": \"1\", \"dcrn\": \"Block::L1::AtRest\", \"header\": {\"dc_id\": \"banana\", \"block_id\": \"24643517\", \"level\": 1, \"timestamp\": \"1555455805\", \"prev_id\": \"24643516\", \"prev_proof\": \"banana\"}, \"transactions\": [], \"proof\": {\"scheme\": \"trust\", \"proof\": \"bananana\"}}]}}")
				} else if strings.Contains(r.URL.RequestURI(), "block") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"version\": \"1\", \"dcrn\": \"Block::L1::AtRest\", \"header\": {\"dc_id\": \"banana\", \"block_id\": \"24643517\", \"level\": 1, \"timestamp\": \"1555455805\", \"prev_id\": \"24643516\", \"prev_proof\": \"banana\"}, \"transactions\": [], \"proof\": {\"scheme\": \"trust\", \"proof\": \"bananana\"}}}")
				} else if strings.Contains(r.URL.RequestURI(), "verifications") && r.URL.RawQuery != "" {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": [{\"version\": \"1\", \"dcrn\": \"Block::L2::AtRest\", \"header\": {}, \"validation\": {\"dc_id\": \"banana\", \"block_id\": \"24641157\", \"stripped_proof\": \"\", \"transactions\": \"{\\\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\\\": true}\"}, \"proof\": {\"scheme\": \"trust\", \"proof\": \"proofnana\"}}]}")
				} else if strings.Contains(r.URL.RequestURI(), "verifications") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"2\": [{\"version\": \"1\", \"dcrn\": \"Block::L2::AtRest\", \"header\": {}, \"validation\": {\"dc_id\": \"banana\", \"block_id\": \"24641157\", \"stripped_proof\": \"\", \"transactions\": \"{\\\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\\\": true}\"}, \"proof\": {\"scheme\": \"trust\", \"proof\": \"proofnana\"}}]}}")
				} else if strings.Contains(r.URL.RequestURI(), "contract/banana") || strings.Contains(r.URL.RequestURI(), "contract/txn_type/banana") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-sc-id\", \"status\": {\"state\": \"active\", \"msg\": \"\", \"timestamp\": \"2019-04-21 11:01:53.113408\"}, \"image\": \"bananamage\", \"auth_key_id\": \"SC_BANANA\", \"image_digest\": \"\", \"cmd\": \"node\", \"args\": [\"index.js\"], \"execution_order\": \"serial\"}}")
				} else if strings.Contains(r.URL.RequestURI(), "contract") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"results\": [{\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-sc-id\", \"status\": {\"state\": \"active\", \"msg\": \"\", \"timestamp\": \"2019-04-21 11:01:53.113408\"}, \"image\": \"bananamage\", \"auth_key_id\": \"SC_BANANA\", \"image_digest\": \"\", \"cmd\": \"node\", \"args\": [\"index.js\"], \"execution_order\": \"serial\"}]}}")
				} else if strings.Contains(r.URL.RequestURI(), "get") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": \"banana\"}")
				} else if strings.Contains(r.URL.RequestURI(), "list") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": \"banana\"}")
				}
			} else if r.Method == "POST" {
				if strings.Contains(r.URL.RequestURI(), "transaction_bulk") {
					fmt.Fprint(w, "{\"status\": 201, \"ok\": true, \"response\": {\"201\": [\"banana\"], \"400\": [\"apple\"]}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"success\": true}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction") {
					fmt.Fprint(w, "{\"status\": 201, \"ok\": true, \"response\": {\"transaction_id\": \"banana\"}}")
				} else if strings.Contains(r.URL.RequestURI(), "contract") {
					fmt.Fprint(w, "{\"status\": 202, \"ok\": true, \"response\": {\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"3\", \"txn_type\": \"banana\", \"id\": \"banana-id\", \"status\": {}, \"image\": \"dragonchain/banana:1.0.0-dev\", \"cmd\": \"go\", \"args\": [\"run\"], \"execution_order\": \"serial\"}}}")
				}
			} else if r.Method == "PUT" {
				if strings.Contains(r.URL.RequestURI(), "contract") {
					fmt.Fprint(w, "{\"status\": 202, \"ok\": true, \"response\": {\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-id\", \"status\": {}, \"image\": \"dragonchain/banana:1.0.0-dev\", \"cmd\": \"go\", \"args\": [\"run\"], \"execution_order\": \"serial\"}}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"success\": true}}")
				}
			} else if r.Method == "DELETE" {
				if strings.Contains(r.URL.RequestURI(), "contract") {
					fmt.Fprint(w, "{\"status\": 202, \"ok\": true, \"response\": {\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-id\"}}}")
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"success\": true}}")
				}
			}
		}))
	}
	auth, _ := NewCredentials("bananachain", "bananakey", "bananaid", HashSHA256)
	client := NewClient(auth, testServer.URL, testServer.Client())
	return testServer, client
}

func TestNewClient(t *testing.T) {
	creds, _ := NewCredentials("bananachain", "bananakey", "bananaid", HashSHA256)
	client := NewClient(creds, "", nil)
	assert.Equal(t, client.apiBaseURL, "https://bananachain.api.dragonchain.com")
	assert.DeepEqual(t, client.httpClient, &http.Client{})
}

func TestOverrideCredentials(t *testing.T) {
	server, client := setUp()
	newAuth, _ := NewCredentials("apple", "orange", "watermelon", HashBLAKE2b512)
	httpStub := server.Client()
	client.OverrideCredentials(newAuth, "farhost", httpStub)
	assert.Equal(t, client.creds, newAuth)
	assert.Equal(t, client.apiBaseURL, "farhost")
}

func TestGetSecret(t *testing.T) {
	os.Setenv("SMART_CONTRACT_ID", "bananacoin")
	_, client := setUp()
	_, err := client.GetSecret("bananasecret", "")
	assert.Error(t, err, "open /var/openfaas/secrets/sc-bananacoin-bananasecret: no such file or directory")
}

func TestParseSecret(t *testing.T) {
	reader := strings.NewReader("banananana")
	resp, err := parseSecret(reader)
	assert.NilError(t, err, "ParseSecret should not return an error")
	assert.Equal(t, resp, "banananana")
}

func TestGetStatus(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetStatus()
	assert.NilError(t, err, "GetStatus should not return an error")
	expected := make(map[string]interface{})
	expected["dragonchainName"] = "banana"
	expected["dragonchainVersion"] = "3.0.11"
	expected["level"] = "1"
	assert.DeepEqual(t, resp.Response, expected)
}

func TestQueryContracts(t *testing.T) {
	query, _ := NewQuery("banana", "fruit", 10, 10)
	_, client := setUp()
	resp, err := client.QueryContracts(query)
	// The Node and Python SDKs return queries under the key response.results as an array.
	// For consistency, the overhead of managing this difference in golang is passed to the user.
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["results"])
	var contracts []Contract
	json.Unmarshal(raw, &contracts)
	expected := Contract{
		TxnType:    "banana",
		ContractID: "banana-sc-id",
		Status: ContractStatus{
			State:     "active",
			Timestamp: "2019-04-21 11:01:53.113408",
		},
		Image:          "bananamage",
		AuthKeyID:      "SC_BANANA",
		Cmd:            "node",
		Args:           []string{"index.js"},
		ExecutionOrder: "serial",
	}
	assert.NilError(t, err, "QueryContracts should not return an error")
	assert.DeepEqual(t, contracts[0], expected)
}

func TestGetSmartContractByID(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetSmartContract("banana", "")
	assert.NilError(t, err, "GetSmartContract should not return an error")
	expected := Contract{
		TxnType:    "banana",
		ContractID: "banana-sc-id",
		Status: ContractStatus{
			State:     "active",
			Timestamp: "2019-04-21 11:01:53.113408",
		},
		Image:          "bananamage",
		AuthKeyID:      "SC_BANANA",
		Cmd:            "node",
		Args:           []string{"index.js"},
		ExecutionOrder: "serial",
	}
	assert.DeepEqual(t, resp.Response, expected)
}

func TestGetSmartContractByType(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetSmartContract("", "banana")
	assert.NilError(t, err, "GetSmartContract should not return an error")
	expected := Contract{
		TxnType:    "banana",
		ContractID: "banana-sc-id",
		Status: ContractStatus{
			State:     "active",
			Timestamp: "2019-04-21 11:01:53.113408",
		},
		Image:          "bananamage",
		AuthKeyID:      "SC_BANANA",
		Cmd:            "node",
		Args:           []string{"index.js"},
		ExecutionOrder: "serial",
	}
	assert.DeepEqual(t, resp.Response, expected)
}

func TestGetSmartContractError(t *testing.T) {
	_, client := setUp()
	_, err := client.GetSmartContract("", "")
	assert.Error(t, err, "invalid parameters: you must provide one of contractID or txnType")
}

func TestPostContract(t *testing.T) {
	_, client := setUp()
	contract := &ContractConfiguration{
		TxnType:        "banana",
		ExecutionOrder: "serial",
		Image:          "dragonchain/banana:1.0.0-dev",
		Cmd:            "go",
		Args:           []string{"run"},
		Seconds:        59,
		Auth:           "bananaauth",
	}
	resp, err := client.PostContract(contract)
	assert.NilError(t, err, "PostContract should not return an error")
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["success"])
	var contractResp Contract
	json.Unmarshal(raw, &contractResp)
	expected := Contract{
		TxnType:        "banana",
		ContractID:     "banana-id",
		Image:          "dragonchain/banana:1.0.0-dev",
		Cmd:            "go",
		Args:           []string{"run"},
		ExecutionOrder: "serial",
	}
	assert.DeepEqual(t, contractResp, expected)
}

func TestUpdateContract(t *testing.T) {
	_, client := setUp()
	contract := &ContractConfiguration{
		TxnType:        "banana2",
		ExecutionOrder: "serial",
		Image:          "dragonchain/banana:2.0.0-dev",
		Cmd:            "go",
		Args:           []string{"run"},
		Seconds:        59,
		Auth:           "bananaauth",
	}
	resp, err := client.UpdateContract(contract)
	assert.NilError(t, err, "UpdateContract should not return an error")
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["success"])
	var contractResp Contract
	json.Unmarshal(raw, &contractResp)
	expected := Contract{
		TxnType:        "banana",
		ContractID:     "banana-id",
		Image:          "dragonchain/banana:1.0.0-dev",
		Cmd:            "go",
		Args:           []string{"run"},
		ExecutionOrder: "serial",
	}
	assert.DeepEqual(t, contractResp, expected)
	// ToDo: Load up the contract and verify the update succeeded? Is that an integration test?
}

func TestDeleteContract(t *testing.T) {
	_, client := setUp()
	resp, err := client.DeleteContract("bananaID")
	assert.NilError(t, err, "DeleteContract should not return an error")
	success := resp.Response.(map[string]interface{})["success"]
	assert.Assert(t, success != nil)
}

func TestGetTransaction(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetTransaction("banana-txn")
	assert.NilError(t, err, "GetTransaction should not return an error")
	txn := resp.Response.(Transaction)
	expected := Transaction{
		Version: "1",
		DCRN:    "Transaction::L1::FullTransaction",
		Header: Header{
			TxnType:   "TEST",
			DcID:      "banana",
			TxnID:     "banana-txn",
			BlockID:   "24626984",
			TimeStamp: "1555373138",
		},
		Payload: make(map[string]interface{}),
		Proof: Proof{
			Full:     "proof",
			Stripped: "banana=",
		},
	}
	expected.Payload["Hello"] = "World"
	assert.DeepEqual(t, txn, expected)
}

func TestPostTransaction(t *testing.T) {
	_, client := setUp()
	txn := &PostTransaction{
		Version: "latest",
		TxnType: "banana",
		Payload: make(map[string]interface{}),
	}
	txn.Payload["banana"] = 4
	resp, err := client.PostTransaction(txn)
	assert.NilError(t, err, "PostTransaction should not return an error")
	assert.DeepEqual(t, resp.Response, map[string]interface{}{"transaction_id": "banana"})
}

func TestPostTransactionBulk(t *testing.T) {
	_, client := setUp()
	txn := []*PostTransaction{
		&PostTransaction{
			Version: "latest",
			TxnType: "banana",
		}, &PostTransaction{
			Version: "latest",
			TxnType: "banana",
		},
	}
	resp, err := client.PostTransactionBulk(txn)
	assert.NilError(t, err, "PostTransactionBulk should not return an error")
	assert.DeepEqual(t, resp.Response, map[string]interface{}{"201": []interface{}{"banana"}, "400": []interface{}{"apple"}})
}

func TestQueryBlocks(t *testing.T) {
	_, client := setUp()
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryBlocks(query)
	assert.NilError(t, err, "QueryBlocks should not return an error")
	// The Node and Python SDKs return queries under the key response.results as an array.
	// For consistency, the overhead of managing this difference in golang is passed to the user.
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["results"])
	var blocks []Block
	json.Unmarshal(raw, &blocks)
	expected := []Block{
		Block{
			Version: "1",
			DCRN:    "Block::L1::AtRest",
			Header: BlockHeader{
				DcID:       "banana",
				BlockID:    "24643517",
				Level:      1,
				Timestamp:  "1555455805",
				PrevProof:  "banana",
				PreviousID: "24643516",
			},
			Proof: BlockProof{
				Scheme: "trust",
				Proof:  "bananana",
			},
			Transactions: []Transaction{},
		},
	}
	assert.DeepEqual(t, blocks[0], expected[0])
}

func TestGetBlock(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetBlock("banana")
	block := resp.Response.(Block)
	assert.NilError(t, err, "GetBlock should not return an error")
	expected := Block{
		Version: "1",
		DCRN:    "Block::L1::AtRest",
		Header: BlockHeader{
			DcID:       "banana",
			BlockID:    "24643517",
			Level:      1,
			Timestamp:  "1555455805",
			PrevProof:  "banana",
			PreviousID: "24643516",
		},
		Proof: BlockProof{
			Scheme: "trust",
			Proof:  "bananana",
		},
		Transactions: []Transaction{},
	}
	assert.DeepEqual(t, block, expected)
}

func TestGetVerification(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetVerification("banana", 0)
	assert.NilError(t, err, "GetVerification should not return an error")
	verification := resp.Response.(Verification)
	expected := Verification{
		L2: []Block{
			Block{
				Version: "1",
				DCRN:    "Block::L2::AtRest",
				Proof:   BlockProof{Scheme: "trust", Proof: "proofnana"},
				Validation: L1Verification{
					BlockID:      "24641157",
					ChainID:      "banana",
					Transactions: "{\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\": true}",
				},
			},
		},
	}
	assert.DeepEqual(t, verification, expected)
}

func TestGetVerificationAtLevel(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetVerification("banana", 2)
	assert.NilError(t, err, "GetVerification should not return an error")
	verification := resp.Response.([]Block)
	expected := Block{
		Version: "1",
		DCRN:    "Block::L2::AtRest",
		Proof:   BlockProof{Scheme: "trust", Proof: "proofnana"},
		Validation: L1Verification{
			BlockID:      "24641157",
			ChainID:      "banana",
			Transactions: "{\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\": true}",
		},
	}
	assert.DeepEqual(t, verification[0], expected)
}

func TestQueryTransactions(t *testing.T) {
	_, client := setUp()
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryTransactions(query)
	assert.NilError(t, err, "QueryTransactions should not return an error")
	// The Node and Python SDKs return queries under the key response.results as an array.
	// For consistency, the overhead of managing this difference in golang is passed to the user.
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["results"])
	var txn []Transaction
	json.Unmarshal(raw, &txn)
	expected := Transaction{
		Version: "1",
		DCRN:    "Transaction::L1::FullTransaction",
		Header: Header{
			TxnType:   "TEST",
			DcID:      "banana",
			TxnID:     "banana-txn",
			BlockID:   "24626984",
			TimeStamp: "1555373138",
		},
		Payload: make(map[string]interface{}),
		Proof: Proof{
			Full:     "proof",
			Stripped: "banana=",
		},
	}
	expected.Payload["Hello"] = "World"
	assert.DeepEqual(t, txn[0], expected)
}

func TestGetSCHeap(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetSCHeap("bananaContract", "apple")
	assert.NilError(t, err, "GetSCHeap should not return an error")
	assert.Equal(t, resp.Response, "banana")
}

func TestListSCHeap(t *testing.T) {
	_, client := setUp()
	resp, err := client.ListSCHeap("bananaContract", "apple")
	assert.NilError(t, err, "ListSCHeap should not return an error")
	assert.Equal(t, resp.Response, "banana")
}

func TestGetTransactionType(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetTransactionType("banana")
	assert.NilError(t, err, "GetTransactionType should not return an error")
	expected := TransactionType{
		Version:       "1",
		Type:          "banana",
		CustomIndexes: []CustomIndexStructure{},
	}
	assert.DeepEqual(t, resp.Response, expected)
}

func TestListTransactionTypes(t *testing.T) {
	_, client := setUp()
	resp, err := client.ListTransactionTypes()
	assert.NilError(t, err, "ListTransactionTypes should not return an error")
	// The Node and Python SDKs return queries under the key response.transaction_types as an array.
	// For consistency, the overhead of managing this difference in golang is passed to the user.
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["transaction_types"])
	var txnTypes []TransactionType
	json.Unmarshal(raw, &txnTypes)
	expected := TransactionType{
		Version:       "1",
		Type:          "banana",
		CustomIndexes: []CustomIndexStructure{},
	}
	assert.DeepEqual(t, txnTypes[0], expected)
}

func TestUpdateTransactionType(t *testing.T) {
	_, client := setUp()
	indexes := []CustomIndexStructure{
		CustomIndexStructure{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.UpdateTransactionType("banana", indexes)
	assert.NilError(t, err, "UpdateTransactionType should not return an error")
	expected := make(map[string]interface{})
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}

func TestRegisterTransactionType(t *testing.T) {
	_, client := setUp()
	indexes := []CustomIndexStructure{
		CustomIndexStructure{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.RegisterTransactionType("banana", indexes)
	assert.NilError(t, err, "RegisterTransactionType should not return an error")
	expected := make(map[string]interface{})
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}

func TestDeleteTransactionType(t *testing.T) {
	_, client := setUp()
	resp, err := client.DeleteTransactionType("banana")
	assert.NilError(t, err, "DeleteTransactionType should not return an error")
	expected := make(map[string]interface{})
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}
