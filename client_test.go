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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"gotest.tools/assert"
)

// Not a test. Designed for manual checking.
// func TestMain(t *testing.T) {
// 	creds, _ := NewCredentials("3a822827-9394-4930-b451-871748695a9a", "BeCTBDhOwPqYK6vHRTDNVdrxdm2G9DVurdlZOZmYhPF", "DCUTBPZRDYUR", "")
// 	client := NewClient(creds, "", nil)
// 	resp, _ := client.GetTransaction("4132741c-0327-4e20-a3ac-e8f4fc861532")
// 	fmt.Printf("%+v\n", resp.Response)
// }

type clientMock struct {
}

func (c clientMock) Do(req *http.Request) (*http.Response, error) {
	return nil, errors.New("this is a test error in Client.Do")
}
func (c clientMock) CloseIdleConnections() {
	return
}
func (c clientMock) Get(url string) (resp *http.Response, err error) {
	return nil, errors.New("this is a test error in Client.Get")
}
func (c clientMock) Head(url string) (resp *http.Response, err error) {
	return nil, errors.New("this is a test error in Client.Head")
}
func (c clientMock) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	return nil, errors.New("this is a test error in Client.Post")
}
func (c clientMock) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return nil, errors.New("this is a test error in Client.PostForm")
}

var testServer *httptest.Server

func setUp() (*httptest.Server, *Client) {
	if testServer == nil {
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mustWrite := func(_ int, err error) {
				if err != nil {
					panic(err)
				}
			}

			if r.Method == "GET" {
				if strings.Contains(r.URL.RequestURI(), "transaction-types") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"transaction_types\": [{\"version\": \"1\", \"txn_type\": \"banana\", \"custom_indexes\": [], \"contract_id\": false}]}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"version\": \"1\", \"txn_type\": \"banana\", \"custom_indexes\": [], \"contract_id\": false}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction") && r.URL.RawQuery != "" {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"results\": [{\"version\": \"1\", \"dcrn\": \"Transaction::L1::FullTransaction\", \"header\": {\"txn_type\": \"TEST\", \"dc_id\": \"banana\", \"txn_id\": \"banana-txn\", \"block_id\": \"24626984\", \"timestamp\": \"1555373138\", \"tag\": \"\", \"invoker\": \"\"}, \"payload\": {\"Hello\": \"World\"}, \"proof\": {\"full\": \"proof\", \"stripped\": \"banana=\"}}]}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"version\": \"1\", \"dcrn\": \"Transaction::L1::FullTransaction\", \"header\": {\"txn_type\": \"TEST\", \"dc_id\": \"banana\", \"txn_id\": \"banana-txn\", \"block_id\": \"24626984\", \"timestamp\": \"1555373138\", \"tag\": \"\", \"invoker\": \"\"}, \"payload\": {\"Hello\": \"World\"}, \"proof\": {\"full\": \"proof\", \"stripped\": \"banana=\"}}}"))
				} else if strings.Contains(r.URL.RequestURI(), "status") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"dragonchainName\": \"banana\", \"dragonchainVersion\": \"3.0.11\", \"level\": \"1\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "block") && r.URL.RawQuery != "" {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"results\": [{\"version\": \"1\", \"dcrn\": \"Block::L1::AtRest\", \"header\": {\"dc_id\": \"banana\", \"block_id\": \"24643517\", \"level\": 1, \"timestamp\": \"1555455805\", \"prev_id\": \"24643516\", \"prev_proof\": \"banana\"}, \"transactions\": [], \"proof\": {\"scheme\": \"trust\", \"proof\": \"bananana\"}}]}}"))
				} else if strings.Contains(r.URL.RequestURI(), "block") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"version\": \"1\", \"dcrn\": \"Block::L1::AtRest\", \"header\": {\"dc_id\": \"banana\", \"block_id\": \"24643517\", \"level\": 1, \"timestamp\": \"1555455805\", \"prev_id\": \"24643516\", \"prev_proof\": \"banana\"}, \"transactions\": [], \"proof\": {\"scheme\": \"trust\", \"proof\": \"bananana\"}}}"))
				} else if strings.Contains(r.URL.RequestURI(), "verifications") && r.URL.RawQuery != "" {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": [{\"version\": \"1\", \"dcrn\": \"Block::L2::AtRest\", \"header\": {}, \"validation\": {\"dc_id\": \"banana\", \"block_id\": \"24641157\", \"stripped_proof\": \"\", \"transactions\": \"{\\\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\\\": true}\"}, \"proof\": {\"scheme\": \"trust\", \"proof\": \"proofnana\"}}]}"))
				} else if strings.Contains(r.URL.RequestURI(), "verifications") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"2\": [{\"version\": \"1\", \"dcrn\": \"Block::L2::AtRest\", \"header\": {}, \"validation\": {\"dc_id\": \"banana\", \"block_id\": \"24641157\", \"stripped_proof\": \"\", \"transactions\": \"{\\\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\\\": true}\"}, \"proof\": {\"scheme\": \"trust\", \"proof\": \"proofnana\"}}]}}"))
				} else if strings.Contains(r.URL.RequestURI(), "contract/banana") || strings.Contains(r.URL.RequestURI(), "contract/txn_type/banana") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-sc-id\", \"status\": {\"state\": \"active\", \"msg\": \"\", \"timestamp\": \"2019-04-21 11:01:53.113408\"}, \"image\": \"bananamage\", \"auth_key_id\": \"SC_BANANA\", \"image_digest\": \"\", \"cmd\": \"node\", \"args\": [\"index.js\"], \"execution_order\": \"serial\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"results\": [{\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-sc-id\", \"status\": {\"state\": \"active\", \"msg\": \"\", \"timestamp\": \"2019-04-21 11:01:53.113408\"}, \"image\": \"bananamage\", \"auth_key_id\": \"SC_BANANA\", \"image_digest\": \"\", \"cmd\": \"node\", \"args\": [\"index.js\"], \"execution_order\": \"serial\"}]}}"))
				} else if strings.Contains(r.URL.RequestURI(), "get") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": \"banana\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "list") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": \"banana\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "test-dc-error") {
					w.WriteHeader(400)
					mustWrite(fmt.Fprint(w, "{\"status\": 400, \"ok\": false, \"response\": \"banana\"}"))
				}
			} else if r.Method == "POST" {
				if strings.Contains(r.URL.RequestURI(), "transaction_bulk") {
					mustWrite(fmt.Fprint(w, "{\"status\": 201, \"ok\": true, \"response\": {\"201\": [\"banana\"], \"400\": [\"apple\"]}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"success\": true}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction") {
					mustWrite(fmt.Fprint(w, "{\"status\": 201, \"ok\": true, \"response\": {\"transaction_id\": \"banana\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"status\": 202, \"ok\": true, \"response\": {\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"3\", \"txn_type\": \"banana\", \"id\": \"banana-id\", \"status\": {}, \"image\": \"dragonchain/banana:1.0.0-dev\", \"cmd\": \"go\", \"args\": [\"run\"], \"execution_order\": \"serial\"}}}"))
				}
			} else if r.Method == "PUT" {
				if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"status\": 202, \"ok\": true, \"response\": {\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-id\", \"status\": {}, \"image\": \"dragonchain/banana:1.0.0-dev\", \"cmd\": \"go\", \"args\": [\"run\"], \"execution_order\": \"serial\"}}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"success\": true}}"))
				}
			} else if r.Method == "DELETE" {
				if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"status\": 202, \"ok\": true, \"response\": {\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-id\"}}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": {\"success\": true}}"))
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

func TestNoCredentials(t *testing.T) {
	server, _ := setUp()
	client := NewClient(nil, server.URL, nil)
	resp, err := client.QueryContracts(nil)
	assert.Error(t, err, "no credentials found")
	assert.Assert(t, resp == nil)
}

func TestDCError(t *testing.T) {
	_, client := setUp()
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/test-dc-error")
	req, _ := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	_, err := client.performRequest(req)
	assert.Error(t, err, "dragonchain api error: Bad Request (400) body: {\"status\": 400, \"ok\": false, \"response\": \"banana\"}")
}

func TestGetSecret(t *testing.T) {
	defer func() {
		err := os.Remove("/tmp/sc-bananacoin-bananasecret")
		assert.NilError(t, err, "os.Remove should not return an error")
	}()
	file, err := os.Create("/tmp/sc-bananacoin-bananasecret")
	assert.NilError(t, err, "os.Create should not return an error")
	defer func() {
		err := file.Close()
		assert.NilError(t, err, "file.Close should not return an error")
	}()
	_, err = file.WriteString("hello world")
	assert.NilError(t, err, "file.WriteString should not return an error")
	err = os.Setenv("SMART_CONTRACT_ID", "bananacoin")
	assert.NilError(t, err, "os.Setenv should not return an error")
	_, client := setUp()
	resp, err := client.GetSecret("/tmp/sc-bananacoin-bananasecret", "")
	assert.NilError(t, err, "GetSecret should not return an error")
	assert.Equal(t, resp, "hello world")
}

func TestGetSecretError(t *testing.T) {
	err := os.Setenv("SMART_CONTRACT_ID", "bananacoin")
	assert.NilError(t, err, "os.Setenv should not return an error")
	_, client := setUp()
	_, err = client.GetSecret("bananasecret", "")
	assert.NilError(t, err, "client.GetSecret should not return an error")
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

func TestGetStatusRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetStatus()
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
}

func TestQueryContracts(t *testing.T) {
	query, _ := NewQuery("banana", "fruit", 10, 10)
	_, client := setUp()
	resp, err := client.QueryContracts(query)
	assert.NilError(t, err, "QueryContracts should not return an error")
	// The Node and Python SDKs return queries under the key response.results as an array.
	// For consistency, the overhead of managing this difference in golang is passed to the user.
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["results"])
	var contracts []Contract
	err = json.Unmarshal(raw, &contracts)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
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

func TestQueryContractsRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryContracts(query)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
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

func TestGetSmartContractRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetSmartContract("banana", "")
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
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
	err = json.Unmarshal(raw, &contractResp)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
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

func TestPostContractRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
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
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
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
	err = json.Unmarshal(raw, &contractResp)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
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

func TestUpdateContractRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
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
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestDeleteContract(t *testing.T) {
	_, client := setUp()
	resp, err := client.DeleteContract("bananaID")
	assert.NilError(t, err, "DeleteContract should not return an error")
	success := resp.Response.(map[string]interface{})["success"]
	assert.Assert(t, success != nil)
}

func TestDeleteContractRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.DeleteContract("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
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

func TestGetTransactionRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetTransaction("banana-txn")
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
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

func TestPostTransactionRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	txn := &PostTransaction{
		Version: "latest",
		TxnType: "banana",
		Payload: make(map[string]interface{}),
	}
	resp, err := client.PostTransaction(txn)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestPostTransactionBulk(t *testing.T) {
	_, client := setUp()
	txn := []*PostTransaction{
		{
			Version: "latest",
			TxnType: "banana",
		}, {
			Version: "latest",
			TxnType: "banana",
		},
	}
	resp, err := client.PostTransactionBulk(txn)
	assert.NilError(t, err, "PostTransactionBulk should not return an error")
	assert.DeepEqual(t, resp.Response, map[string]interface{}{"201": []interface{}{"banana"}, "400": []interface{}{"apple"}})
}

func TestPostTransactionBulkSizeExceeded(t *testing.T) {
	_, client := setUp()
	txn := &PostTransaction{
		Version: "latest",
		TxnType: "banana",
		Payload: make(map[string]interface{}),
	}
	txns := make([]*PostTransaction, 0)
	for i := 0; i < 260; i++ {
		txns = append(txns, txn)
	}
	resp, err := client.PostTransactionBulk(txns)
	assert.Error(t, err, "too many transactions. transaction count can not be greater than MaxBulkPutSize")
	assert.Assert(t, resp == nil)
}

func TestPostTransactionBulkRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	txn := []*PostTransaction{
		{
			Version: "latest",
			TxnType: "banana",
		}, {
			Version: "latest",
			TxnType: "banana",
		},
	}
	resp, err := client.PostTransactionBulk(txn)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
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
	err = json.Unmarshal(raw, &blocks)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
	expected := []Block{
		{
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

func TestQueryBlocksRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryBlocks(query)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetBlock(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetBlock("banana")
	if resp == nil {
		t.Errorf("did not expect nil response")
	}
	assert.NilError(t, err, "GetBlock should not return an error")
	block := resp.Response.(Block)
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

func TestGetBlockRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetBlock("banana-block")
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
}

func TestGetVerification(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetVerification("banana", 0)
	assert.NilError(t, err, "GetVerification should not return an error")
	verification := resp.Response.(Verification)
	expected := Verification{
		L2: []Block{
			{
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

func TestGetVerificationRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetVerification("banana-verification", 0)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
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
	err = json.Unmarshal(raw, &txn)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
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

func TestQueryTransactionsRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryTransactions(query)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetSCHeap(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetSCHeap("bananaContract", "apple")
	assert.NilError(t, err, "GetSCHeap should not return an error")
	assert.Equal(t, resp.Response, "banana")
}

func TestGetSCHeapNoID(t *testing.T) {
	_, client := setUp()
	err := os.Setenv("SMART_CONTRACT_ID", "bananaContract")
	assert.NilError(t, err, "os.Setenv should not return an error")
	resp, err := client.GetSCHeap("", "apple")
	assert.NilError(t, err, "GetSCHeap should not return an error")
	assert.Equal(t, resp.Response, "banana")
}

func TestGetSCHeapNoKey(t *testing.T) {
	_, client := setUp()
	resp, err := client.GetSCHeap("bananaContract", "")
	assert.Error(t, err, "key can not be empty")
	assert.Assert(t, resp == nil)
}

func TestGetSCHeapRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetSCHeap("bananaContract", "apple")
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
}

func TestListSCHeap(t *testing.T) {
	_, client := setUp()
	resp, err := client.ListSCHeap("bananaContract", "apple")
	assert.NilError(t, err, "ListSCHeap should not return an error")
	assert.Equal(t, resp.Response, "banana")
}

func TestListSCHeapNoID(t *testing.T) {
	_, client := setUp()
	err := os.Setenv("SMART_CONTRACT_ID", "bananaContract")
	assert.NilError(t, err, "os.Setenv should not return an error")
	resp, err := client.ListSCHeap("", "apple")
	assert.NilError(t, err, "ListSCHeap should not return an error")
	assert.Equal(t, resp.Response, "banana")
}

func TestListSCHeapBadFolder(t *testing.T) {
	_, client := setUp()
	resp, err := client.ListSCHeap("bananaContract", "apple/")
	assert.Error(t, err, "folder can not end with '/'")
	assert.Assert(t, resp == nil)
}

func TestListSCHeapRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.ListSCHeap("bananaContract", "apple")
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
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

func TestGetTransactionTypeRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.GetTransactionType("banana")
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
}

func TestListTransactionTypes(t *testing.T) {
	_, client := setUp()
	resp, err := client.ListTransactionTypes()
	assert.NilError(t, err, "ListTransactionTypes should not return an error")
	// The Node and Python SDKs return queries under the key response.transaction_types as an array.
	// For consistency, the overhead of managing this difference in golang is passed to the user.
	raw, _ := json.Marshal(resp.Response.(map[string]interface{})["transaction_types"])
	var txnTypes []TransactionType
	err = json.Unmarshal(raw, &txnTypes)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
	expected := TransactionType{
		Version:       "1",
		Type:          "banana",
		CustomIndexes: []CustomIndexStructure{},
	}
	assert.DeepEqual(t, txnTypes[0], expected)
}

func TestListTransactionTypesRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.ListTransactionTypes()
	assert.Error(t, err, "this is a test error in Client.Get")
	assert.Assert(t, resp == nil)
}

func TestUpdateTransactionType(t *testing.T) {
	_, client := setUp()
	indexes := []CustomIndexStructure{
		{
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

func TestUpdateTransactionTypeRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	indexes := []CustomIndexStructure{
		{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.UpdateTransactionType("banana", indexes)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestRegisterTransactionType(t *testing.T) {
	_, client := setUp()
	indexes := []CustomIndexStructure{
		{
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

func TestRegisterTransactionTypeRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	indexes := []CustomIndexStructure{
		{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.RegisterTransactionType("banana", indexes)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestDeleteTransactionType(t *testing.T) {
	_, client := setUp()
	resp, err := client.DeleteTransactionType("banana")
	assert.NilError(t, err, "DeleteTransactionType should not return an error")
	expected := make(map[string]interface{})
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}

func TestDeleteTransactionTypeRequestFails(t *testing.T) {
	_, client := setUp()
	fakeHTTPClient := clientMock{}
	client.OverrideCredentials(nil, "", fakeHTTPClient)
	resp, err := client.DeleteTransactionType("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}
