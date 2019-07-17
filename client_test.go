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

func TestMain(t *testing.T) {
	creds, _ := NewCredentials("23qqLjVBWpgeZHf9gXRCernSDMXk8TbmPR9w2DnqTiijx", "haf4Ku9Pk5AfZSHKI3F5ZSZycrh2RzhgPR1nqw2WLey", "EDGJEFKFBXGK", "")
	client := NewClient(creds, "https://281bd112-2dda-49f4-97a3-6456c08c5b2e.api.dragonchain.com", nil)

	resp, _ := client.CreateTransactionType("banana", []CustomIndexStructure{})
	fmt.Printf("RESPONSE: %+v\n", resp.Response)
}

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

func setUp(injectedClient *clientMock) (*httptest.Server, *Client) {
	if testServer == nil {
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mustWrite := func(_ int, err error) {
				if err != nil {
					panic(err)
				}
			}

			if r.Method == "GET" {
				if strings.Contains(r.URL.RequestURI(), "transaction-types") {
					mustWrite(fmt.Fprint(w, "{\"transaction_types\": [{\"version\": \"1\", \"txn_type\": \"banana\", \"custom_indexes\": [], \"contract_id\": false}]}"))
				} else if strings.Contains(r.URL.RequestURI(), "public-blockchain-address") {
					mustWrite(fmt.Fprint(w, "{\"eth_mainnet\": \"0xd409258c7B4a26510B5892bE80AFbdB122c35968\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"version\": \"1\", \"txn_type\": \"banana\", \"custom_indexes\": [], \"contract_id\": false}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction") && r.URL.RawQuery != "" {
					mustWrite(fmt.Fprint(w, "{\"results\": [{\"version\": \"1\", \"dcrn\": \"Transaction::L1::FullTransaction\", \"header\": {\"txn_type\": \"TEST\", \"dc_id\": \"banana\", \"txn_id\": \"banana-txn\", \"block_id\": \"24626984\", \"timestamp\": \"1555373138\", \"tag\": \"\", \"invoker\": \"\"}, \"payload\": {\"Hello\": \"World\"}, \"proof\": {\"full\": \"proof\", \"stripped\": \"banana=\"}}]}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction") {
					mustWrite(fmt.Fprint(w, "{\"version\": \"1\", \"dcrn\": \"Transaction::L1::FullTransaction\", \"header\": {\"txn_type\": \"TEST\", \"dc_id\": \"banana\", \"txn_id\": \"banana-txn\", \"block_id\": \"24626984\", \"timestamp\": \"1555373138\", \"tag\": \"\", \"invoker\": \"\"}, \"payload\": {\"Hello\": \"World\"}, \"proof\": {\"full\": \"proof\", \"stripped\": \"banana=\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "status") {
					mustWrite(fmt.Fprint(w, "{\"dragonchainName\": \"banana\", \"dragonchainVersion\": \"3.0.11\", \"level\": \"1\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "block") && r.URL.RawQuery != "" {
					mustWrite(fmt.Fprint(w, "{\"results\": [{\"version\": \"1\", \"dcrn\": \"Block::L1::AtRest\", \"header\": {\"dc_id\": \"banana\", \"block_id\": \"24643517\", \"level\": 1, \"timestamp\": \"1555455805\", \"prev_id\": \"24643516\", \"prev_proof\": \"banana\"}, \"transactions\": [], \"proof\": {\"scheme\": \"trust\", \"proof\": \"bananana\"}}]}"))
				} else if strings.Contains(r.URL.RequestURI(), "block") {
					mustWrite(fmt.Fprint(w, "{\"version\": \"1\", \"dcrn\": \"Block::L1::AtRest\", \"header\": {\"dc_id\": \"banana\", \"block_id\": \"24643517\", \"level\": 1, \"timestamp\": \"1555455805\", \"prev_id\": \"24643516\", \"prev_proof\": \"banana\"}, \"transactions\": [], \"proof\": {\"scheme\": \"trust\", \"proof\": \"bananana\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "verifications") && r.URL.RawQuery != "" {
					mustWrite(fmt.Fprint(w, "[{\"version\": \"1\", \"dcrn\": \"Block::L2::AtRest\", \"header\": {}, \"validation\": {\"dc_id\": \"banana\", \"block_id\": \"24641157\", \"stripped_proof\": \"\", \"transactions\": \"{\\\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\\\": true}\"}, \"proof\": {\"scheme\": \"trust\", \"proof\": \"proofnana\"}}]"))
				} else if strings.Contains(r.URL.RequestURI(), "verifications") {
					mustWrite(fmt.Fprint(w, "{\"2\": [{\"version\": \"1\", \"dcrn\": \"Block::L2::AtRest\", \"header\": {}, \"validation\": {\"dc_id\": \"banana\", \"block_id\": \"24641157\", \"stripped_proof\": \"\", \"transactions\": \"{\\\"6f4aaf5b-0b9e-4447-9351-5e7c478dac62\\\": true}\"}, \"proof\": {\"scheme\": \"trust\", \"proof\": \"proofnana\"}}]}"))
				} else if strings.Contains(r.URL.RequestURI(), "contract/banana") || strings.Contains(r.URL.RequestURI(), "contract/txn_type/banana") {
					mustWrite(fmt.Fprint(w, "{\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-sc-id\", \"status\": {\"state\": \"active\", \"msg\": \"\", \"timestamp\": \"2019-04-21 11:01:53.113408\"}, \"image\": \"bananamage\", \"auth_key_id\": \"SC_BANANA\", \"image_digest\": \"\", \"cmd\": \"node\", \"args\": [\"index.js\"], \"execution_order\": \"serial\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"results\": [{\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-sc-id\", \"status\": {\"state\": \"active\", \"msg\": \"\", \"timestamp\": \"2019-04-21 11:01:53.113408\"}, \"image\": \"bananamage\", \"auth_key_id\": \"SC_BANANA\", \"image_digest\": \"\", \"cmd\": \"node\", \"args\": [\"index.js\"], \"execution_order\": \"serial\"}]}"))
				} else if strings.Contains(r.URL.RequestURI(), "get") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": \"banana\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "list") {
					mustWrite(fmt.Fprint(w, "{\"status\": 200, \"ok\": true, \"response\": \"banana\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "api-key/") {
					mustWrite(fmt.Fprint(w, "{\"id\": \"YOQZNKYTUWTQ\", \"root\": true, \"registration_time\": 0, \"nickname\": \"banana\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "api-key") {
					mustWrite(fmt.Fprint(w, "[{\"id\": \"YOQZNKYTUWTQ\", \"root\": true, \"registration_time\": 0, \"nickname\": \"banana\"}]"))
				} else if strings.Contains(r.URL.RequestURI(), "test-dc-error") {
					w.WriteHeader(400)
					mustWrite(fmt.Fprint(w, "{\"status\": 400, \"ok\": false, \"response\": \"banana\"}"))
				}
			} else if r.Method == "POST" {
				if strings.Contains(r.URL.RequestURI(), "transaction_bulk") {
					mustWrite(fmt.Fprint(w, "{\"201\": [\"banana\"], \"400\": [\"apple\"]}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"success\": true}"))
				} else if strings.Contains(r.URL.RequestURI(), "public-blockchain-transaction") {
					mustWrite(fmt.Fprint(w, "{\"signed\": \"0xf8638084040d6e5c82ea6094e9f36fd8428723cf08b7fd50e084fc61aa378f20018029a063f6630df48a42f138e592714c3cef4c5e70f6a1ec78d9350072d918e1203102a00c264fada9f62bc653c4e3fe807fd315274aaa8abd0626a7a51758be56a3b270\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction") {
					mustWrite(fmt.Fprint(w, "{\"transaction_id\": \"banana\"}"))
				} else if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"3\", \"txn_type\": \"banana\", \"id\": \"banana-id\", \"status\": {}, \"image\": \"dragonchain/banana:1.0.0-dev\", \"cmd\": \"go\", \"args\": [\"run\"], \"execution_order\": \"serial\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "api-key") {
					mustWrite(fmt.Fprint(w, "{\"key\": \"N4UuMzqFRt183ajXjR8P7goKNBqwRZ7ILKHUIcfNquu\", \"id\": \"VIUBMEGJKVRY\", \"registration_time\": 1560362013}"))
				}
			} else if r.Method == "PUT" {
				if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-id\", \"status\": {}, \"image\": \"dragonchain/banana:1.0.0-dev\", \"cmd\": \"go\", \"args\": [\"run\"], \"execution_order\": \"serial\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"success\": true}"))
				} else if strings.Contains(r.URL.RequestURI(), "api-key") {
					mustWrite(fmt.Fprint(w, "{\"success\": true}"))
				}
			} else if r.Method == "DELETE" {
				if strings.Contains(r.URL.RequestURI(), "contract") {
					mustWrite(fmt.Fprint(w, "{\"success\": {\"dcrn\": \"SmartContract::L1::AtRest\", \"version\": \"1\", \"txn_type\": \"banana\", \"id\": \"banana-id\"}}"))
				} else if strings.Contains(r.URL.RequestURI(), "transaction-type") {
					mustWrite(fmt.Fprint(w, "{\"success\": true}"))
				} else if strings.Contains(r.URL.RequestURI(), "api-key") {
					mustWrite(fmt.Fprint(w, "{\"success\": true}"))
				}
			}
		}))
	}
	auth, _ := NewCredentials("bananachain", "bananakey", "bananaid", HashSHA256)
	var client *Client
	if injectedClient != nil {
		client = NewClient(auth, testServer.URL, injectedClient)
	} else {
		client = NewClient(auth, testServer.URL, testServer.Client())

	}
	return testServer, client
}

func TestNewClient(t *testing.T) {
	creds, _ := NewCredentials("bananachain", "bananakey", "bananaid", HashSHA256)
	client := NewClient(creds, "", nil)
	assert.Equal(t, client.apiBaseURL, "https://bananachain.api.dragonchain.com")
	assert.DeepEqual(t, client.httpClient, &http.Client{})
}

func TestNoCredentials(t *testing.T) {
	server, _ := setUp(nil)
	client := NewClient(nil, server.URL, nil)
	resp, err := client.QuerySmartContracts(nil)
	assert.Error(t, err, "no credentials found")
	assert.Assert(t, resp == nil)
}

func TestDCError(t *testing.T) {
	_, client := setUp(nil)
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/test-dc-error")
	req, _ := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	resp, err := client.performRequest(req, []byte(""))
	assert.NilError(t, err, "errors from the dragonchain should not cause exceptions")
	assert.Equal(t, string(resp.Response.([]byte)), "{\"status\": 400, \"ok\": false, \"response\": \"banana\"}")
}

func TestGetSmartContractSecret(t *testing.T) {
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
	_, client := setUp(nil)
	resp, err := client.GetSmartContractSecret("/tmp/sc-bananacoin-bananasecret")
	assert.NilError(t, err, "GetSmartContractSecret should not return an error")
	assert.Equal(t, resp, "hello world")
}

func TestGetSmartContractSecretError(t *testing.T) {
	err := os.Setenv("SMART_CONTRACT_ID", "bananacoin")
	assert.NilError(t, err, "os.Setenv should not return an error")
	_, client := setUp(nil)
	_, err = client.GetSmartContractSecret("bananasecret")
	assert.Error(t, err, "open /var/openfaas/secrets/sc-bananacoin-bananasecret: no such file or directory")
}

func TestParseSecret(t *testing.T) {
	reader := strings.NewReader("banananana")
	resp, err := parseSecret(reader)
	assert.NilError(t, err, "ParseSecret should not return an error")
	assert.Equal(t, resp, "banananana")
}

func TestGetStatus(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetStatus()
	assert.NilError(t, err, "GetStatus should not return an error")
	expected := make(map[string]interface{})
	expected["dragonchainName"] = "banana"
	expected["dragonchainVersion"] = "3.0.11"
	expected["level"] = "1"
	var actual map[string]interface{}
	json.Unmarshal(resp.Response.([]byte), &actual)
	assert.DeepEqual(t, actual, expected)
}

func TestGetStatusRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetStatus()
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestQuerySmartContracts(t *testing.T) {
	query, _ := NewQuery("banana", "fruit", 10, 10)
	_, client := setUp(nil)
	resp, err := client.QuerySmartContracts(query)
	assert.NilError(t, err, "QuerySmartContracts should not return an error")
	expected := Contract{
		TransactionType: "banana",
		ContractID:      "banana-sc-id",
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
	assert.NilError(t, err, "QuerySmartContracts should not return an error")
	assert.DeepEqual(t, resp.Response.(map[string][]Contract)["results"][0], expected)
}

func TestQuerySmartContractsRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QuerySmartContracts(query)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetSmartContractByID(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetSmartContract("banana", "")
	assert.NilError(t, err, "GetSmartContract should not return an error")
	expected := Contract{
		TransactionType: "banana",
		ContractID:      "banana-sc-id",
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
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetSmartContract("banana", "")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetSmartContractByType(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetSmartContract("", "banana")
	assert.NilError(t, err, "GetSmartContract should not return an error")
	expected := Contract{
		TransactionType: "banana",
		ContractID:      "banana-sc-id",
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
	_, client := setUp(nil)
	_, err := client.GetSmartContract("", "")
	assert.Error(t, err, "invalid parameters: you must provide one of smartContractID or transactionType")
}

func TestCreateSmartContract(t *testing.T) {
	_, client := setUp(nil)
	contract := &ContractConfiguration{
		TransactionType:           "banana",
		ExecutionOrder:            "serial",
		Image:                     "dragonchain/banana:1.0.0-dev",
		Cmd:                       "go",
		Args:                      []string{"run"},
		ScheduleIntervalInSeconds: 59,
		RegistryCredentials:       "bananaauth",
	}
	resp, err := client.CreateSmartContract(contract)
	assert.NilError(t, err, "CreateSmartContract should not return an error")
	var success map[string]Contract
	err = json.Unmarshal(resp.Response.([]byte), &success)
	assert.NilError(t, err, "CreateSmartContract should not return an error")
	actual := success["success"]
	expected := Contract{
		TransactionType: "banana",
		ContractID:      "banana-id",
		Image:           "dragonchain/banana:1.0.0-dev",
		Cmd:             "go",
		Args:            []string{"run"},
		ExecutionOrder:  "serial",
	}
	assert.DeepEqual(t, actual, expected)
}

func TestCreateSmartContractRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	contract := &ContractConfiguration{
		TransactionType:           "banana",
		ExecutionOrder:            "serial",
		Image:                     "dragonchain/banana:1.0.0-dev",
		Cmd:                       "go",
		Args:                      []string{"run"},
		ScheduleIntervalInSeconds: 59,
		RegistryCredentials:       "bananaauth",
	}
	resp, err := client.CreateSmartContract(contract)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestUpdateSmartContract(t *testing.T) {
	_, client := setUp(nil)
	contract := &ContractConfiguration{
		TransactionType:           "banana2",
		ExecutionOrder:            "serial",
		Image:                     "dragonchain/banana:2.0.0-dev",
		Cmd:                       "go",
		Args:                      []string{"run"},
		ScheduleIntervalInSeconds: 59,
		RegistryCredentials:       "bananaauth",
	}
	resp, err := client.UpdateSmartContract(contract)
	assert.NilError(t, err, "UpdateSmartContract should not return an error")
	var success map[string]Contract
	err = json.Unmarshal(resp.Response.([]byte), &success)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
	actual := success["success"]
	expected := Contract{
		TransactionType: "banana",
		ContractID:      "banana-id",
		Image:           "dragonchain/banana:1.0.0-dev",
		Cmd:             "go",
		Args:            []string{"run"},
		ExecutionOrder:  "serial",
	}
	assert.DeepEqual(t, actual, expected)
	// ToDo: Load up the contract and verify the update succeeded? Is that an integration test?
}

func TestUpdateSmartContractRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	contract := &ContractConfiguration{
		TransactionType:           "banana2",
		ExecutionOrder:            "serial",
		Image:                     "dragonchain/banana:2.0.0-dev",
		Cmd:                       "go",
		Args:                      []string{"run"},
		ScheduleIntervalInSeconds: 59,
		RegistryCredentials:       "bananaauth",
	}
	resp, err := client.UpdateSmartContract(contract)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestDeleteContract(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.DeleteContract("bananaID")
	assert.NilError(t, err, "DeleteContract should not return an error")
	var success map[string]*Contract
	err = json.Unmarshal(resp.Response.([]byte), &success)
	assert.NilError(t, err, "Delete should not return an error")
	assert.Assert(t, success["success"] != nil)
}

func TestDeleteContractRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.DeleteContract("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetTransaction(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetTransaction("banana-txn")
	assert.NilError(t, err, "GetTransaction should not return an error")
	txn := resp.Response.(Transaction)
	expected := Transaction{
		Version: "1",
		DCRN:    "Transaction::L1::FullTransaction",
		Header: Header{
			TransactionType: "TEST",
			DcID:            "banana",
			TxnID:           "banana-txn",
			BlockID:         "24626984",
			TimeStamp:       "1555373138",
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
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetTransaction("banana-txn")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestCreateTransaction(t *testing.T) {
	_, client := setUp(nil)
	txn := &CreateTransaction{
		Version:         "latest",
		TransactionType: "banana",
		Payload:         make(map[string]interface{}),
	}
	txn.Payload["banana"] = 4
	resp, err := client.CreateTransaction(txn)
	assert.NilError(t, err, "CreateTransaction should not return an error")
	assert.DeepEqual(t, string(resp.Response.([]byte)), "{\"transaction_id\": \"banana\"}")
}

func TestCreateTransactionRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	txn := &CreateTransaction{
		Version:         "latest",
		TransactionType: "banana",
		Payload:         make(map[string]interface{}),
	}
	resp, err := client.CreateTransaction(txn)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestCreateBulkTransaction(t *testing.T) {
	_, client := setUp(nil)
	txn := []*CreateTransaction{
		{
			Version:         "latest",
			TransactionType: "banana",
		}, {
			Version:         "latest",
			TransactionType: "banana",
		},
	}
	resp, err := client.CreateBulkTransaction(txn)
	assert.NilError(t, err, "CreateBulkTransaction should not return an error")
	assert.DeepEqual(t, string(resp.Response.([]byte)), "{\"201\": [\"banana\"], \"400\": [\"apple\"]}")
}

func TestCreateBulkTransactionSizeExceeded(t *testing.T) {
	_, client := setUp(nil)
	txn := &CreateTransaction{
		Version:         "latest",
		TransactionType: "banana",
		Payload:         make(map[string]interface{}),
	}
	txns := make([]*CreateTransaction, 0)
	for i := 0; i < 260; i++ {
		txns = append(txns, txn)
	}
	resp, err := client.CreateBulkTransaction(txns)
	assert.Error(t, err, "too many transactions. transaction count can not be greater than MaxBulkPutSize")
	assert.Assert(t, resp == nil)
}

func TestCreateBulkTransactionRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	txn := []*CreateTransaction{
		{
			Version:         "latest",
			TransactionType: "banana",
		}, {
			Version:         "latest",
			TransactionType: "banana",
		},
	}
	resp, err := client.CreateBulkTransaction(txn)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestQueryBlocks(t *testing.T) {
	_, client := setUp(nil)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryBlocks(query)
	assert.NilError(t, err, "QueryBlocks should not return an error")
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
	assert.DeepEqual(t, resp.Response.(map[string][]Block)["results"][0], expected[0])
}

func TestQueryBlocksRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryBlocks(query)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetBlock(t *testing.T) {
	_, client := setUp(nil)
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
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetBlock("banana-block")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetVerifications(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetVerifications("banana", 0)
	assert.NilError(t, err, "GetVerifications should not return an error")
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

func TestGetVerificationsRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetVerifications("banana-verification", 0)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetVerificationsAtLevel(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetVerifications("banana", 2)
	assert.NilError(t, err, "GetVerifications should not return an error")
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
	_, client := setUp(nil)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryTransactions(query)
	assert.NilError(t, err, "QueryTransactions should not return an error")
	var txn map[string][]Transaction
	err = json.Unmarshal(resp.Response.([]byte), &txn)
	assert.NilError(t, err, "json.Unmarshal should not return an error")
	expected := Transaction{
		Version: "1",
		DCRN:    "Transaction::L1::FullTransaction",
		Header: Header{
			TransactionType: "TEST",
			DcID:            "banana",
			TxnID:           "banana-txn",
			BlockID:         "24626984",
			TimeStamp:       "1555373138",
		},
		Payload: make(map[string]interface{}),
		Proof: Proof{
			Full:     "proof",
			Stripped: "banana=",
		},
	}
	expected.Payload["Hello"] = "World"
	assert.DeepEqual(t, txn["results"][0], expected)
}

func TestQueryTransactionsRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	query, _ := NewQuery("banana", "fruit", 10, 10)
	resp, err := client.QueryTransactions(query)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetSmartContractObject(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetSmartContractObject("apple", "bananaContract")
	assert.NilError(t, err, "GetSmartContractObject should not return an error")
	var actual map[string]interface{}
	err = json.Unmarshal(resp.Response.([]byte), &actual)
	assert.Equal(t, actual["response"], "banana")
}

func TestGetSmartContractObjectNoID(t *testing.T) {
	_, client := setUp(nil)
	err := os.Setenv("SMART_CONTRACT_ID", "bananaContract")
	assert.NilError(t, err, "os.Setenv should not return an error")
	resp, err := client.GetSmartContractObject("apple", "")
	assert.NilError(t, err, "GetSmartContractObject should not return an error")
	var actual map[string]interface{}
	err = json.Unmarshal(resp.Response.([]byte), &actual)
	assert.Equal(t, actual["response"], "banana")
}

func TestGetSmartContractObjectNoKey(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetSmartContractObject("", "bananaContract")
	assert.Error(t, err, "key can not be empty")
	assert.Assert(t, resp == nil)
}

func TestGetSmartContractObjectRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetSmartContractObject("apple", "bananaContract")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestListSmartContractObjects(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.ListSmartContractObjects("apple", "bananaContract")
	assert.NilError(t, err, "ListSmartContractObjects should not return an error")
	var actual map[string]interface{}
	err = json.Unmarshal(resp.Response.([]byte), &actual)
	assert.Equal(t, actual["response"], "banana")
}

func TestListSmartContractObjectsNoID(t *testing.T) {
	_, client := setUp(nil)
	err := os.Setenv("SMART_CONTRACT_ID", "bananaContract")
	assert.NilError(t, err, "os.Setenv should not return an error")
	resp, err := client.ListSmartContractObjects("apple", "")
	assert.NilError(t, err, "ListSmartContractObjects should not return an error")
	var actual map[string]interface{}
	err = json.Unmarshal(resp.Response.([]byte), &actual)
	assert.Equal(t, actual["response"], "banana")
}

func TestListSmartContractObjectsBadFolder(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.ListSmartContractObjects("apple/", "bananaContract")
	assert.Error(t, err, "folder can not end with '/'")
	assert.Assert(t, resp == nil)
}

func TestListSmartContractObjectsRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.ListSmartContractObjects("apple", "bananaContract")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetTransactionType(t *testing.T) {
	_, client := setUp(nil)
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
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetTransactionType("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestListTransactionTypes(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.ListTransactionTypes()
	assert.NilError(t, err, "ListTransactionTypes should not return an error")
	expected := TransactionType{
		Version:       "1",
		Type:          "banana",
		CustomIndexes: []CustomIndexStructure{},
	}
	assert.DeepEqual(t, resp.Response.(map[string][]TransactionType)["transaction_types"][0], expected)
}

func TestListTransactionTypesRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.ListTransactionTypes()
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestUpdateTransactionType(t *testing.T) {
	_, client := setUp(nil)
	indexes := []CustomIndexStructure{
		{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.UpdateTransactionType("banana", indexes)
	assert.NilError(t, err, "UpdateTransactionType should not return an error")
	expected := make(map[string]bool)
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}

func TestUpdateTransactionTypeRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
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

func TestCreateTransactionType(t *testing.T) {
	_, client := setUp(nil)
	indexes := []CustomIndexStructure{
		{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.CreateTransactionType("banana", indexes)
	assert.NilError(t, err, "CreateTransactionType should not return an error")
	expected := make(map[string]interface{})
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}

func TestCreateTransactionTypeRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	indexes := []CustomIndexStructure{
		{
			Key:  "skeleton_key",
			Path: "any/door",
		},
	}
	resp, err := client.CreateTransactionType("banana", indexes)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestDeleteTransactionType(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.DeleteTransactionType("banana")
	assert.NilError(t, err, "DeleteTransactionType should not return an error")
	expected := make(map[string]bool)
	expected["success"] = true
	assert.DeepEqual(t, resp.Response, expected)
}

func TestDeleteTransactionTypeRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.DeleteTransactionType("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestGetPublicBlockchainAddress(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetPublicBlockchainAddress()
	assert.NilError(t, err, "GetPublicBlockchainAddress should not return an error")
	addresses := make(map[string]string)
	addresses["eth_mainnet"] = "0xd409258c7B4a26510B5892bE80AFbdB122c35968"
	assert.DeepEqual(t, resp.Response, addresses)
}

func TestGetPublicBlockchainAddressFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetPublicBlockchainAddress()
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestCreateBitcoinTransaction(t *testing.T) {
	_, client := setUp(nil)
	btcTransaction := BitcoinTransaction{
		Network: "BTC_TESTNET3",
	}
	resp, err := client.CreateBitcoinTransaction(&btcTransaction)
	assert.NilError(t, err, "CreateBitcoinTransaction should not return an error")
	assert.DeepEqual(t, resp.Response.(map[string]string)["signed"], "0xf8638084040d6e5c82ea6094e9f36fd8428723cf08b7fd50e084fc61aa378f20018029a063f6630df48a42f138e592714c3cef4c5e70f6a1ec78d9350072d918e1203102a00c264fada9f62bc653c4e3fe807fd315274aaa8abd0626a7a51758be56a3b270")
}

func TestCreateBitcoinTransactionBadNetwork(t *testing.T) {
	_, client := setUp(nil)
	btcTransaction := BitcoinTransaction{
		Network: "BTC_BANANA",
	}
	_, err := client.CreateBitcoinTransaction(&btcTransaction)
	assert.Error(t, err, "bitcoin transactions can only be created on supported networks: map[BTC_MAINNET:true BTC_TESTNET3:true]")
}

func TestCreateEthereumTransaction(t *testing.T) {
	_, client := setUp(nil)
	btcTransaction := EthereumTransaction{
		Network: "ETH_ROPSTEN",
	}
	resp, err := client.CreateEthereumTransaction(&btcTransaction)
	assert.NilError(t, err, "CreateEthereumTransaction should not return an error")
	assert.DeepEqual(t, resp.Response.(map[string]string)["signed"], "0xf8638084040d6e5c82ea6094e9f36fd8428723cf08b7fd50e084fc61aa378f20018029a063f6630df48a42f138e592714c3cef4c5e70f6a1ec78d9350072d918e1203102a00c264fada9f62bc653c4e3fe807fd315274aaa8abd0626a7a51758be56a3b270")
}

func TestCreateEthereumTransactionBadNetwork(t *testing.T) {
	_, client := setUp(nil)
	ethTransaction := EthereumTransaction{
		Network: "ETH_BANANA",
	}
	_, err := client.CreateEthereumTransaction(&ethTransaction)
	assert.Error(t, err, "ethereum transactions can only be created on supported networks: map[ETC_MAINNET:true ETC_MORDEN:true ETH_MAINNET:true ETH_ROPSTEN:true]")
}

func TestGetAPIKey(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.GetAPIKey("banana")
	assert.NilError(t, err, "GetAPIKey should not return an error")
	expected := APIKey{
		ID:                    "YOQZNKYTUWTQ",
		Root:                  true,
		RegistrationTimestamp: 0,
		Nickname:              "banana",
	}
	assert.DeepEqual(t, resp.Response, expected)
}

func TestGetAPIKeyFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.GetAPIKey("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestListAPIKeys(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.ListAPIKeys()
	assert.NilError(t, err, "ListAPIKeys should not return an error")
	keys := resp.Response.(map[string]interface{})["keys"]
	expected := APIKey{
		RegistrationTimestamp: 0,
		Nickname:              "banana",
		Root:                  true,
		ID:                    "YOQZNKYTUWTQ",
	}
	assert.DeepEqual(t, keys.([]APIKey)[0], expected)
}

func TestListAPIKeysFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.ListAPIKeys()
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestCreateAPIKey(t *testing.T) {
	_, client := setUp(nil)
	apiKeyConfig := &APIKeyConfiguration{}
	resp, err := client.CreateAPIKey(apiKeyConfig)
	expected := APIKey{
		Key:                   "N4UuMzqFRt183ajXjR8P7goKNBqwRZ7ILKHUIcfNquu",
		ID:                    "VIUBMEGJKVRY",
		RegistrationTimestamp: 1560362013,
	}
	assert.NilError(t, err, "CreateAPIKey should not return an error")
	assert.DeepEqual(t, resp.Response, expected)
}

func TestCreateAPIKeyFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	apiKeyConfig := &APIKeyConfiguration{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.CreateAPIKey(apiKeyConfig)
	assert.Error(t, err, "this is a test error in Client.Post")
	assert.Assert(t, resp == nil)
}

func TestDeleteAPIKey(t *testing.T) {
	_, client := setUp(nil)
	resp, err := client.DeleteAPIKey("banana")
	expected := map[string]bool{
		"success": true,
	}
	assert.NilError(t, err, "DeleteAPIKey should not return an error")
	assert.DeepEqual(t, resp.Response, expected)
}

func TestDeleteAPIKeyFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.DeleteAPIKey("banana")
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}

func TestUpdateAPIKey(t *testing.T) {
	_, client := setUp(nil)
	apiKeyConfig := &APIKeyConfiguration{
		Nickname: "nickname",
	}
	resp, err := client.UpdateAPIKey("myKey", apiKeyConfig)
	expected := map[string]bool{
		"success": true,
	}
	assert.NilError(t, err, "UpdateAPIKey should not return an error")
	assert.DeepEqual(t, resp.Response, expected)
}

func TestUpdateAPIKeyRequestFails(t *testing.T) {
	fakeHTTPClient := &clientMock{}
	apiKeyConfig := &APIKeyConfiguration{}
	_, client := setUp(fakeHTTPClient)
	resp, err := client.UpdateAPIKey("keyID", apiKeyConfig)
	assert.Error(t, err, "this is a test error in Client.Do")
	assert.Assert(t, resp == nil)
}
