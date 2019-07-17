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

// Package dragonchain is used to interact programmatically with dragonchains.
package dragonchain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// MaxBulkPutSize is the configurable limit of how many txn can be included in a bulk operation.
const MaxBulkPutSize = 250

// Response defines the standard response all chains will use.
type Response struct {
	OK       bool        `json:"ok"`
	Status   int         `json:"status"`
	Response interface{} `json:"response"`
}

// Client defines the structure of the DragonchainSDK client.
type Client struct {
	creds      Authenticator
	apiBaseURL string

	httpClient httpClient
	ctx        context.Context
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
	CloseIdleConnections()
	Get(url string) (resp *http.Response, err error)
	Head(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
	PostForm(url string, data url.Values) (resp *http.Response, err error)
}

// NewClient creates a new instance of client. By default, it does not generate usable credentials.
// Accepts Authenticator credentials created using dragonchain.NewCredentials.
// apiBaseUrl is optional and for use when interacting with chains outside of the managed service.
// httpClient is optional if you wish to designate custom headers for requests.
func NewClient(creds Authenticator, apiBaseURL string, httpClient httpClient) *Client {
	if apiBaseURL == "" {
		apiBaseURL = fmt.Sprintf("https://%s.api.dragonchain.com", creds.GetDragonchainID())
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	client := &Client{
		creds:      creds,
		apiBaseURL: apiBaseURL,
		httpClient: httpClient,
	}

	return client
}

// GetSmartContractSecret pulls a secret for the running smart contract from the chain.
func (client *Client) GetSmartContractSecret(secretName string) (_ string, err error) {
	scID := os.Getenv("SMART_CONTRACT_ID")
	var path string
	// Allow users to specify their own paths
	if strings.Contains(secretName, "/") {
		path = secretName
	} else {
		path = fmt.Sprintf("/var/openfaas/secrets/sc-%s-%s", scID, secretName)
	}

	file, err := os.Open(path)
	defer func() {
		file.Close()
	}()
	if err == nil {
		return parseSecret(file)
	}
	return "", err
}

// parseSecret does the actual work of reading the secret. The functions are separated for testability.
func parseSecret(reader io.Reader) (string, error) {
	b, readErr := ioutil.ReadAll(reader)
	return string(b), readErr
}

// GetStatus returns the chain's status, such as Active or Updating.
func (client *Client) GetStatus() (*Response, error) {
	path := "/status"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}

	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	return resp, err
}

// QuerySmartContracts returns a list of matching contracts on the chain.
func (client *Client) QuerySmartContracts(query *Query) (*Response, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}

	buildQuery(req, query)
	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to []Contract for the user.
	var raw map[string]interface{}
	err = json.Unmarshal(resp.Response.([]byte), &raw)
	if err != nil {
		return nil, err
	}
	contractJSON, err := json.Marshal(raw["results"])
	if err != nil {
		return nil, err
	}
	var contract []Contract
	if err := json.Unmarshal(contractJSON, &contract); err != nil {
		return nil, err
	}

	resp.Response = make(map[string][]Contract)
	resp.Response.(map[string][]Contract)["results"] = contract
	return resp, err
}

// GetSmartContract returns details on a smart contract by ID or transactionType.
// If both contractID and transactionType are provided, contractID is used.
func (client *Client) GetSmartContract(smartContractID, transactionType string) (*Response, error) {
	var err error
	var uri string
	if smartContractID == "" && transactionType == "" {
		return nil, errors.New("invalid parameters: you must provide one of smartContractID or transactionType")
	} else if smartContractID != "" {
		path := "/contract"
		uri = fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, smartContractID)
	} else if transactionType != "" {
		path := "/contract/txn_type"
		uri = fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, transactionType)
	}
	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	var contract Contract
	if err := json.Unmarshal(resp.Response.([]byte), &contract); err != nil {
		return nil, err
	}
	resp.Response = contract
	return resp, err
}

// CreateSmartContract creates a new smart contract on the chain.
func (client *Client) CreateSmartContract(contract *ContractConfiguration) (_ *Response, err error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	b, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(uri, "content/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var statusMessage []byte
	statusMessage, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	response := Response{
		Response: statusMessage,
		Status:   resp.StatusCode,
		OK:       200 <= resp.StatusCode && 300 > resp.StatusCode,
	}
	return &response, err
}

// UpdateSmartContract updates an existing contract with a new configuration.
// Configuration details that aren't provided will not be changed.
func (client *Client) UpdateSmartContract(contract *ContractConfiguration) (*Response, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	b, err := json.Marshal(contract)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, b)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// DeleteContract removes a contract from the chain.
func (client *Client) DeleteContract(smartContractID string) (*Response, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, smartContractID)
	req, err := http.NewRequest("DELETE", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetTransaction gets a transaction from the chain by id.
func (client *Client) GetTransaction(txnID string) (*Response, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, txnID)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to Transaction for the user.
	var txn Transaction
	if err := json.Unmarshal(resp.Response.([]byte), &txn); err != nil {
		return nil, err
	}
	resp.Response = txn
	return resp, err
}

// CreateTransaction creates a transaction on the chain.
func (client *Client) CreateTransaction(txn *CreateTransaction) (_ *Response, err error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	b, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, b)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to Transaction for the user.
	var transaction CreateTransactionResponse
	if err := json.Unmarshal(resp.Response.([]byte), &transaction); err != nil {
		return nil, err
	}
	resp.Response = transaction
	return resp, err
}

// CreateBulkTransaction sends many transactions to a chain in a single HTTP request.
func (client *Client) CreateBulkTransaction(txn []*CreateTransaction) (_ *Response, err error) {
	path := "/transaction_bulk"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	if len(txn) > MaxBulkPutSize {
		return nil, ErrMaxBulkSizeExceeded
	}

	txnBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(txnBytes))
	if err != nil {
		return nil, err
	}

	resp, err := client.performRequest(req, txnBytes)
	if err != nil {
		return nil, err
	}

	var response CreateBulkTransactionResponse
	if err := json.Unmarshal(resp.Response.([]byte), &response); err != nil {
		return nil, err
	}

	resp.Response = response

	return resp, err
}

// QueryBlocks gets all blocks matching the given query.
func (client *Client) QueryBlocks(query *Query) (*Response, error) {
	path := "/block"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	buildQuery(req, query)
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	var results map[string][]Block
	err = json.Unmarshal(resp.Response.([]byte), &results)
	if err != nil {
		return nil, err
	}
	resp.Response = results
	return resp, err
}

// GetBlock returns a block by ID.
func (client *Client) GetBlock(blockID string) (*Response, error) {
	path := "/block"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, blockID)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	var block Block
	if err := json.Unmarshal(resp.Response.([]byte), &block); err != nil {
		return nil, err
	}
	resp.Response = block
	return resp, err
}

// GetVerifications returns a block's verification at a specific level of DragonNet.
func (client *Client) GetVerifications(blockID string, level int) (*Response, error) {
	path := "/verifications"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, blockID)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	if level > 0 {
		q := req.URL.Query()
		q.Add("level", string(level))
		req.URL.RawQuery = q.Encode()
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to Verification for the user.
	if level > 0 {
		var verificationBlocks []Block
		if err := json.Unmarshal(resp.Response.([]byte), &verificationBlocks); err != nil {
			return nil, err
		}
		resp.Response = verificationBlocks
	} else {
		var verification Verification
		if err := json.Unmarshal(resp.Response.([]byte), &verification); err != nil {
			return nil, err
		}
		resp.Response = verification
	}
	return resp, err
}

// QueryTransactions gets all transactions matching the given query on the chain.
func (client *Client) QueryTransactions(query *Query) (*Response, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	buildQuery(req, query)
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetSmartContractObject returns a specific key from a smart contract's heap.
// If SCName is not provided, the SDK will try to pull it from the environment.
func (client *Client) GetSmartContractObject(key, smartContractID string) (*Response, error) {
	if len(smartContractID) == 0 {
		smartContractID = os.Getenv("SMART_CONTRACT_ID")
	}

	if len(key) == 0 {
		return nil, errors.New("key can not be empty")
	}

	path := "/get"
	uri := fmt.Sprintf("%s%s/%s/%s", client.apiBaseURL, path, smartContractID, key)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// ListSmartContractObjects lists out all keys from a smart contract's heap.
// Optionally, folder can be provided to only list a subset of keys.
func (client *Client) ListSmartContractObjects(folder, smartContractID string) (*Response, error) {
	if len(smartContractID) == 0 {
		smartContractID = os.Getenv("SMART_CONTRACT_ID")
	}

	path := "/list"
	uri := fmt.Sprintf("%s%s/%s/", client.apiBaseURL, path, smartContractID)
	body := []byte("")

	if len(folder) > 0 {
		if strings.HasSuffix(folder, "/") {
			return nil, errors.New("folder can not end with '/'")
		}
		uri = fmt.Sprintf("%s%s", uri, folder)
	}

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetTransactionType returns a transaction type on chain by its name.
func (client *Client) GetTransactionType(transactionType string) (*Response, error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, transactionType)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	var txnType TransactionType
	if err := json.Unmarshal(resp.Response.([]byte), &txnType); err != nil {
		return nil, err
	}
	resp.Response = txnType
	return resp, err
}

// ListTransactionTypes lists out all registered transaction types for a chain.
func (client *Client) ListTransactionTypes() (*Response, error) {
	path := "/transaction-types"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	var txnTypes map[string][]TransactionType
	if err := json.Unmarshal(resp.Response.([]byte), &txnTypes); err != nil {
		return nil, err
	}
	resp.Response = txnTypes
	return resp, err
}

// UpdateTransactionType updates a given transaction type.
func (client *Client) UpdateTransactionType(transactionType string, customIndexes []CustomIndexStructure) (*Response, error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, transactionType)
	var params TransactionType
	params.Version = "1"
	params.CustomIndexes = customIndexes

	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, b)
	if err != nil {
		return nil, err
	}
	var success map[string]bool
	if err := json.Unmarshal(resp.Response.([]byte), &success); err != nil {
		return nil, err
	}
	resp.Response = success
	return resp, err
}

// CreateTransactionType creates a new transaction type.
func (client *Client) CreateTransactionType(transactionType string, customIndexes []CustomIndexStructure) (_ *Response, err error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	var params TransactionType
	params.Version = "1"
	params.Type = transactionType
	if len(customIndexes) > 0 {
		params.CustomIndexes = customIndexes
	}

	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	resp, err := client.performRequest(req, b)
	if err != nil {
		return nil, err
	}

	var success map[string]bool
	if err := json.Unmarshal(resp.Response.([]byte), &success); err != nil {
		return nil, err
	}

	resp.Response = success

	return resp, err
}

// DeleteTransactionType removes the specified transaction type. It will not affect transactions that have already been processed.
func (client *Client) DeleteTransactionType(transactionType string) (*Response, error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, transactionType)

	req, err := http.NewRequest("DELETE", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	var success map[string]bool
	if err := json.Unmarshal(resp.Response.([]byte), &success); err != nil {
		return nil, err
	}
	resp.Response = success
	return resp, err
}

// GetPublicBlockchainAddress returns a dictionary of this chain's interchain addresses.
// This method is only supported on L1 and L5 chains.
func (client *Client) GetPublicBlockchainAddress() (*Response, error) {
	path := "/public-blockchain-address"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	var addresses map[string]string
	if err := json.Unmarshal(resp.Response.([]byte), &addresses); err != nil {
		return nil, err
	}
	resp.Response = addresses
	return resp, err
}

// CreateBitcoinTransaction creates an interchain btc transaction using this chain's interchain address.
func (client *Client) CreateBitcoinTransaction(btcTransaction *BitcoinTransaction) (*Response, error) {
	if !BitcoinNetworks[btcTransaction.Network] {
		return nil, fmt.Errorf("bitcoin transactions can only be created on supported networks: %+v", BitcoinNetworks)
	}
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/public-blockchain-transaction")
	btcTransactionRequest := bitcoinBackEndTransaction{
		Network: btcTransaction.Network,
		Transaction: bitcoinTransactionWithoutNetwork{
			SatoshisPerByte: btcTransaction.SatoshisPerByte,
			Data:            btcTransaction.Data,
			ChangeAddress:   btcTransaction.ChangeAddress,
			Outputs:         btcTransaction.Outputs,
		},
	}

	b, err := json.Marshal(btcTransactionRequest)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(uri, "content/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var chainResp Response
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var signed map[string]string
	if err := json.Unmarshal(bytes, &signed); err != nil {
		return nil, err
	}
	chainResp.Response = signed
	chainResp.Status = resp.StatusCode
	if 200 <= resp.StatusCode && resp.StatusCode < 300 {
		chainResp.OK = true
	}
	return &chainResp, err
}

// CreateEthereumTransaction creates an interchain eth transaction using this chain's interchain address.
func (client *Client) CreateEthereumTransaction(ethTransaction *EthereumTransaction) (*Response, error) {
	if !EthereumNetworks[ethTransaction.Network] {
		return nil, fmt.Errorf("ethereum transactions can only be created on supported networks: %+v", EthereumNetworks)
	}
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/public-blockchain-transaction")
	ethTransactionRequest := ethereumBackEndTransaction{
		Network: ethTransaction.Network,
		Transaction: ethereumTransactionWithoutNetwork{
			To:       ethTransaction.To,
			Value:    ethTransaction.Value,
			Data:     ethTransaction.Data,
			GasPrice: ethTransaction.GasPrice,
			Gas:      ethTransaction.Gas,
		},
	}

	b, err := json.Marshal(ethTransactionRequest)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(uri, "content/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var chainResp Response
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var signed map[string]string
	if err := json.Unmarshal(bytes, &signed); err != nil {
		return nil, err
	}
	chainResp.Response = signed
	chainResp.Status = resp.StatusCode
	if 200 <= resp.StatusCode && resp.StatusCode < 300 {
		chainResp.OK = true
	}
	return &chainResp, err
}

// GetAPIKey returns an HMAC API key.
func (client *Client) GetAPIKey(keyID string) (*Response, error) {
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, "/api-key", keyID)
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	var key APIKey
	if err := json.Unmarshal(resp.Response.([]byte), &key); err != nil {
		return nil, err
	}
	resp.Response = key
	return resp, err
}

// ListAPIKeys for a chain.
func (client *Client) ListAPIKeys() (*Response, error) {
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/api-key")
	body := []byte("")

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, body)
	if err != nil {
		return nil, err
	}
	apiKeyList := make(map[string][]APIKey)
	if err := json.Unmarshal(resp.Response.([]byte), &apiKeyList); err != nil {
		return nil, err
	}
	resp.Response = apiKeyList
	return resp, err
}

// CreateAPIKey to access chain with.
func (client *Client) CreateAPIKey(configuration *APIKeyConfiguration) (*Response, error) {
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/api-key")
	b, err := json.Marshal(configuration)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	resp, err := client.performRequest(req, b)
	if err != nil {
		return nil, err
	}
	var apiKey APIKey
	if err := json.Unmarshal(resp.Response.([]byte), &apiKey); err != nil {
		return nil, err
	}
	resp.Response = apiKey

	return resp, err
}

// UpdateAPIKey to update api key nickname
func (client *Client) UpdateAPIKey(KeyID string, configuration *APIKeyConfiguration) (*Response, error) {
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, "/api-key", KeyID)
	b, err := json.Marshal(configuration)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	resp, err := client.performRequest(req, b)
	if err != nil {
		return nil, err
	}
	var success map[string]bool
	if err := json.Unmarshal(resp.Response.([]byte), &success); err != nil {
		return nil, err
	}
	resp.Response = success
	return resp, err
}

// DeleteAPIKey from chain.
func (client *Client) DeleteAPIKey(keyID string) (*Response, error) {
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, "/api-key")
	req, err := http.NewRequest("DELETE", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req, []byte(""))
	if err != nil {
		return nil, err
	}
	var success map[string]bool
	if err := json.Unmarshal(resp.Response.([]byte), &success); err != nil {
		return nil, err
	}
	resp.Response = success
	return resp, err
}

// setHeaders sets the http headers of a request to the chain with proper authorization.
func (client *Client) setHeaders(req *http.Request, httpVerb, path, contentType string, content []byte) error {
	if client.creds == nil {
		return ErrNoCredentials
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	if len(contentType) > 0 {
		req.Header.Set("Content-Type", contentType)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Dragonchain", client.creds.GetDragonchainID())
	req.Header.Set("Timestamp", fmt.Sprintf("%s", now))
	req.Header.Set("Authorization", client.creds.GetAuthorization(httpVerb, path, now, contentType, content))
	return nil
}

func (client *Client) performRequest(req *http.Request, body []byte) (*Response, error) {
	err := client.setHeaders(req, req.Method, req.URL.RequestURI(), "application/json", body)
	if err != nil {
		return nil, err
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	var chainResp Response
	chainResp.Response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	chainResp.Status = resp.StatusCode
	if 200 <= resp.StatusCode && resp.StatusCode < 300 {
		chainResp.OK = true
	}
	return &chainResp, err
}

func buildQuery(req *http.Request, query *Query) {
	if query == nil {
		return
	}
	q := req.URL.Query()
	q.Add("q", query.Query)
	if query.Sort != "" {
		q.Add("sort", query.Sort)
	}
	if query.Limit != 0 {
		q.Add("limit", string(query.Limit))
	}
	if query.Offset != 0 {
		q.Add("offset", string(query.Offset))
	}
	req.URL.RawQuery = q.Encode()
}
