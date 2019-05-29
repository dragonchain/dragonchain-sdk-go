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

// OverrideCredentials changes the creds, apiBaseURL, and httpClient of an existing DragonchainSDK Client.
func (client *Client) OverrideCredentials(creds Authenticator, apiBaseURL string, httpClient httpClient) {
	if creds != nil {
		client.creds = creds
		client.apiBaseURL = fmt.Sprintf("https://%s.api.dragonchain.com", creds.GetDragonchainID())
	}
	if apiBaseURL != "" {
		client.apiBaseURL = apiBaseURL
	}
	if httpClient != nil {
		client.httpClient = httpClient
	}
}

// GetSecret pulls a secret for a smart contract from the chain.
// If scID is not provided, the SDK will attempt to pull it from the environment.
func (client *Client) GetSecret(secretName, scID string) (_ string, err error) {
	if scID == "" {
		scID = os.Getenv("SMART_CONTRACT_ID")
	}
	var path string
	// Allow users to specify their own paths
	if strings.Contains(secretName, "/") {
		path = secretName
	} else {
		path = fmt.Sprintf("/var/openfaas/secrets/sc-%s-%s", scID, secretName)
	}

	file, err := os.Open(path)
	defer func() {
		err = file.Close()
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

	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// QueryContracts returns a list of matching contracts on the chain.
func (client *Client) QueryContracts(query *Query) (*Response, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}

	buildQuery(req, query)
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetSmartContract returns details on a smart contract by ID or txnType.
// If both contractID and txnType are provided, contractID is used.
func (client *Client) GetSmartContract(contractID, txnType string) (*Response, error) {
	var err error
	var uri string
	if contractID == "" && txnType == "" {
		return nil, errors.New("invalid parameters: you must provide one of contractID or txnType")
	} else if contractID != "" {
		path := "/contract"
		uri = fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, contractID)
	} else if txnType != "" {
		path := "/contract/txn_type"
		uri = fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, txnType)
	}
	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to Contract for the user.
	raw, err := json.Marshal(resp.Response)
	if err != nil {
		return nil, err
	}
	var contract Contract
	if err := json.Unmarshal(raw, &contract); err != nil {
		return nil, err
	}
	resp.Response = contract
	return resp, err
}

// PostContract creates a new smart contract on the chain.
func (client *Client) PostContract(contract *ContractConfiguration) (_ *Response, err error) {
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
	defer func() {
		err = resp.Body.Close()
	}()
	decoder := json.NewDecoder(resp.Body)
	var chainResp Response
	err = decoder.Decode(&chainResp)
	if err != nil {
		return nil, err
	}
	return &chainResp, err
}

// UpdateContract updates an existing contract with a new configuration.
// Configuration details that aren't provided will not be changed.
func (client *Client) UpdateContract(contract *ContractConfiguration) (*Response, error) {
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
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// DeleteContract removes a contract from the chain.
func (client *Client) DeleteContract(contractID string) (*Response, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, contractID)
	req, err := http.NewRequest("DELETE", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetTransaction gets a transaction from the chain by id.
func (client *Client) GetTransaction(txnID string) (*Response, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, txnID)
	fmt.Println(uri)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
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

// PostTransaction creates a transaction on the chain.
func (client *Client) PostTransaction(txn *PostTransaction) (_ *Response, err error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	b, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(uri, "content/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
	}()
	decoder := json.NewDecoder(resp.Body)
	var chainResp Response
	err = decoder.Decode(&chainResp)
	if err != nil {
		return nil, err
	}
	return &chainResp, err
}

// PostTransactionBulk sends many transactions to a chain in a single HTTP request.
func (client *Client) PostTransactionBulk(txn []*PostTransaction) (_ *Response, err error) {
	path := "/transaction_bulk"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	if len(txn) > MaxBulkPutSize {
		return nil, ErrMaxBulkSizeExceeded
	}

	txnBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(uri, "content/json", bytes.NewBuffer(txnBytes))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
	}()
	decoder := json.NewDecoder(resp.Body)
	var chainResp Response
	err = decoder.Decode(&chainResp)
	if err != nil {
		return nil, err
	}
	return &chainResp, err
}

// QueryBlocks gets all blocks matching the given query.
func (client *Client) QueryBlocks(query *Query) (*Response, error) {
	path := "/block"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	buildQuery(req, query)
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetBlock returns a block by ID.
func (client *Client) GetBlock(blockID string) (*Response, error) {
	path := "/block"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, blockID)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to Block for the user.
	raw, err := json.Marshal(resp.Response)
	if err != nil {
		return nil, err
	}
	var block Block
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, err
	}
	resp.Response = block
	return resp, err
}

// GetVerification returns a block's verification at a specific level of DragonNet.
func (client *Client) GetVerification(blockID string, level int) (*Response, error) {
	path := "/verifications"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, blockID)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	if level > 0 {
		q := req.URL.Query()
		q.Add("level", string(level))
		req.URL.RawQuery = q.Encode()
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to Verification for the user.
	if level > 0 {
		raw, err := json.Marshal(resp.Response)
		if err != nil {
			return nil, err
		}
		var verificationBlocks []Block
		if err := json.Unmarshal(raw, &verificationBlocks); err != nil {
			return nil, err
		}
		resp.Response = verificationBlocks
	} else {
		raw, err := json.Marshal(resp.Response)
		if err != nil {
			return nil, err
		}
		var verification Verification
		if err := json.Unmarshal(raw, &verification); err != nil {
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

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}

	buildQuery(req, query)
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetSCHeap returns a specific key from a smart contract's heap.
// If SCName is not provided, the SDK will try to pull it from the environment.
func (client *Client) GetSCHeap(scID, key string) (*Response, error) {
	if len(scID) == 0 {
		scID = os.Getenv("SMART_CONTRACT_ID")
	}

	if len(key) == 0 {
		return nil, errors.New("key can not be empty")
	}

	path := "/get"
	uri := fmt.Sprintf("%s%s/%s/%s", client.apiBaseURL, path, scID, key)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// ListSCHeap lists out all keys from a smart contract's heap.
// Optionally, folder can be provided to only list a subset of keys.
func (client *Client) ListSCHeap(scID, folder string) (*Response, error) {
	if len(scID) == 0 {
		scID = os.Getenv("SMART_CONTRACT_ID")
	}

	path := "/list"
	uri := fmt.Sprintf("%s%s/%s/", client.apiBaseURL, path, scID)

	if len(folder) > 0 {
		if strings.HasSuffix(folder, "/") {
			return nil, errors.New("folder can not end with '/'")
		}
		uri = fmt.Sprintf("%s%s", uri, folder)
	}

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// GetTransactionType returns a transaction type on chain by its name.
func (client *Client) GetTransactionType(transactionType string) (*Response, error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, transactionType)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	// Handle conversion of Response from an interface{} to TransactionType for the user.
	raw, err := json.Marshal(resp.Response)
	if err != nil {
		return nil, err
	}
	var txnType TransactionType
	if err := json.Unmarshal(raw, &txnType); err != nil {
		return nil, err
	}
	resp.Response = txnType
	return resp, err
}

// ListTransactionTypes lists out all registered transaction types for a chain.
func (client *Client) ListTransactionTypes() (*Response, error) {
	path := "/transaction-types"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
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
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// RegisterTransactionType creates a new transaction type.
func (client *Client) RegisterTransactionType(transactionType string, customIndexes []CustomIndexStructure) (_ *Response, err error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	var params TransactionType
	params.Version = "1"
	params.Type = transactionType
	params.CustomIndexes = customIndexes

	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(uri, "content/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
	}()
	decoder := json.NewDecoder(resp.Body)
	var chainResp Response
	err = decoder.Decode(&chainResp)
	if err != nil {
		return nil, err
	}
	return &chainResp, err
}

// DeleteTransactionType removes the specified transaction type. It will not affect transactions that have already been processed.
func (client *Client) DeleteTransactionType(transactionType string) (*Response, error) {
	path := "/transaction-type"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, transactionType)

	req, err := http.NewRequest("DELETE", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// setHeaders sets the http headers of a request to the chain with proper authorization.
func (client *Client) setHeaders(req *http.Request, httpVerb, path, contentType, content string) error {
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

func (client *Client) performRequest(req *http.Request) (*Response, error) {
	err := client.setHeaders(req, req.Method, req.URL.RequestURI(), "application/json", "")
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
