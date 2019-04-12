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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

// MaxBulkPutSize is the configurable limit of how many txn can be included in a bulk operation.
const MaxBulkPutSize = 250

// TODO: Move these into a query response file? Don't belong here, not sure where they belong.
type postTransactionResponse struct {
	TransactionID string `json:"transaction_id"`
}

type postBulkTransactionResponse struct {
	TransactionIDs []string           `json:"201"`
	Failed         []*PostTransaction `json:"400"`
}

type searchTransactionResponse struct {
	Results []*Transaction `json:"results"`
}

type searchBlockResponse struct {
	Results []*Block `json:"results"`
}

// Client defines the structure of the DragonchainSDK client.
type Client struct {
	creds      Authenticator
	apiBaseURL string

	httpClient *http.Client
	ctx        context.Context
}

// NewClient creates a new instance of client. By default, it does not generate usable credentials.
// Accepts Authenticator credentials created using dragonchain.NewCredentials.
// apiBaseUrl is optional and for use when interacting with chains outside of the managed service.
// httpClient is optional if you wish to designate custom headers for requests.
func NewClient(creds Authenticator, apiBaseURL string, httpClient *http.Client) *Client {
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
func (client *Client) OverrideCredentials(creds Authenticator, apiBaseURL string, httpClient *http.Client) {
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
func (client *Client) GetSecret(secretName, scID string) (string, error) {
	if scID == "" {
		scID = os.Getenv("SMART_CONTRACT_ID")
	}

	path := fmt.Sprintf("/var/openfaas/secrets/sc-%s-%s", scID, secretName)
	file, err := os.Open(path)
	if err == nil {
		b, readErr := ioutil.ReadAll(file)
		return string(b), readErr
	}
	return "", err
}

// GetStatus returns the chain's status, such as Active or Updating.
func (client *Client) GetStatus() (string, error) {
	path := "/status"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return "", err
	}
	resp, err := client.performRequest(req)
	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

// QueryContracts returns a list of matching contracts on the chain.
func (client *Client) QueryContracts(query *Query) (string, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return "", err
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
	resp, err := client.performRequest(req)
	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

// GetSmartContract returns details on a smart contract by ID or txnType.
// If both contractID and txnType are provided, contractID is used.
// TODO: dry this method out. Ask David.
func (client *Client) GetSmartContract(contractID, txnType string) (string, error) {
	if contractID != "" {
		path := "/contract"
		uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, contractID)
		req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
		if err != nil {
			return "", err
		}
		resp, err := client.performRequest(req)
		msg, err := ioutil.ReadAll(resp.Body)
		return string(msg), err
	} else if txnType != "" {
		path := "/contract/txn_type"
		uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, txnType)
		req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
		if err != nil {
			return "", err
		}
		resp, err := client.performRequest(req)
		msg, err := ioutil.ReadAll(resp.Body)
		return string(msg), err
	}
	return "", errors.New("invalid parameters: you must provide one of contractID or txnType")
}

// PostContract creates a new smart contract on the chain.
func (client *Client) PostContract(contract *ContractConfiguration) (string, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	b, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	resp, err := client.performRequest(req)
	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

// UpdateContract updates an existing contract with a new configuration.
// Configuration details that aren't provided will not be changed.
func (client *Client) UpdateContract(contract *ContractConfiguration) (string, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)
	b, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("PUT", uri, bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	resp, err := client.performRequest(req)
	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

// DeleteContract removes a contract from the chain.
func (client *Client) DeleteContract(contractID string) (string, error) {
	path := "/contract"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, contractID)
	req, err := http.NewRequest("DELETE", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return "", err
	}
	resp, err := client.performRequest(req)
	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

// GetTransaction gets a transaction from the chain by id.
func (client *Client) GetTransaction(txnID string) (*Transaction, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, txnID)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(resp.Body)

	var respData Transaction
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return &respData, nil
}

// PostTransaction creates a transaction on the chain.
func (client *Client) PostTransaction(txn *PostTransaction) (string, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	b, err := json.Marshal(txn)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	resp, err := client.performRequest(req)
	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

// PostTransactionBulk sends many transactions to a chain in a single HTTP request.
func (client *Client) PostTransactionBulk(txn []*PostTransaction) ([]string, []*PostTransaction, error) {
	path := "/transaction_bulk"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	if len(txn) > MaxBulkPutSize {
		return nil, nil, ErrMaxBulkSizeExceeded
	}

	txnBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(txnBytes))
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, nil, err
	}

	decoder := json.NewDecoder(resp.Body)

	var respData postBulkTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, nil, err
	}

	return respData.TransactionIDs, respData.Failed, nil
}

// QueryBlocks gets all blocks matching the given query.
func (client *Client) QueryBlocks(query *Query) ([]*Block, error) {
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

	decoder := json.NewDecoder(resp.Body)

	var respData searchBlockResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData.Results, nil
}

// GetBlock returns a block by ID.
func (client *Client) GetBlock(blockID string) (*Block, error) {
	path := "/block"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, blockID)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	decoder := json.NewDecoder(resp.Body)
	var block Block
	err = decoder.Decode(&block)
	if err != nil {
		return nil, err
	}

	return &block, nil
}

// GetVerification returns a block's verification at a specific level of DragonNet.
func (client *Client) GetVerification(blockID string, level int) (*L1Verification, error) {
	path := "/verifications"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseURL, path, blockID)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}
	if level > 0 {
		q := req.URL.Query()
		q.Add("level", string(level))
	}
	resp, err := client.performRequest(req)
	decoder := json.NewDecoder(resp.Body)
	var verification L1Verification
	err = decoder.Decode(&verification)
	if err != nil {
		return nil, err
	}

	return &verification, nil
}

// QueryTransactions gets all transactions matching the given query on the chain.
func (client *Client) QueryTransactions(query *Query) ([]*Transaction, error) {
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

	decoder := json.NewDecoder(resp.Body)

	var respData searchTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData.Results, nil
}

// GetSCHeap returns a specific key from a smart contract's heap.
// If SCName is not provided, the SDK will try to pull it from the environment.
func (client *Client) GetSCHeap(scID, key string) (io.Reader, error) {
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

	return resp.Body, nil
}

// ListSCHeap lists out all keys from a smart contract's heap.
// Optionally, folder can be provided to only list a subset of keys.
func (client *Client) ListSCHeap(scID, folder string) ([]string, error) {
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

	decoder := json.NewDecoder(resp.Body)

	var respData []string
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData, nil
}

// GetTransactionType returns a transaction type on chain by its name.
func (client *Client) GetTransactionType(transactionType string) (*TransactionType, error) {
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
	decoder := json.NewDecoder(resp.Body)
	var respData TransactionType
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return &respData, nil
}

// ListTransactionTypes lists out all registered transaction types for a chain.
func (client *Client) ListTransactionTypes() ([]TransactionType, error) {
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
	decoder := json.NewDecoder(resp.Body)
	var respData []TransactionType
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData, nil
}

// UpdateTransactionType updates a given transaction type.
func (client *Client) UpdateTransactionType(transactionType string, customIndexes []CustomIndexStructure) (*http.Response, error) {
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
	return resp, nil
}

// RegisterTransactionType creates a new transaction type.
func (client *Client) RegisterTransactionType(transactionType string, customIndexes []CustomIndexStructure) (*http.Response, error) {
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

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	resp, err := client.performRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// DeleteTransactionType removes the specified transaction type. It will not affect transactions that have already been processed.
func (client *Client) DeleteTransactionType(transactionType string) (*http.Response, error) {
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
	return resp, nil
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

func (client *Client) performRequest(req *http.Request) (*http.Response, error) {
	client.setHeaders(req, req.Method, req.URL.RequestURI(), "application/json", "")
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != http.StatusCreated {
		return resp, NewRequestError(resp)
	}
	return resp, err
}

func buildQuery(req *http.Request, query *Query) {
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
