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

const (
	// MaxBulkPutSize is the configurable limit of how many txn can be included in a bulk operation.
	MaxBulkPutSize = 250
)

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

// Client defines the structure of the DragonchainSDK client.
type Client struct {
	creds      Authenticator
	apiBaseURL string

	httpClient *http.Client
	ctx        context.Context
}

// NewClient creates a new instance of client.
// Requires Authenticator credentials to already have been created using dragonchain.NewCredentials.
// apiBaseUrl is optional and for use when interacting with chains outside of the managed service.
// httpClient is also optional, for if you wish to designate custom headers to apply to requests.
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

// setHeaders sets the http headers of a request to the chain with proper authorization.
func (client *Client) setHeaders(req *http.Request, httpVerb, path, contentType, content string) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	if len(contentType) > 0 {
		req.Header.Set("Content-Type", contentType)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Dragonchain", client.creds.GetDragonchainID())
	req.Header.Set("Timestamp", fmt.Sprintf("%s", now))
	req.Header.Set("Authorization", client.creds.GetAuthorization(httpVerb, path, now, contentType, content))
}

// GetSmartContractHeap gets data from a given smart contract's heap.
// If SCName is not provided, the go-sdk will try to pull it from the environment.
func (client *Client) GetSmartContractHeap(getHeap *GetSmartContractHeap) (string, error) {
	if getHeap.SCName == "" {
		getHeap.SCName = os.Getenv("SMART_CONTRACT_ID")
	}
	path := fmt.Sprintf("/get/%s/%s", getHeap.SCName, getHeap.Key)
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return "", err
	}

	client.setHeaders(req, "GET", req.URL.RequestURI(), "application/json", "")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", NewRequestError(resp)
	}

	return "", err
}

// PostTransaction to a chain.
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

	client.setHeaders(req, "POST", path, "application/json", string(b))

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", NewRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData postTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return "", err
	}

	return respData.TransactionID, nil
}

// PostBulkTransactions sends many transactions to a chain in a single HTTP request.
func (client *Client) PostBulkTransactions(trans []*PostTransaction) ([]string, []*PostTransaction, error) {
	path := "/transaction_bulk"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	if len(trans) > MaxBulkPutSize {
		return nil, nil, ErrMaxBulkSizeExceeded
	}

	trainsBytes, err := json.Marshal(trans)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(trainsBytes))
	if err != nil {
		return nil, nil, err
	}

	client.setHeaders(req, "POST", path, "application/json", string(trainsBytes))

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusMultiStatus {
		return nil, nil, NewRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData postBulkTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, nil, err
	}

	return respData.TransactionIDs, respData.Failed, nil
}

// Status returns the chain's status, such as Active or Updating.
func (client *Client) Status() (string, error) {
	path := "/status"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return "", err
	}

	client.setHeaders(req, "GET", req.URL.RequestURI(), "application/json", "")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", NewRequestError(resp)
	}

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

	client.setHeaders(req, "GET", req.URL.RequestURI(), "application/json", "")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, NewRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData Transaction
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return &respData, nil
}

// QueryTransactions gets all transactions matching the given query on the chain.
func (client *Client) QueryTransactions(query *Query) ([]*Transaction, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseURL, path)

	req, err := http.NewRequest("GET", uri, bytes.NewBuffer([]byte("")))
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("q", query.Query)

	req.URL.RawQuery = q.Encode()

	client.setHeaders(req, "GET", req.URL.RequestURI(), "application/json", "")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, NewRequestError(resp)
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

	client.setHeaders(req, "GET", req.URL.RequestURI(), "application/json", "")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, NewRequestError(resp)
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

	client.setHeaders(req, "GET", req.URL.RequestURI(), "application/json", "")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, NewRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData []string
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData, nil
}
