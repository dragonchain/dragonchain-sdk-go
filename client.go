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
	MaxBulkPutSize = 250
)

type postTransactionResponse struct {
	TransactionId string `json:"transaction_id"`
}

type postBulkTransactionResponse struct {
	TransactionIds []string           `json:"201"`
	Failed         []*PostTransaction `json:"400"`
}

type searchTransactionResponse struct {
	Results []*Transaction `json:"results"`
}

type Client struct {
	creds      Authenticator
	apiBaseUrl string

	httpClient *http.Client
	ctx        context.Context
}

func NewClient(ctx context.Context, creds Authenticator, apiBaseUrl string, httpClient *http.Client) *Client {
	client := &Client{
		creds:      creds,
		apiBaseUrl: apiBaseUrl,
		httpClient: httpClient,
		ctx:        ctx,
	}

	return client
}

func (client *Client) setHeaders(req *http.Request, httpVerb, path, contentType, content string) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")

	if len(contentType) > 0 {
		req.Header.Set("Content-Type", contentType)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Dragonchain", client.creds.GetDragonchainId())
	req.Header.Set("Timestamp", fmt.Sprintf("%s", now))
	req.Header.Set("Authorization", client.creds.GetAuthorization(httpVerb, path, now, contentType, content))
}

func (client *Client) GetSmartContractHeap(ctx context.Context, trans *GetSmartContractHeap) (string, error) {
	path := fmt.Sprintf("/get/%s/%s", trans.SCName, trans.Key)
	uri := fmt.Sprintf("%s%s", client.apiBaseUrl, path)

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
		return "", NewDCRequestError(resp)
	}

	return "", err
}

func (client *Client) PostTransaction(ctx context.Context, trans *PostTransaction) (string, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseUrl, path)

	trainsBytes, err := json.Marshal(trans)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(trainsBytes))
	if err != nil {
		return "", err
	}

	client.setHeaders(req, "POST", path, "application/json", string(trainsBytes))

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", NewDCRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData postTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return "", err
	}

	return respData.TransactionId, nil
}

func (client *Client) PostTemp(ctx context.Context, trans *PostTempTransaction) (string, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseUrl, path)

	trainsBytes, err := json.Marshal(trans)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(trainsBytes))
	if err != nil {
		return "", err
	}

	client.setHeaders(req, "POST", path, "application/json", string(trainsBytes))

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", NewDCRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData postTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return "", err
	}

	return respData.TransactionId, nil
}

func (client *Client) PostBulkTransactions(trans []*PostTransaction) ([]string, []*PostTransaction, error) {
	path := "/transaction_bulk"
	uri := fmt.Sprintf("%s%s", client.apiBaseUrl, path)

	if len(trans) > MaxBulkPutSize {
		return nil, nil, MaxBulkSizeError
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
		return nil, nil, NewDCRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData postBulkTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, nil, err
	}

	return respData.TransactionIds, respData.Failed, nil
}

func (client *Client) Status() (string, error) {
	path := "/status"
	uri := fmt.Sprintf("%s%s", client.apiBaseUrl, path)

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
		return "", NewDCRequestError(resp)
	}

	msg, err := ioutil.ReadAll(resp.Body)
	return string(msg), err
}

func (client *Client) GetTransaction(transId string) (*Transaction, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s/%s", client.apiBaseUrl, path, transId)

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
		return nil, NewDCRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData Transaction
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return &respData, nil
}

func (client *Client) QueryTransactions(query *Query) ([]*Transaction, error) {
	path := "/transaction"
	uri := fmt.Sprintf("%s%s", client.apiBaseUrl, path)

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
		return nil, NewDCRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData searchTransactionResponse
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData.Results, nil
}

func (client *Client) GetSCHeap(scId, key string) (io.Reader, error) {
	if len(scId) == 0 {
		scId = os.Getenv("SMART_CONTRACT_ID")
	}

	if len(key) == 0 {
		return nil, errors.New("key can not be empty")
	}

	path := "/get"
	uri := fmt.Sprintf("%s%s/%s/%s", client.apiBaseUrl, path, scId, key)

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
		return nil, NewDCRequestError(resp)
	}

	return resp.Body, nil
}

func (client *Client) ListSCHeap(scId, folder string) ([]string, error) {
	if len(scId) == 0 {
		scId = os.Getenv("SMART_CONTRACT_ID")
	}

	path := "/list"
	uri := fmt.Sprintf("%s%s/%s/", client.apiBaseUrl, path, scId)

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
		return nil, NewDCRequestError(resp)
	}

	decoder := json.NewDecoder(resp.Body)

	var respData []string
	err = decoder.Decode(&respData)
	if err != nil {
		return nil, err
	}

	return respData, nil
}
