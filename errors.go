package dragonchain

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

var (
	DCTimeoutRequestError = errors.New("dragonchain api returned 408 timeout request")
	MaxBulkSizeError      = errors.New("to many transactions, transaction count can not be greater than MaxBulkPutSize")
)

type DCRequestError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func NewDCRequestError(resp *http.Response) *DCRequestError {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return &DCRequestError{
		Status:  resp.StatusCode,
		Message: string(body),
	}
}

func (err DCRequestError) Error() string {
	return fmt.Sprintf("dragonchain api error: %s (%d) body: %s",
		http.StatusText(err.Status), err.Status, err.Message)
}
