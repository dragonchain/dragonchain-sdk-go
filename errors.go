package dragonchain

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

var (
	// ErrDCTimeout is thrown when the chain API returns a timeout.
	ErrDCTimeout = errors.New("chain api returned 408 timeout request")
	// ErrMaxBulkSizeExceeded is thrown when bulk requests exceed MaxBulkPutSize.
	ErrMaxBulkSizeExceeded = errors.New("too many transactions. transaction count can not be greater than MaxBulkPutSize")
)

// ErrFailedRequest defines the structure of an error returned by the chain.
type ErrFailedRequest struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// NewRequestError returns a formatted ErrFailedRequest object from the chain's http response.
func NewRequestError(resp *http.Response) *ErrFailedRequest {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return &ErrFailedRequest{
		Status:  resp.StatusCode,
		Message: string(body),
	}
}

func (err ErrFailedRequest) Error() string {
	return fmt.Sprintf("dragonchain api error: %s (%d) body: %s",
		http.StatusText(err.Status), err.Status, err.Message)
}
