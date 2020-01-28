// Copyright 2020 Dragonchain, Inc. or its affiliates. All Rights Reserved.
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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

// ErrDCTimeout is thrown when the chain API returns a timeout.
var ErrDCTimeout = errors.New("chain api returned 408 timeout request")

// ErrMaxBulkSizeExceeded is thrown when bulk requests exceed MaxBulkPutSize.
var ErrMaxBulkSizeExceeded = errors.New("too many transactions. transaction count can not be greater than MaxBulkPutSize")

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
