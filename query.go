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
	"errors"
)

// Query defines the structure of a lucene query on the Dragonchain.
type Query struct {
	Query  string `json:"q"`
	Sort   string `json:"sort"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

var (
	// ErrInvalidOffset is thrown when a negative offset is provided.
	ErrInvalidOffset = errors.New("invalid offset given, must be positive int")
	// ErrInvalidLimit is thrown when a negative limit is provided.
	ErrInvalidLimit = errors.New("invalid limit given, must be positive int")
)

// NewQuery constructs a Query based on provided parameters.
func NewQuery(query, sort string, offset int, limit int) (*Query, error) {
	if offset < 0 {
		return nil, ErrInvalidOffset
	}
	if limit < 0 {
		return nil, ErrInvalidLimit
	}

	return &Query{
		Query:  query,
		Sort:   sort,
		Offset: offset,
		Limit:  limit,
	}, nil
}
