package dragonchain

import (
	"errors"
)

type Query struct {
	Query  string `json:"q"`
	Sort   string `json:"sort"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

var (
	InvalidOffsetError = errors.New("invalid offset given, must be positive int")
	InvalidLimitError  = errors.New("invalid limit given, must be positive int")
)

func NewQuery(query, sort string, offset int, limit int) (*Query, error) {
	if offset < 0 {
		return nil, InvalidOffsetError
	}
	if limit < 0 {
		return nil, InvalidLimitError
	}

	return &Query{
		Query:  query,
		Sort:   sort,
		Offset: offset,
		Limit:  limit,
	}, nil
}
