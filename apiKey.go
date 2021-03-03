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

// APIKeyConfiguration defines the structure of a request to create/update a transaction type
type APIKeyConfiguration struct {
	Nickname string `json:"nickname,omitempty"`
}

// APIKey defines a stored/registered API key
type APIKey struct {
	RegistrationTimestamp int    `json:"registration_time"`
	Nickname              string `json:"nickname,omitempty"`
	Root                  bool   `json:"root,omitempty"`
	Key                   string `json:"key,omitempty"`
	ID                    string `json:"id"`
}
