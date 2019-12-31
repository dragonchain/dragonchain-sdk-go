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

// Verification is a representation of the verification object for a block.
type Verification struct {
	L2 []Block `json:"2,omitempty"`
	L3 []Block `json:"3,omitempty"`
	L4 []Block `json:"4,omitempty"`
	L5 []Block `json:"5,omitempty"`
}

// L1Verification is a representation of an L1 block verified by an L2 chain.
type L1Verification struct {
	BlockID       string `json:"block_id"`
	ChainID       string `json:"dc_id"`
	StrippedProof string `json:"stripped_proof"`
	Transactions  string `json:"transactions"`
}

// L2Verification is a representation of an L2 block verified by an L3 chain.
type L2Verification struct {
	Clouds    []string
	Count     string
	DDSS      string `json:"ddss"`
	L1BlockID string `json:"l1_block_id"`
	L1ChainID string `json:"l1_dc_id"`
	L1Proof   string `json:"l1_proof"`
	Regions   []string
}

// L3Verification is a representation of an L3 block verified by an L4 chain.
type L3Verification struct {
	L3ChainID string `json:"l3_dc_id"`
	L3BlockID string `json:"l3_block_id"`
	L3Proof   string `json:"l3_proof"`
	Valid     bool   `json:"valid"`
}

// L4Verification is a representation of an L4 block verified by an L4 chain.
type L4Verification struct {
	L1ChainID string `json:"l1_dc_id"`
	L1BlockID string `json:"l1_block_id"`
	L4ChainID string `json:"l4_dc_id"`
	L4BlockID string `json:"l4_block_id"`
	L4Proof   string `json:"l4_proof"`
}
