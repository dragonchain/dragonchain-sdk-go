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

// Common block structs

// Block defines the structure of a finalized block.
type Block struct {
	Version       string           `json:"version"`
	DCRN          string           `json:"dcrn"`
	Header        BlockHeader      `json:"header"`
	Proof         BlockProof       `json:"proof"`
	Transactions  []Transaction    `json:"transactions,omitempty"`   // L1 only
	Validation    L1Verification   `json:"validation,omitempty"`     // L2 only
	L2Validations L2Verification   `json:"l2-validations,omitempty"` // L3 only
	L3Validations []L3Verification `json:"l3-validations,omitempty"` // L4 only
	L4Blocks      []string         `json:"l4-blocks,omitempty"`      // L5 only
}

// BlockHeader defines the structure of a block's header
type BlockHeader struct {
	DcID       string `json:"dc_id"`
	DDSS       string `json:"current_ddss"`
	Level      int    `json:"level"`
	BlockID    string `json:"block_id"`
	Timestamp  string `json:"timestamp"`
	PrevProof  string `json:"prev_proof"`
	PreviousID string `json:"prev_id"`
	// L4 only headers
	L1BlockID string `json:"l1_block_id,omitempty"`
	L1ChainID string `json:"l1_dc_id,omitempty"`
	L1Proof   string `json:"l1_proof,omitempty"`
}

// BlockProof defines the structure of a signature proof.
type BlockProof struct {
	Scheme string `json:"scheme"`
	Proof  string `json:"proof,omitempty"`
	Nonce  int    `json:"nonce,omitempty"` // Used for PoW chains.
	// L5 only proofs
	BlockLastSentAt int64    `json:"block_last_sent_at,omitempty"`
	TxnHash         []string `json:"transaction_hash,omitempty"`
	Network         string   `json:"network,omitempty"`
}
