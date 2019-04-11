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

// Common block structs

// Block defines the structure of a finalized block.
type Block struct {
	Version string `json:"version"`
	DCRN    string `json:"dcrn"`
	Header  BlockHeader
	Proof   BlockProof
}

// BlockHeader defines the structure of a block's header
type BlockHeader struct {
	ChainID   string `json:"dc_id"`
	DDSS      string `json:"current_ddss"`
	Level     int    `json:"level"`
	BlockID   string `json:"block_id"`
	Timestamp string `json:"timestamp"`
	PrevProof string `json:"prev_proof"`
}

// BlockProof defines the structure of a signature proof.
type BlockProof struct {
	Scheme string `json:"scheme"`
	Proof  string `json:"proof"`
	Nonce  int    `json:"nonce"` // Used for PoW chains.
}

// L1 block structs

// L1Header specifies additional header properties for L1 chains.
type L1Header struct {
	*BlockHeader
	PreviousID string `json:"prev_id"`
}

// L1Block specifies additional block properties for L1 chains.
type L1Block struct {
	*Block
	Transactions []Transaction
}

// L2 block structs

// L2Header specifies additional header properties for L2 chains.
type L2Header struct {
	*BlockHeader
}

// L2Block specifies additional block properties for L2 chains.
type L2Block struct {
	*Block
	Validation L1Verification
}

// L3 block structs

// L3Header specifies additional header properties for L3 chains.
type L3Header struct {
	*BlockHeader
}

// L3Block specifies additional block properties for L3 chains.
type L3Block struct {
	*Block
	L2Validations []L2Verification `json:"l2-validations"`
}

// L4 block structs

// L4Header specifies additional header properties for L4 chains.
type L4Header struct {
	*BlockHeader
	L1BlockID string `json:"l1_block_id"`
	L1ChainID string `json:"l1_dc_id"`
	L1Proof   string `json:"l1_proof"`
}

// L4Block specifies additional block properties for L4 chains.
type L4Block struct {
	*Block
	L3Validations []L3Verification `json:"l3-validations"`
}

// L5 block structs

// L5Header specifies additional header properties for L5 chains.
type L5Header struct {
	*BlockHeader
}

// L5Block specifies additional block properties for L5 chains.
type L5Block struct {
	*Block
	L4Blocks []string `json:"l4-blocks"`
}

// L5Proof specifies additional proof properties for L5 chains.
type L5Proof struct {
	*Proof
	BlockLastSentAt string   `json:"block_last_sent_at"`
	TxnHash         []string `json:"transaction_hash"`
	Network         string   `json:"network"`
}
