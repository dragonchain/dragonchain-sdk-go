package dragonchain

type PostTransaction struct {
	Version string                 `json:"version"`
	TxnType string                 `json:"txn_type"`
	Tag     string                 `json:"tag"`
	Payload map[string]interface{} `json:"payload"`
}

type PostTempTransaction struct {
	Version string `json:"version"`
	TxnType string `json:"txn_type"`
	Tag     string `json:"tag"`
	Payload string `json:"payload"`
}

type Header struct {
	TxnType   string `json:"txn_type"`
	DcId      string `json:"dc_id"`
	TxnId     string `json:"txn_id"`
	BlockId   string `json:"block_id"`
	TimeStamp string `json:"timestamp"`
	Tag       string `json:"tag"`
	Invoker   string `json:"invoker"`
}

type Proof struct {
	Full     string `json:"full"`
	Stripped string `json:"stripped"`
}

type Transaction struct {
	Version string                 `json:"version"`
	DCRN    string                 `json:"dcrn"`
	Header  Header                 `json:"header"`
	Payload map[string]interface{} `json:"payload"`
	Proof   Proof                  `json:"proof"`
}

type GetSmartContractHeap struct {
	SCName string `json:"sc_name"`
	Key    string `json:"key"`
}
