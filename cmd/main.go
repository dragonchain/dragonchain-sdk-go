package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dragonchain-inc/dragonchain-sdk-go"
)

var (
	dcID     = ""
	apiKey   = ""
	apiKeyID = ""
)

func main() {
	httpClient := &http.Client{}

	creds, err := dragonchain.NewCredentials(dcID, apiKey, apiKeyID, dragonchain.HashSHA256)
	if err != nil {
		fmt.Println("dragonchain.NewCredentials returned error: ", err)
		return
	}

	baseURL := fmt.Sprintf("https://%s.api.dragonchain.com", creds.GetDragonchainID())
	client := dragonchain.NewClient(creds, baseURL, httpClient)

	heapList, err := client.GetSCHeap("", "")
	if err != nil {
		fmt.Println("client.ListSCHeap returned error: ", err)
		return
	}

	heapListJSON, err := json.Marshal(heapList)
	if err != nil {
		fmt.Println("json.Marshal returned error: ", err)
		return
	}

	fmt.Println(string(heapListJSON))
}
