package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dragonchain-inc/dragonchain-sdk-go"
)

var (
	dcId     = ""
	apiKey   = ""
	apiKeyId = ""
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpClient := &http.Client{}

	creds, err := dragonchain.NewCredentials(dcId, apiKey, apiKeyId, dragonchain.HashSHA256)
	if err != nil {
		fmt.Println("dragonchain.NewCredentials returned error: ", err)
		return
	}

	baseURL := fmt.Sprintf("https://%s.api.dragonchain.com", creds.GetDragonchainId())
	client := dragonchain.NewClient(ctx, creds, baseURL, httpClient)

	heapList, err := client.GetSCHeap("", "")
	if err != nil {
		fmt.Println("client.ListSCHeap returned error: ", err)
		return
	}

	healListJson, err := json.Marshal(heapList)
	if err != nil {
		fmt.Println("json.Marshal returned error: ", err)
		return
	}

	fmt.Println(string(healListJson))
}
