package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dragonchain-inc/dragonchain"
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
		fmt.Println(err)
	}

	baseURL := fmt.Sprintf("https://%s.api.dragonchain.com", creds.GetDragonchainId())
	client := dragonchain.NewClient(ctx, creds, baseURL, httpClient)

	msg, err := client.Status()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(msg)
}
