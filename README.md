# Dragonchain Golang SDK

Talk to your dragonchain.

## Method Quicklinks

These docs are auto-generated.

- [Godoc](https://godoc.org/github.com/dragonchain-inc/dragonchain-sdk-go)

### Installation

```sh
go get https://github.com/dragonchain-inc/dragonchain-sdk-go
```

### Examples

#### GetBlock

```golang
import (
    "fmt"
    "net/http"

    "github.com/dragonchain-inc/dragonchain-sdk-go"
)
httpClient := &http.Client{}
myDcID := "3f2fef78-0000-0000-0000-9f2971607130";
myCreds := dragonchain.NewCredentials(mydcID, apiKey, apiKeyID, dragonchain.HashSHA256)
client := dragonchain.NewClient(myCreds, baseURL, httpClient)

call, err := await client.GetBlock("block-id-here");

if err != nil {
  fmt.Println("Something went wrong!");
  fmt.Printf("HTTP status code from chain: %s", call.status);
  fmt.Printf("Error response from chain: %s", call.response);
}
fmt.Println("Successful call!");
fmt.Printf("Block: %s", call.response);
```

#### QueryTransactions

```golang
searchResult := client.QueryTransactions(Query.NewQuery("tag=MyAwesomeTransactionTag"))
```

#### OverrideCredentials

This is fine for quick tests. For actual production use, you should use the [credential ini file or environment variables](#configuration)

```golang
newHttpClient := &http.Client{}
client.overrideCredentials("AUTH_KEY_ID","AUTH_KEY", newHttpClient)
```

## Configuration

In order to use this SDK, you need to have an Auth Key as well as an Auth Key ID for a given dragonchain.
This can be loaded into the sdk in various ways, and are checked in the following order of precedence:

1. The environment variables `AUTH_KEY` and `AUTH_KEY_ID` can be set with the appropriate values
2. Write an ini-style credentials file at `~/.dragonchain/credentials` (or on Windows: `%LOCALAPPDATA%\dragonchain\credentials`) where the section name is the dragonchain id, with values for `auth_key` and `auth_key_id` like so:

```ini
[35a7371c-a20a-4830-9a59-5d654fcd0a4a]
auth_key_id = JSDMWFUJDVTC
auth_key = n3hlldsFxFdP2De0yMu6A4MFRh1HGzFvn6rJ0ICZzkE
```

## Contributing

Dragonchain is happy to welcome contributions from the community. You can get started [here](https://github.com/dragonchain-inc/dragonchain-sdk-node/blob/master/CONTRIBUTING.md).
