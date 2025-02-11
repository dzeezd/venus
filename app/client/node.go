package client

import (
	"context"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/filecoin-project/go-jsonrpc"
	"github.com/filecoin-project/venus/app/paths"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

func getVenusClientInfo() (string, http.Header, error) {
	repoPath, err := paths.GetRepoPath("")
	if err != nil {
		return "", nil, err
	}

	tokePath := path.Join(repoPath, "token")
	rpcPath := path.Join(repoPath, "api")

	tokenBytes, err := ioutil.ReadFile(tokePath)
	if err != nil {
		return "", nil, err
	}
	rpcBytes, err := ioutil.ReadFile(rpcPath)
	if err != nil {
		return "", nil, err
	}

	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+string(tokenBytes))
	apima, err := multiaddr.NewMultiaddr(string(rpcBytes))
	if err != nil {
		return "", nil, err
	}

	_, addr, err := manet.DialArgs(apima)
	if err != nil {
		return "", nil, err
	}

	addr = "ws://" + addr + "/rpc/v0"
	return addr, headers, nil
}

func NewFullNode(ctx context.Context) (FullNodeStruct, jsonrpc.ClientCloser, error) {
	addr, headers, err := getVenusClientInfo()
	if err != nil {
		return FullNodeStruct{}, nil, err
	}
	node := FullNodeStruct{}
	closer, err := jsonrpc.NewClient(ctx, addr, "Filecoin", &node, headers)
	if err != nil {
		return FullNodeStruct{}, nil, err
	}
	return node, closer, nil
}

func NewMiningAPINode(ctx context.Context) (IMiningStruct, jsonrpc.ClientCloser, error) {
	addr, headers, err := getVenusClientInfo()
	if err != nil {
		return IMiningStruct{}, nil, err
	}
	node := IMiningStruct{}
	closer, err := jsonrpc.NewClient(ctx, addr, "Filecoin", &node, headers)
	if err != nil {
		return IMiningStruct{}, nil, err
	}
	return node, closer, nil
}
