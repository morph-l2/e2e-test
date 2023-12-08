package configs

import (
	"encoding/base64"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"math/big"
)

func init() {
	alias := new(big.Int).Add(new(big.Int).SetBytes(L1CrossDomainMessengerAddress.Bytes()), new(big.Int).SetBytes(AliasOffset.Bytes()))
	L1CrossDomainMessengerAddressAlias = common.BytesToAddress(alias.Bytes())
	for _, privKey := range sequencersPriKeys {
		sequencerPrivKeyBytes, err := base64.StdEncoding.DecodeString(privKey)
		if err != nil {
			panic(err)
		}
		Sequencers = append(Sequencers, sequencerPrivKeyBytes)
	}
}

var (
	AliasOffset                        = common.HexToAddress("0x1111000000000000000000000000000000001111")
	L1StandardBridgeAddress            = common.HexToAddress("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0")
	L1CrossDomainMessengerAddress      = common.HexToAddress("0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9")
	L1CrossDomainMessengerAddressAlias common.Address

	L2StandardBridgeAddress       = common.HexToAddress("0x4200000000000000000000000000000000000010")
	L2CrossDomainMessengerAddress = common.HexToAddress("0x4200000000000000000000000000000000000007")

	DepositETHGasLimit = big.NewInt(200_000)

	sequencersPriKeys = []string{
		"XY72UBdFzwx+0JePwPOvB8/Og0k+G/XRLKeDCjmrA/FSgNDu4qZNOtKUgNFf/RsEjOWQjxgLXM1lzD3PAJQauw==",
		"OHOtc9F+OaicESSSyn4QEO5Eo2QucbF4KaDZCRbijGS3mOt0wGch1Uxlnp6ivCMqf5XpbSNMyHGGsquPQ9tpNQ==",
		"8ROYORUq6FHUn8yG6kFp/5qQbTw63CjKnOaAS06/PiPs/60BEpeGupxik6pmT5UolNxAGXYoBHmd+h/7bk7QQA==",
		"5Q0TRMdvQnSeZ3IGKSmwPsqtlP8YhocLT4aipVe4yx+NKWlbtBV8aWCttIa+HZoMn3KFJNCb/8xPiTLtFSIcSg=="}
	Sequencers []ed25519.PrivKey
)
