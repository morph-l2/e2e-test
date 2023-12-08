package node_geth

import (
	"errors"
	"github.com/tendermint/tendermint/crypto"

	node "github.com/morph-l2/node/core"
	"github.com/morph-l2/node/sync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tendermint/tendermint/l2node"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tdm "github.com/tendermint/tendermint/types"
)

func NewSequencerNode(geth Geth, syncer *sync.Syncer, tmPubKey crypto.PubKey) (l2node.L2Node, error) {
	nodeConfig := node.DefaultConfig()
	nodeConfig.L2.EthAddr = geth.Node.HTTPEndpoint()
	nodeConfig.L2.EngineAddr = geth.Node.HTTPAuthEndpoint()
	nodeConfig.L2.JwtSecret = testingJWTSecret
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	if tmPubKey == nil {
		nodeConfig.DevSequencer = true
	}
	return node.NewExecutor(func() (*sync.Syncer, error) {
		return syncer, nil
	}, nodeConfig, tmPubKey)
}

func ManualCreateBlock(node l2node.L2Node, blockNumber int64) error {
	txs, blockMeta, _, err := node.RequestBlockData(blockNumber)
	if err != nil {
		return err
	}
	valid, err := node.CheckBlockData(txs, blockMeta)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("check block data false")
	}
	_, _, err = node.DeliverBlock(txs, blockMeta, l2node.ConsensusData{})
	return err
}

/**
 * Custom node, customize the actions to test different cases
 */

type CustomNode struct {
	origin l2node.L2Node

	CustomFuncRequestBlockData FuncRequestBlockData
	CustomFuncCheckBlockData   FuncCheckBlockData
	CustomFuncDeliverBlock     FuncDeliverBlock

	CustomFuncCalculateCapWithProposalBlock FuncCalculateCapWithProposalBlock
	CustomFuncSealBatch                     FuncSealBatch
	CustomFuncCommitBatch                   FuncCommitBatch
}

type FuncRequestBlockData func(height int64) (txs [][]byte, blockMeta []byte, collectedL1Msgs bool, err error)
type FuncCheckBlockData func(txs [][]byte, blockMeta []byte) (valid bool, err error)
type FuncDeliverBlock func(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error)
type FuncCalculateCapWithProposalBlock func(proposalBlockBytes []byte, proposalTxs tdm.Txs, get l2node.GetFromBatchStartFunc) (batchSize int64, chunkNum int64, err error)
type FuncSealBatch func() (batchHash []byte, batchHeader []byte, err error)
type FuncCommitBatch func(currentBlockBytes []byte, currentTxs tdm.Txs, blsDatas []l2node.BlsData) error

func NewCustomNode(origin l2node.L2Node) *CustomNode {
	return &CustomNode{
		origin: origin,
	}
}
func (cn *CustomNode) WithCustomRequestBlockData(rbdFunc FuncRequestBlockData) *CustomNode {
	cn.CustomFuncRequestBlockData = rbdFunc
	return cn
}
func (cn *CustomNode) WithCustomFuncCheckBlockData(cbdFunc FuncCheckBlockData) *CustomNode {
	cn.CustomFuncCheckBlockData = cbdFunc
	return cn
}
func (cn *CustomNode) WithCustomFuncDeliverBlock(dbFunc FuncDeliverBlock) *CustomNode {
	cn.CustomFuncDeliverBlock = dbFunc
	return cn
}
func (cn *CustomNode) WithCustomSealBatch(sbFunc FuncSealBatch) *CustomNode {
	cn.CustomFuncSealBatch = sbFunc
	return cn
}
func (cn *CustomNode) WithCustomCommitBatch(f FuncCommitBatch) *CustomNode {
	cn.CustomFuncCommitBatch = f
	return cn
}
func (cn *CustomNode) WithCustomCalculateCapWithPb(f FuncCalculateCapWithProposalBlock) *CustomNode {
	cn.CustomFuncCalculateCapWithProposalBlock = f
	return cn
}

func (cn *CustomNode) RequestBlockData(height int64) (txs [][]byte, blockMeta []byte, collectedL1Msgs bool, err error) {
	if cn.CustomFuncRequestBlockData != nil {
		return cn.CustomFuncRequestBlockData(height)
	}
	return cn.origin.RequestBlockData(height)
}

func (cn *CustomNode) CheckBlockData(txs [][]byte, blockMeta []byte) (valid bool, err error) {
	if cn.CustomFuncCheckBlockData != nil {
		return cn.CustomFuncCheckBlockData(txs, blockMeta)
	}
	return cn.origin.CheckBlockData(txs, blockMeta)
}

func (cn *CustomNode) DeliverBlock(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error) {
	if cn.CustomFuncDeliverBlock != nil {
		return cn.CustomFuncDeliverBlock(txs, blockMeta, data)
	}
	return cn.origin.DeliverBlock(txs, blockMeta, data)
}

func (cn *CustomNode) RequestHeight(tmHeight int64) (height int64, err error) {
	return cn.origin.RequestHeight(tmHeight)
}

func (cn *CustomNode) EncodeTxs(batchTxs [][]byte) (encodedTxs []byte, err error) {
	return cn.origin.EncodeTxs(batchTxs)
}

func (cn *CustomNode) VerifySignature(tmKey []byte, message []byte, signature []byte) (valid bool, err error) {
	return cn.origin.VerifySignature(tmKey, message, signature)
}

func (cn *CustomNode) CalculateCapWithProposalBlock(proposalBlockBytes []byte, proposalTxs tdm.Txs, get l2node.GetFromBatchStartFunc) (batchSize int64, chunkNum int64, err error) {
	if cn.CustomFuncCalculateCapWithProposalBlock != nil {
		return cn.CustomFuncCalculateCapWithProposalBlock(proposalBlockBytes, proposalTxs, get)
	}
	return cn.origin.CalculateCapWithProposalBlock(proposalBlockBytes, proposalTxs, get)
}

func (cn *CustomNode) SealBatch() (
	batchHash []byte,
	batchHeader []byte,
	err error,
) {
	if cn.CustomFuncSealBatch != nil {
		return cn.CustomFuncSealBatch()
	}
	return cn.origin.SealBatch()
}

func (cn *CustomNode) CommitBatch(
	currentBlockBytes []byte,
	currentTxs tdm.Txs,
	blsDatas []l2node.BlsData,
) error {
	if cn.CustomFuncCommitBatch != nil {
		return cn.CustomFuncCommitBatch(currentBlockBytes, currentTxs, blsDatas)
	}
	return cn.origin.CommitBatch(currentBlockBytes, currentTxs, blsDatas)
}

func (cn *CustomNode) PackCurrentBlock(
	currentBlockBytes []byte,
	currentTxs tdm.Txs,
) error {
	return cn.origin.PackCurrentBlock(currentBlockBytes, currentTxs)
}

func (cn *CustomNode) AppendBlsData(height int64, batchHash []byte, data l2node.BlsData) error {
	return cn.origin.AppendBlsData(height, batchHash, data)
}

func (cn *CustomNode) BatchHash(batchHeader []byte) ([]byte, error) {
	return cn.origin.BatchHash(batchHeader)
}
