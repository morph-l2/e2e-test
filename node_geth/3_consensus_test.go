package node_geth

import (
	"context"
	"fmt"
	"github.com/morph-l2/bindings/bindings"
	"github.com/morph-l2/node/types"
	"github.com/scroll-tech/go-ethereum/common"
	eth "github.com/scroll-tech/go-ethereum/core/types"
	"github.com/tendermint/tendermint/l2node"
	"github.com/tendermint/tendermint/libs/rand"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"math/big"
	"testing"
	"time"

	"github.com/morph-l2/node/db"
	"github.com/scroll-tech/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/blssignatures"
	"github.com/tendermint/tendermint/config"
	rpctest "github.com/tendermint/tendermint/rpc/test"
	tdm "github.com/tendermint/tendermint/types"
)

func TestSingleTendermint_BasicProduceBlocks(t *testing.T) {
	t.Run("TestDefaultConfig", func(t *testing.T) {
		geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
		tendermint, err := NewDefaultTendermintNode(node)
		require.NoError(t, err)
		require.NoError(t, tendermint.Start())
		defer func() {
			rpctest.StopTendermint(tendermint)
		}()
		tx, err := SimpleTransfer(geth)
		require.NoError(t, err)

		timeoutCommit := tendermint.Config().Consensus.TimeoutCommit
		time.Sleep(timeoutCommit + time.Second)
		receipt, err := geth.EthClient.TransactionReceipt(context.Background(), tx.Hash())
		require.NoError(t, err)
		require.NotNil(t, receipt)
		require.NotNil(t, receipt.BlockNumber, "has not been involved in block after (timeoutCommit + 1) sec passed")
		require.EqualValues(t, 1, receipt.Status)

		block1Header := geth.Backend.BlockChain().GetHeaderByNumber(1)
		queriedBlock1Header, err := geth.EthClient.HeaderByNumber(context.Background(), big.NewInt(1))
		require.NoError(t, err)
		require.EqualValues(t, block1Header.Hash(), queriedBlock1Header.Hash())
	})

	t.Run("TestDelayEmptyBlocks", func(t *testing.T) {
		geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
		tendermint, err := NewTendermintNode(node, nil, func(c *config.Config) {
			c.Consensus.TimeoutCommit = time.Second
			c.Consensus.CreateEmptyBlocks = true
			c.Consensus.CreateEmptyBlocksInterval = 5 * time.Second
		})
		require.NoError(t, err)
		require.NoError(t, tendermint.Start())
		defer func() {
			rpctest.StopTendermint(tendermint)
		}()

		time.Sleep(3 * time.Second)
		tx, err := SimpleTransfer(geth)
		require.NoError(t, err)

		timeoutCommit := tendermint.Config().Consensus.TimeoutCommit
		time.Sleep(timeoutCommit)
		receipt, err := geth.EthClient.TransactionReceipt(context.Background(), tx.Hash())
		require.NoError(t, err)
		require.NotNil(t, receipt)
		require.NotNil(t, receipt.BlockNumber, "has not been involved in block after (timeoutCommit + 1) sec passed")
		require.EqualValues(t, 1, receipt.Status)
	})
}

func TestSingleTendermint_VerifyBLS(t *testing.T) {
	geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
	blsKey := blssignatures.GenFileBLSKey()

	stop := make(chan struct{})
	var firstBatchHash []byte
	customNode := NewCustomNode(node).
		WithCustomFuncDeliverBlock(func(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error) {
			nextParams, nextValidator, err := node.DeliverBlock(txs, blockMeta, data)
			wrappedBlock := new(types.WrappedBlock)
			err = wrappedBlock.UnmarshalBinary(blockMeta)
			require.NoError(t, err)
			// set batch blocksInterval for testing when it is the first block
			if wrappedBlock.Number == 1 {
				nextParams = &tmproto.BatchParams{
					BlocksInterval: 1,
				}
			} else if wrappedBlock.Number == 2 {
				require.True(t, len(data.BatchHash) > 0, "should have batchHash when block 2")
				firstBatchHash = data.BatchHash
			}
			return nextParams, nextValidator, err
		}).
		WithCustomSealBatch(func() (batchHash []byte, batchHeader []byte, err error) {
			batchHash, batchHeader, err = node.SealBatch()
			return
		}).
		WithCustomCommitBatch(func(currentBlockBytes []byte, currentTxs tdm.Txs, blsDatas []l2node.BlsData) error {
			var curBlock = new(types.WrappedBlock)
			err := curBlock.UnmarshalBinary(currentBlockBytes)
			require.NoError(t, err)
			if curBlock.Number == 2 {
				require.EqualValues(t, 1, len(blsDatas))
				sig, err := blssignatures.SignatureFromBytes(blsDatas[0].Signature)
				require.NoError(t, err)
				blsPk, err := blssignatures.PublicKeyFromBytes(blsKey.PubKey, true)
				require.NoError(t, err)
				valid, err := blssignatures.VerifySignature(sig, firstBatchHash, blsPk)
				require.NoError(t, err)
				require.True(t, valid)
				close(stop)
			}
			return node.CommitBatch(currentBlockBytes, currentTxs, blsDatas)
		})

	tendermint, err := NewTendermintNode(customNode, blsKey)
	require.NoError(t, err)
	require.NoError(t, tendermint.Start())
	defer func() {
		rpctest.StopTendermint(tendermint)
		geth.Node.Close()
	}()
	_, err = SimpleTransfer(geth)
	require.NoError(t, err)

	timer := time.NewTimer(2 * time.Second)
Loop:
	for {
		select {
		case <-stop:
			t.Log("successfully verified BLS")
			break Loop
		case <-timer.C:
			require.Fail(t, "timeout")
			break Loop
		}
	}
}

func TestSingleTendermint_BatchPoint(t *testing.T) {
	var (
		batchBlockInterval = int64(2)
		batchMaxBytes      = int64(1000)
		batchTimeout       = 1 * time.Second
		batchMaxChunks     = int64(2)
	)
	t.Run("TestBatchBlockInterval", func(t *testing.T) {
		stop := make(chan struct{})
		geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
		customNode := NewCustomNode(node).
			WithCustomFuncDeliverBlock(func(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error) {
				nextParams, nextVal, err := node.DeliverBlock(txs, blockMeta, data)
				require.NoError(t, err)
				wrappedBlock := new(types.WrappedBlock)
				err = wrappedBlock.UnmarshalBinary(blockMeta)
				require.NoError(t, err)
				if wrappedBlock.Number == 1 {
					nextParams = &tmproto.BatchParams{
						BlocksInterval: batchBlockInterval,
					}
				}
				if wrappedBlock.Number != 1 && (wrappedBlock.Number-1)%2 == 0 {
					require.NotNil(t, data.BatchHash, fmt.Sprintf("batchHash should not be nil at height: %d", wrappedBlock.Number))
				} else {
					require.Nil(t, data.BatchHash, fmt.Sprintf("batchHash should be nil at height: %d", wrappedBlock.Number))
				}
				if wrappedBlock.Number == 10 {
					close(stop)
				}
				return nextParams, nextVal, nil
			})
		tendermint, err := NewDefaultTendermintNode(customNode)
		require.NoError(t, err)
		require.NoError(t, tendermint.Start())
		defer func() {
			rpctest.StopTendermint(tendermint)
			geth.Node.Close()
		}()

		timer := time.NewTimer(10 * time.Second)
	Loop:
		for {
			select {
			case <-stop:
				t.Log("test passed")
				break Loop
			case <-timer.C:
				require.Fail(t, "timeout")
				break Loop
			}
		}
	})

	t.Run("TestBatchMaxBytes", func(t *testing.T) {
		var (
			shouldCommitBatch  bool
			stop               = make(chan struct{})
			committedIndex     int
			committedIndexChan = make(chan int)
		)
		geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
		rollup, err := bindings.NewRollup(common.BigToAddress(big.NewInt(100)), geth.EthClient)
		transactOpts, err := bind.NewKeyedTransactorWithChainID(testingPrivKey, geth.Backend.BlockChain().Config().ChainID)
		require.NoError(t, err)
		transactOpts.NoSend = true
		transactOpts.GasLimit = 100000000

		customNode := NewCustomNode(node).
			WithCustomFuncDeliverBlock(func(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error) {
				nextParams, nextVal, err := node.DeliverBlock(txs, blockMeta, data)
				require.NoError(t, err)
				wrappedBlock := new(types.WrappedBlock)
				err = wrappedBlock.UnmarshalBinary(blockMeta)
				require.NoError(t, err)
				if wrappedBlock.Number == 1 {
					nextParams = &tmproto.BatchParams{
						MaxBytes: batchMaxBytes,
					}
				}
				return nextParams, nextVal, nil
			}).
			WithCustomCalculateCapWithPb(func(proposalBlockBytes []byte, proposalTxs tdm.Txs, get l2node.GetFromBatchStartFunc) (batchSize int64, chunkNum int64, err error) {
				batchSize, chunkNum, err = node.CalculateCapWithProposalBlock(proposalBlockBytes, proposalTxs, get)
				require.NoError(t, err)
				if batchSize > batchMaxBytes {
					shouldCommitBatch = true
				}
				return batchSize, chunkNum, nil
			}).
			WithCustomCommitBatch(func(currentBlockBytes []byte, currentTxs tdm.Txs, blsDatas []l2node.BlsData) error {
				if !shouldCommitBatch {
					require.FailNow(t, "should not commit batch now")
				}
				err := node.CommitBatch(currentBlockBytes, currentTxs, blsDatas)
				require.NoError(t, err)
				committedIndex++
				committedIndexChan <- committedIndex
				if committedIndex == 5 {
					close(stop)
				}
				return nil
			})
		tendermint, err := NewDefaultTendermintNode(customNode)
		require.NoError(t, err)
		require.NoError(t, tendermint.Start())
		defer func() {
			rpctest.StopTendermint(tendermint)
			geth.Node.Close()
		}()

		timer := time.NewTimer(10 * time.Second)
	Loop:
		for {
			select {
			case <-stop:
				t.Log("test passed")
				break Loop
			case index := <-committedIndexChan:
				batch, err := geth.GetBatch(uint64(index))
				require.NoError(t, err)
				require.NotNil(t, batch)
				require.Greater(t, len(batch.Chunks), 0)

				var chunks [][]byte
				var chunkSize int
				for _, c := range batch.Chunks {
					chunks = append(chunks, c)
					chunkSize += len(c)
				}
				size := 97 + len(batch.ParentBatchHeader) + chunkSize + len(batch.SkippedL1MessageBitmap)
				require.True(t, batchMaxBytes >= int64(size))
				t.Log(fmt.Sprintf("======>index: %d, size: %d \n", index, size))

				tx, err := rollup.CommitBatch(transactOpts, bindings.IRollupBatchData{
					Version:                uint8(batch.Version),
					ParentBatchHeader:      batch.ParentBatchHeader,
					Chunks:                 chunks,
					SkippedL1MessageBitmap: batch.SkippedL1MessageBitmap,
					PrevStateRoot:          batch.PrevStateRoot,
					PostStateRoot:          batch.PostStateRoot,
					WithdrawalRoot:         batch.WithdrawRoot,
					Signature: bindings.IRollupBatchSignature{
						Version:   big.NewInt(0),
						Signers:   []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3)},
						Signature: rand.Bytes(256),
					},
				})
				require.NoError(t, err)
				txBytes, err := tx.MarshalBinary()
				require.NoError(t, err)
				t.Log(fmt.Sprintf("======>index: %d, txBytes:%d \n", index, len(txBytes)))
				bufferLength := len(txBytes) - size
				require.True(t, bufferLength < 2048, "buffer length should less than 2K")
			case <-timer.C:
				require.Fail(t, "timeout")
				break Loop
			}
		}
	})

	t.Run("TestBatchTimeout", func(t *testing.T) {
		var batchCount int
		geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
		customNode := NewCustomNode(node).
			WithCustomFuncDeliverBlock(func(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error) {
				nextParams, nextVal, err := node.DeliverBlock(txs, blockMeta, data)
				require.NoError(t, err)
				wrappedBlock := new(types.WrappedBlock)
				err = wrappedBlock.UnmarshalBinary(blockMeta)
				require.NoError(t, err)
				if wrappedBlock.Number == 1 {
					nextParams = &tmproto.BatchParams{
						Timeout: batchTimeout,
					}
				}

				if len(data.BatchHash) > 0 {
					batchCount++
				}
				return nextParams, nextVal, nil
			})
		tendermint, err := NewDefaultTendermintNode(customNode)
		require.NoError(t, err)
		require.NoError(t, tendermint.Start())
		defer func() {
			rpctest.StopTendermint(tendermint)
			geth.Node.Close()
		}()

		timer := time.NewTimer(3*batchTimeout + 1*time.Second)
	Loop:
		for {
			select {
			case <-timer.C:
				require.True(t, batchCount >= 3, "do not have enough count during this period")
				break Loop
			}
		}
	})

	t.Run("TestBatchMaxChunks", func(t *testing.T) {
		stop := make(chan struct{})
		geth, node := NewGethAndNode(t, db.NewMemoryStore(), nil, nil, nil)
		customNode := NewCustomNode(node).
			WithCustomRequestBlockData(func(height int64) (txs [][]byte, blockMeta []byte, collectedL1Msgs bool, err error) {
				txs, blockMeta, collectedL1Msgs, err = node.RequestBlockData(height)
				require.NoError(t, err)
				wrappedBlock := new(types.WrappedBlock)
				err = wrappedBlock.UnmarshalBinary(blockMeta)
				require.NoError(t, err)
				// set rowConsumption to make 2 blocks into a chunk
				wrappedBlock.RowConsumption = eth.RowConsumption{eth.SubCircuitRowUsage{Name: "a", RowNumber: 500_000}}
				blockMeta, err = wrappedBlock.MarshalBinary()
				require.NoError(t, err)
				return
			}).
			WithCustomFuncDeliverBlock(func(txs [][]byte, blockMeta []byte, data l2node.ConsensusData) (*tmproto.BatchParams, [][]byte, error) {
				nextParams, nextVal, err := node.DeliverBlock(txs, blockMeta, data)
				require.NoError(t, err)
				wrappedBlock := new(types.WrappedBlock)
				err = wrappedBlock.UnmarshalBinary(blockMeta)
				require.NoError(t, err)
				if wrappedBlock.Number == 1 {
					nextParams = &tmproto.BatchParams{
						MaxChunks: batchMaxChunks,
					}
				}
				if wrappedBlock.Number != 1 && int64(wrappedBlock.Number-1)%(batchMaxChunks*2) == 0 {
					require.NotNil(t, data.BatchHash, fmt.Sprintf("batchHash should not be nil at height: %d", wrappedBlock.Number))
				} else {
					require.Nil(t, data.BatchHash, fmt.Sprintf("batchHash should be nil at height: %d", wrappedBlock.Number))
				}
				if wrappedBlock.Number == uint64(batchMaxChunks*2*3+1) {
					close(stop)
				}
				return nextParams, nextVal, nil
			})
		tendermint, err := NewDefaultTendermintNode(customNode)
		require.NoError(t, err)
		require.NoError(t, tendermint.Start())
		defer func() {
			rpctest.StopTendermint(tendermint)
			geth.Node.Close()
		}()

		timer := time.NewTimer(10 * time.Second)
	Loop:
		for {
			select {
			case <-stop:
				t.Log("test passed")
				break Loop
			case <-timer.C:
				require.Fail(t, "timeout")
				break Loop
			}
		}
	})
}

/******************************************************/
/*                 multiple nodes testing             */
/******************************************************/

func TestMultipleTendermint_BasicProduceBlocks(t *testing.T) {
	//nodesNum := 4
	privKeys, pubKeys := sequencersPrivateKeys()

	l2Nodes, geths := NewMultipleGethNodes(t, pubKeys)

	sendValue := big.NewInt(1e18)
	transactOpts, err := bind.NewKeyedTransactorWithChainID(testingPrivKey, geths[0].Backend.BlockChain().Config().ChainID)
	require.NoError(t, err)
	transactOpts.Value = sendValue
	transferTx, err := geths[0].Transfer(transactOpts, testingAddress2)
	require.NoError(t, err)
	pendings := geths[0].Backend.TxPool().Pending(true)
	require.EqualValues(t, 1, len(pendings))

	// testing the transactions broadcasting
	time.Sleep(1000 * time.Millisecond) // give the time for broadcasting
	for i := 1; i < len(privKeys); i++ {
		pendings = geths[i].Backend.TxPool().Pending(true)
		require.EqualValues(t, 1, len(pendings), "geth%d has not received this transaction", i)
	}

	tmNodes, err := NewMultipleTendermintNodes(l2Nodes, privKeys)
	defer func() {
		for _, tmNode := range tmNodes {
			if tmNode != nil {
				rpctest.StopTendermint(tmNode)
			}
		}
	}()
	require.NoError(t, err)
	for _, tmNode := range tmNodes {
		go tmNode.Start()
		// sleep for a while to start the next tendermint node, in case the conflicts during concurrent operations
		time.Sleep(100 * time.Millisecond)
	}

	// testing the block producing
	time.Sleep(tmNodes[0].Config().Consensus.TimeoutCommit + 2*time.Second)
	receipt, err := geths[0].EthClient.TransactionReceipt(context.Background(), transferTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, receipt.BlockNumber, "the transaction has not been involved in block")
	require.EqualValues(t, 1, receipt.Status)

	receipt, err = geths[1].EthClient.TransactionReceipt(context.Background(), transferTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, receipt.BlockNumber, "the transaction has not been involved in block")
	require.EqualValues(t, 1, receipt.Status)

	receipt, err = geths[2].EthClient.TransactionReceipt(context.Background(), transferTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, receipt.BlockNumber, "the transaction has not been involved in block")
	require.EqualValues(t, 1, receipt.Status)

	receipt, err = geths[3].EthClient.TransactionReceipt(context.Background(), transferTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, receipt.BlockNumber, "the transaction has not been involved in block")
	require.EqualValues(t, 1, receipt.Status)
}

func TestMultipleTendermint_AddNonSequencer(t *testing.T) {
	nodesNum := 5

	privKeys, pubKeys := sequencersPrivateKeys()
	_, nonPubKeys := generateTendermintKeys(nodesNum - 4)
	pubKeys = append(pubKeys, nonPubKeys...)
	l2Nodes, geths := NewMultipleGethNodes(t, pubKeys)

	nonSeqL2Node, nonSeqGeth := l2Nodes[4], geths[4]
	l2Nodes = l2Nodes[:4]

	//timeoutCommit := time.Second
	tmNodes, err := NewMultipleTendermintNodes(l2Nodes, privKeys)
	defer func() {
		for _, tmNode := range tmNodes {
			if tmNode != nil {
				rpctest.StopTendermint(tmNode)
			}
		}
	}()
	require.NoError(t, err)

	// send transfer tx
	sendValue := big.NewInt(1e18)
	transactOpts, err := bind.NewKeyedTransactorWithChainID(testingPrivKey, geths[0].Backend.BlockChain().Config().ChainID)
	require.NoError(t, err)
	transactOpts.Value = sendValue
	transferTx, err := geths[0].Transfer(transactOpts, testingAddress2)
	require.NoError(t, err)

	for _, tmNode := range tmNodes {
		go tmNode.Start()
		// sleep for a while to start the next tendermint node, in case the conflicts during concurrent operations
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(time.Second)

	// new a non-sequencer
	genDoc, err := tdm.GenesisDocFromFile(tmNodes[0].Config().GenesisFile())
	require.NoError(t, err)
	nonSeqTendermint, err := NewDefaultTendermintNode(nonSeqL2Node, func(c *config.Config) {
		if err = genDoc.SaveAs(c.GenesisFile()); err != nil {
			require.NoError(t, err)
		}
		c.P2P.PersistentPeers = tmNodes[0].Config().P2P.PersistentPeers
	})
	defer func() {
		if nonSeqTendermint != nil {
			rpctest.StopTendermint(nonSeqTendermint)
		}
	}()
	require.NoError(t, err)
	go nonSeqTendermint.Start()
	time.Sleep(2 * time.Second)
	require.True(t, nonSeqGeth.Backend.BlockChain().CurrentHeader().Number.Uint64() > 0)
	receipt, err := nonSeqGeth.EthClient.TransactionReceipt(context.Background(), transferTx.Hash())
	require.NoError(t, err)
	require.EqualValues(t, 1, receipt.Status)

	balance, err := nonSeqGeth.EthClient.BalanceAt(context.Background(), testingAddress2, nil)
	require.NoError(t, err)
	require.EqualValues(t, sendValue.Int64(), balance.Int64())
}

func TestMultipleTendermint_NodeOffline(t *testing.T) {
	privKeys, pubKeys := sequencersPrivateKeys()
	l2Nodes, geths := NewMultipleGethNodes(t, pubKeys)

	timeoutCommit := time.Second
	tmNodes, err := NewMultipleTendermintNodes(l2Nodes, privKeys, func(c *config.Config) {
		c.Consensus.SkipTimeoutCommit = false
		c.Consensus.TimeoutCommit = timeoutCommit
	})
	defer func() {
		for _, tmNode := range tmNodes {
			if tmNode != nil {
				rpctest.StopTendermint(tmNode)
			}
		}
	}()
	require.NoError(t, err)
	for _, tmNode := range tmNodes {
		go tmNode.Start()
		// sleep for a while to start the next tendermint node, in case the conflicts during concurrent operations
		time.Sleep(100 * time.Millisecond)
	}

	theAlwaysActiveGeth := geths[len(pubKeys)-1]
	startedHeight := theAlwaysActiveGeth.Backend.BlockChain().CurrentHeader().Number.Uint64()
	time.Sleep(timeoutCommit * 3)
	laterHeight := theAlwaysActiveGeth.Backend.BlockChain().CurrentHeader().Number.Uint64()
	require.True(t, laterHeight > startedHeight)
	// one node offline
	require.NoError(t, tmNodes[0].Stop())
	afterNode0StoppedHeight := theAlwaysActiveGeth.Backend.BlockChain().CurrentHeader().Number.Uint64()
	time.Sleep(timeoutCommit * 3)
	laterHeight = theAlwaysActiveGeth.Backend.BlockChain().CurrentHeader().Number.Uint64()
	require.True(t, laterHeight > afterNode0StoppedHeight, "stop producing blocks after one node offline")
	// two nodes offline
	require.NoError(t, tmNodes[1].Stop())
	afterNode1StoppedHeight := theAlwaysActiveGeth.Backend.BlockChain().CurrentHeader().Number.Uint64()
	time.Sleep(timeoutCommit * 3)
	laterHeight = theAlwaysActiveGeth.Backend.BlockChain().CurrentHeader().Number.Uint64()
	require.True(t, laterHeight == afterNode1StoppedHeight, "producing blocks even 2 nodes offline")
}
