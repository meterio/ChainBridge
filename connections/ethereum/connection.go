// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package ethereum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ChainSafe/ChainBridge/connections/ethereum/egs"
	"github.com/ChainSafe/chainbridge-utils/crypto/secp256k1"
	"github.com/ChainSafe/log15"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

var BlockRetryInterval = time.Second * 5

type Connection struct {
	endpoint         string
	http             bool
	kp               *secp256k1.Keypair
	gasLimit         *big.Int
	maxGasPrice      *big.Int
	gasMultiplier    *big.Float
	egsApiKey        string
	egsSpeed         string
	moonbeamFinality bool
	conn             *ethclient.Client
	connRPC          *rpc.Client

	// signer    ethtypes.Signer
	opts     *bind.TransactOpts
	callOpts *bind.CallOpts
	nonce    uint64
	optsLock sync.Mutex
	log      log15.Logger
	stop     chan int // All routines should exit when this channel is closed
}

// NewConnection returns an uninitialized connection, must call Connection.Connect() before using.
func NewConnection(endpoint string, http bool, kp *secp256k1.Keypair, log log15.Logger, gasLimit, gasPrice *big.Int, gasMultiplier *big.Float, gsnApiKey, gsnSpeed string, moonbeamFinality bool) *Connection {
	return &Connection{
		endpoint:         endpoint,
		http:             http,
		kp:               kp,
		gasLimit:         gasLimit,
		maxGasPrice:      gasPrice,
		gasMultiplier:    gasMultiplier,
		egsApiKey:        gsnApiKey,
		egsSpeed:         gsnSpeed,
		moonbeamFinality: moonbeamFinality,
		log:              log,
		stop:             make(chan int),
	}
}

// Connect starts the ethereum WS connection
func (c *Connection) Connect() error {
	c.log.Info("Connecting to ethereum chain...", "url", c.endpoint)
	var rpcClient *rpc.Client
	var err error
	// Start http or ws client
	if c.http {
		rpcClient, err = rpc.DialHTTP(c.endpoint)
	} else {
		rpcClient, err = rpc.DialContext(context.Background(), c.endpoint)
	}
	if err != nil {
		return err
	}
	c.conn = ethclient.NewClient(rpcClient)
	c.connRPC = rpcClient

	// Construct tx opts, call opts, and nonce mechanism
	opts, _, err := c.newTransactOpts(big.NewInt(0), c.gasLimit, c.maxGasPrice)
	if err != nil {
		return err
	}
	c.opts = opts
	c.nonce = 0
	c.callOpts = &bind.CallOpts{From: c.kp.CommonAddress()}
	return nil
}

// newTransactOpts builds the TransactOpts for the connection's keypair.
func (c *Connection) newTransactOpts(value, gasLimit, gasPrice *big.Int) (*bind.TransactOpts, uint64, error) {
	privateKey := c.kp.PrivateKey()
	address := ethcrypto.PubkeyToAddress(privateKey.PublicKey)

	nonce, err := c.conn.PendingNonceAt(context.Background(), address)
	if err != nil {
		return nil, 0, err
	}

	id, err := c.conn.ChainID(context.Background())
	if err != nil {
		return nil, 0, err
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, id)
	if err != nil {
		return nil, 0, err
	}

	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = value
	auth.GasLimit = uint64(gasLimit.Int64())
	auth.GasPrice = gasPrice
	auth.Context = context.Background()

	return auth, nonce, nil
}

func (c *Connection) Keypair() *secp256k1.Keypair {
	return c.kp
}

func (c *Connection) Client() *ethclient.Client {
	return c.conn
}

func (c *Connection) Opts() *bind.TransactOpts {
	return c.opts
}

func (c *Connection) CallOpts() *bind.CallOpts {
	return c.callOpts
}

func (c *Connection) SafeEstimateGas(ctx context.Context) (*big.Int, error) {

	var suggestedGasPrice *big.Int

	// First attempt to use EGS for the gas price if the api key is supplied
	if c.egsApiKey != "" {
		price, err := egs.FetchGasPrice(c.egsApiKey, c.egsSpeed)
		if err != nil {
			c.log.Error("Couldn't fetch gasPrice from GSN", "err", err)
		} else {
			suggestedGasPrice = price
		}
	}

	// Fallback to the node rpc method for the gas price if GSN did not provide a price
	if suggestedGasPrice == nil {
		c.log.Debug("Fetching gasPrice from node")
		nodePriceEstimate, err := c.conn.SuggestGasPrice(context.TODO())
		if err != nil {
			return nil, err
		} else {
			suggestedGasPrice = nodePriceEstimate
		}
	}

	gasPrice := multiplyGasPrice(suggestedGasPrice, c.gasMultiplier)

	// Check we aren't exceeding our limit
	if gasPrice.Cmp(c.maxGasPrice) == 1 {
		return c.maxGasPrice, nil
	} else {
		return gasPrice, nil
	}
}

func (c *Connection) EstimateGasLondon(ctx context.Context, baseFee *big.Int) (*big.Int, *big.Int, error) {
	var maxPriorityFeePerGas *big.Int
	var maxFeePerGas *big.Int

	if c.maxGasPrice.Cmp(baseFee) < 0 {
		maxPriorityFeePerGas = big.NewInt(1000000000)
		maxFeePerGas = new(big.Int).Add(c.maxGasPrice, maxPriorityFeePerGas)
		return maxPriorityFeePerGas, maxFeePerGas, nil
	}

	maxPriorityFeePerGas, err := c.conn.SuggestGasTipCap(context.TODO())
	if err != nil {
		return nil, nil, err
	}

	maxFeePerGas = new(big.Int).Add(
		maxPriorityFeePerGas,
		new(big.Int).Mul(baseFee, big.NewInt(2)),
	)

	if maxFeePerGas.Cmp(maxPriorityFeePerGas) < 0 {
		return nil, nil, fmt.Errorf("maxFeePerGas (%v) < maxPriorityFeePerGas (%v)", maxFeePerGas, maxPriorityFeePerGas)
	}

	// Check we aren't exceeding our limit
	if maxFeePerGas.Cmp(c.maxGasPrice) == 1 {
		maxPriorityFeePerGas.Sub(c.maxGasPrice, baseFee)
		maxFeePerGas = c.maxGasPrice
	}
	return maxPriorityFeePerGas, maxFeePerGas, nil
}

func multiplyGasPrice(gasEstimate *big.Int, gasMultiplier *big.Float) *big.Int {

	gasEstimateFloat := new(big.Float).SetInt(gasEstimate)

	result := gasEstimateFloat.Mul(gasEstimateFloat, gasMultiplier)

	gasPrice := new(big.Int)

	result.Int(gasPrice)

	return gasPrice
}

// LockAndUpdateOpts acquires a lock on the opts before updating the nonce
// and gas price.
func (c *Connection) LockAndUpdateOpts() error {
	c.optsLock.Lock()

	head, err := c.conn.HeaderByNumber(context.TODO(), nil)
	if err != nil {
		c.UnlockOpts()
		return err
	}

	if head.BaseFee != nil {
		c.opts.GasTipCap, c.opts.GasFeeCap, err = c.EstimateGasLondon(context.TODO(), head.BaseFee)
		if err == nil {
			// Both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) cannot be specified: https://github.com/ethereum/go-ethereum/blob/95bbd46eabc5d95d9fb2108ec232dd62df2f44ab/accounts/abi/bind/base.go#L254
			c.opts.GasPrice = nil
			c.log.Info("estimateGasLondon...", "GasTipCap", c.opts.GasTipCap.String(), "GasFeeCap", c.opts.GasFeeCap.String())
		} else {
			c.log.Info("estimateGasLondon failed", "error", err)
			if err.Error() == "Method not found" {
				var gasPrice *big.Int
				gasPrice, err = c.SafeEstimateGas(context.TODO())
				if err != nil {
					c.UnlockOpts()
					return err
				}
				c.log.Info("SafeEstimateGas...", "gasPrice", gasPrice.String())
				c.opts.GasPrice = gasPrice
			} else {
				c.UnlockOpts()
				return err
			}
		}
	} else {
		var gasPrice *big.Int
		gasPrice, err = c.SafeEstimateGas(context.TODO())
		if err != nil {
			c.UnlockOpts()
			return err
		}
		c.log.Info("SafeEstimateGas...", "gasPrice", gasPrice.String())
		c.opts.GasPrice = gasPrice
	}

	nonce, err := c.conn.PendingNonceAt(context.Background(), c.opts.From)
	if err != nil {
		c.optsLock.Unlock()
		return err
	}
	c.opts.Nonce.SetUint64(nonce)
	c.log.Info("PendingNonceAt, get nonce.", "nonce", nonce)
	return nil
}

func (c *Connection) UnlockOpts() {
	c.optsLock.Unlock()
}

// LatestBlock returns the latest block from the current chain
func (c *Connection) LatestBlock() (*big.Int, error) {
	if c.moonbeamFinality == true {
		return c.LatestFinalizedBlock()
	}

	header, err := c.conn.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	return header.Number, nil
}

// EnsureHasBytecode asserts if contract code exists at the specified address
func (c *Connection) EnsureHasBytecode(addr ethcommon.Address) error {
	code, err := c.conn.CodeAt(context.Background(), addr, nil)
	if err != nil {
		return err
	}

	if len(code) == 0 {
		return fmt.Errorf("no bytecode found at %s", addr.Hex())
	}
	return nil
}

// WaitForBlock will poll for the block number until the current block is equal or greater.
// If delay is provided it will wait until currBlock - delay = targetBlock
func (c *Connection) WaitForBlock(targetBlock *big.Int, delay *big.Int) error {
	for {
		select {
		case <-c.stop:
			return errors.New("connection terminated")
		default:
			currBlock, err := c.LatestBlock()
			if err != nil {
				return err
			}

			if delay != nil {
				currBlock.Sub(currBlock, delay)
			}

			// Equal or greater than target
			if currBlock.Cmp(targetBlock) >= 0 {
				return nil
			}
			c.log.Trace("Block not ready, waiting", "target", targetBlock, "current", currBlock, "delay", delay)
			time.Sleep(BlockRetryInterval)
			continue
		}
	}
}

// Close terminates the client connection and stops any running routines
func (c *Connection) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
	close(c.stop)
}

//
func (c *Connection) LatestFinalizedBlock() (*big.Int, error) {
	var raw json.RawMessage
	err := c.connRPC.CallContext(context.Background(), &raw, "chain_getFinalizedHead")
	if err != nil {
		c.log.Error("chain_getFinalizedHead failed", "error", err.Error())
		return nil, err
	}

	// The hash is with double quote "", should remove
	var blockHash string = string(raw)
	blockHash = blockHash[1 : len(blockHash)-1]
	//fmt.Println(blockHash)
	err = c.connRPC.CallContext(context.Background(), &raw, "chain_getHeader", blockHash)
	if err != nil {
		c.log.Error("chain_getHeader failed", "error", err.Error())
		return nil, err
	}

	var m map[string]interface{}
	if err = json.Unmarshal(raw, &m); err != nil {
		c.log.Error(err.Error())
		return nil, err
	}
	if m == nil {
		c.log.Error("body: empty body")
		return nil, errors.New("body: empty body")
	}

	/***
	for k, v := range m {
		fmt.Println("decoding", k, v)
	}
	***/
	number := m["number"].(string)
	// remove 0x
	number = number[2:]
	num, ok := new(big.Int).SetString(number, 16)
	if ok != true {
		return nil, err
	}
	return num, nil
}
