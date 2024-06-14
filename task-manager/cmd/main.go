package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Config struct {
	Environment   string `yaml:"environment"`
	EthRpcUrl     string `yaml:"eth_rpc_url"`
	EthWsUrl      string `yaml:"eth_ws_url"`
	Notifications struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"notifications"`
}

type Listener struct {
	logger          *log.Logger
	contractAddress common.Address
}

func (lis *Listener) ListenForJobEvents(ctx context.Context, rpcClient *ethclient.Client) error {
	// Subscribe to the IncredibleSquaringTaskManager contract events
	query := ethereum.FilterQuery{
		Addresses: []common.Address{lis.contractAddress},
	}
	logs := make(chan types.Log)
	sub, err := rpcClient.SubscribeFilterLogs(ctx, query, logs)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return nil
		case vLog := <-logs:
			lis.logger.Println("Received IncredibleSquaringTaskManager event", "vLog", vLog)
			// Process the event and send a new task
			err := lis.sendNewTask(rpcClient, big.NewInt(0))
			if err != nil {
				lis.logger.Println("Error sending new task:", err)
			}
		case err := <-sub.Err():
			return err
		}
	}
}

func (lis *Listener) sendNewTask(client *ethclient.Client, taskNum *big.Int) error {
	privateKey, err := crypto.HexToECDSA("96f5385132887200ce8a069b32ec1d21addafa2c954657d8e27bd3340e0d05f6")
	if err != nil {
		return err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return err
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return err
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}

	// Manually encode the function call
	functionSelector := crypto.Keccak256Hash([]byte("registerTask(uint256)")).Hex()[:10] // First 4 bytes of Keccak256 hash
	taskNumHex := common.BigToHash(taskNum).Hex()[2:]                                   // Encode taskNum as hex, remove "0x"
	data := functionSelector + taskNumHex

	// Convert the data string to bytes
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		return err
	}

	// Create the transaction
	tx := types.NewTransaction(nonce, lis.contractAddress, big.NewInt(0), uint64(300000), gasPrice, dataBytes)

	// Sign the transaction
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return err
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return err
	}

	// Send the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	lis.logger.Printf("Sent new task with number: %s to contract: %s", taskNum.String(), lis.contractAddress.Hex())
	return nil
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func main() {
	// Load configuration
	config, err := loadConfig("config-files/task-manager.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Set up the Ethereum client to connect to a local node
	client, err := ethclient.Dial(config.EthRpcUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	// Set up the logger
	logger := log.New(os.Stdout, "Listener: ", log.LstdFlags)

	// Define the contract address
	contractAddress := common.HexToAddress("0xb81c6Ac1385FaaC61a84337e916018c730b1B9Af")

	// Create the Listener instance
	listener := &Listener{
		logger:          logger,
		contractAddress: contractAddress,
	}

	// Check if notifications are enabled
	if !config.Notifications.Enabled {
		logger.Println("Notifications are disabled in the configuration.")
		// Exit the application since notifications are not supported
		os.Exit(0)
	}

	// Define the context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start listening for job events
	err = listener.ListenForJobEvents(ctx, client)
	if err != nil {
		logger.Fatalf("Error while listening for job events: %v", err)
	}
}
