package main

import (
    "context"
    "crypto/ecdsa"
    "encoding/hex"
    "log"
    "math/big"
    "os"
    "time"

    "github.com/ethereum/go-ethereum"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
)

type Listener struct {
    logger          *log.Logger
    contractAddress common.Address
}

func (lis *Listener) ListenForJobEvents(ctx context.Context, rpcClient *ethclient.Client) error {
   /*  ticker := time.NewTicker(10 * time.Second)
    lis.logger.Println("Listener set to send new task every 10 seconds...")
    defer ticker.Stop()
    taskNum := int64(0)

    // Send the first task immediately
    _ = sendNewTask(rpcClient, big.NewInt(taskNum), lis.contractAddress, lis.logger)
    taskNum++ */

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
        case <-ticker.C:
            err := sendNewTask(rpcClient, big.NewInt(taskNum), lis.contractAddress, lis.logger)
            taskNum++
            if err != nil {
                lis.logger.Println("Error sending new task:", err)
            }
        case vLog := <-logs:
            lis.logger.Println("Received IncredibleSquaringTaskManager event", "vLog", vLog)
            // Process the event and send a new task
            err := sendNewTask(rpcClient, big.NewInt(taskNum), lis.contractAddress, lis.logger)
            taskNum++
            if err != nil {
                lis.logger.Println("Error sending new task:", err)
            }
        case err := <-sub.Err():
            return err
        }
    }
}

func sendNewTask(client *ethclient.Client, taskNum *big.Int, contractAddress common.Address, logger *log.Logger) error {
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
    tx := types.NewTransaction(nonce, contractAddress, big.NewInt(0), uint64(300000), gasPrice, dataBytes)

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

    logger.Printf("Sent new task with number: %s to contract: %s", taskNum.String(), contractAddress.Hex())
    return nil
}

func main() {
    // Set up the Ethereum client to connect to a local node
    client, err := ethclient.Dial("http://localhost:8545")
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

    // Define the context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Start listening for job events
    err = listener.ListenForJobEvents(ctx, client)
    if err != nil {
        logger.Fatalf("Error while listening for job events: %v", err)
    }
}
