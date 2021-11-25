package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type PrivateTxType string

const (
	PrivateTxTypeRestricted PrivateTxType = "restricted"
)

type PrivateETHTransactionParams struct {
	PrivateFrom    string
	PrivateFor     []string
	PrivacyGroupID string
	PrivateTxType  PrivateTxType
}

func NewTransaction(_value, _gasPrice, _gasLimit, _data, _nonce, _toAddr string) *types.Transaction {
	// No need to validate the data as we know that internally the values are correct
	value, _ := new(big.Int).SetString(_value, 10)
	gasPrice, _ := new(big.Int).SetString(_gasPrice, 10)
	data, _ := hexutil.Decode(_data)
	nonce, _ := strconv.ParseUint(_nonce, 10, 64)
	gasLimit, _ := strconv.ParseUint(_gasLimit, 10, 64)
	toAddr := common.HexToAddress(_toAddr)

	txData := &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       &toAddr,
		Value:    value,
		Data:     data,
	}

	return types.NewTx(txData)
}

func NewEEATransaction(_privateFrom string, _privateFor []string, privacyGroupID string) *PrivateETHTransactionParams {
	return &PrivateETHTransactionParams{
		PrivateFrom:    _privateFrom,
		PrivateFor:     _privateFor,
		PrivacyGroupID: privacyGroupID,
		PrivateTxType:  PrivateTxTypeRestricted,
	}
}

func getEncodedPrivateFrom(privateFrom string) ([]byte, error) {
	privateFromEncoded, err := base64.StdEncoding.DecodeString(privateFrom)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 value for 'privateFrom'. %s", err.Error())
	}

	return privateFromEncoded, nil
}

func getEncodedPrivateRecipient(privacyGroupID string, privateFor []string) (interface{}, error) {
	var privateRecipientEncoded interface{}
	var err error
	if privacyGroupID != "" {
		privateRecipientEncoded, err = base64.StdEncoding.DecodeString(privacyGroupID)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 value for 'privacyGroupId'. %s", err.Error())
		}
	} else {
		var privateForByteSlice [][]byte
		for _, v := range privateFor {
			b, der := base64.StdEncoding.DecodeString(v)
			if der != nil {
				return nil, fmt.Errorf("invalid base64 value for 'privateFor'. %s", err.Error())
			}
			privateForByteSlice = append(privateForByteSlice, b)
		}
		privateRecipientEncoded = privateForByteSlice
	}

	return privateRecipientEncoded, nil
}

func eeaTransactionPayload(tx *types.Transaction, privateArgs *PrivateETHTransactionParams, chainID string) ([]byte, error) {
	chainIDBigInt, ok := new(big.Int).SetString(chainID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid chainID")
	}

	privateFromEncoded, err := getEncodedPrivateFrom(privateArgs.PrivateFrom)
	if err != nil {
		return nil, err
	}

	privateRecipientEncoded, err := getEncodedPrivateRecipient(privateArgs.PrivacyGroupID, privateArgs.PrivateFor)
	if err != nil {
		return nil, err
	}

	var hash = common.Hash{}
	hashAlgo := sha3.NewLegacyKeccak256()
	err = rlp.Encode(hashAlgo, []interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		chainIDBigInt,
		uint(0),
		uint(0),
		privateFromEncoded,
		privateRecipientEncoded,
		privateArgs.PrivateTxType,
	})
	if err != nil {
		return nil, err
	}

	hashAlgo.Sum(hash[:0])
	return hash.Bytes(), nil
}

func SignTransaction(privKey *ecdsa.PrivateKey, transaction *types.Transaction, privateArgs *PrivateETHTransactionParams, chainID string) (string, error) {
	hash, err := eeaTransactionPayload(transaction, privateArgs, chainID)
	if err != nil {
		return "", err
	}

	signature, err := crypto.Sign(hash, privKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign eea transaction. %s", err.Error())
	}
	
	chainIDBigInt := new(big.Int)
	chainIDBigInt, _ = chainIDBigInt.SetString(chainID, 10)
	chainSigner := types.NewEIP155Signer(chainIDBigInt)
	
	signedTx, err := transaction.WithSignature(chainSigner, signature)
	if err != nil {
		return "", fmt.Errorf("failed to set eea transaction signature. %s", err.Error())
	}
	
	v, r, s := signedTx.RawSignatureValues()
	privateFromEncoded, err := getEncodedPrivateFrom(privateArgs.PrivateFrom)
	if err != nil {
		return "", err
	}

	privateRecipientEncoded, err := getEncodedPrivateRecipient(privateArgs.PrivacyGroupID, privateArgs.PrivateFor)
	if err != nil {
		return "", err
	}
	
	signedRaw, err := rlp.EncodeToBytes([]interface{}{
		transaction.Nonce(),
		transaction.GasPrice(),
		transaction.Gas(),
		transaction.To(),
		transaction.Value(),
		transaction.Data(),
		v,
		r,
		s,
		privateFromEncoded,
		privateRecipientEncoded,
		privateArgs.PrivateTxType,
	})

	if err != nil {
		return "", fmt.Errorf("failed to RLP encode signed eea transaction. %s", err.Error())
	}

	return hexutil.Encode(signedRaw), nil
}


func main() {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	
	chainID := "2555"
	txValue := "0"
	txGasPrice := "0"
	txData := "0x0"
	txNonce := "0x1"
	txToAddr := "0x0000000000000000a1b2c3d4e5f67890"
	
	txPrivFrom := "BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo="
	txPrivFor := []string{"QfeDAys9MPDs2XHExtc84jKGHxZg/aj52DTh0vtA3Xc=", "BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo="}
	txPrivGroupID := ""
	
	privTxParams := NewEEATransaction(txPrivFrom, txPrivFor, txPrivGroupID)
	txWithZeroGas := NewTransaction(txValue, txGasPrice, "0", txData, txNonce, txToAddr)
	txWithNonZeroGas := NewTransaction(txValue, txGasPrice, "900000", txData, txNonce, txToAddr)
	
	address := crypto.PubkeyToAddress(privKey.PublicKey)
	log.Println("Public address of signer:\t", address)
	
	signedTxWithZeroGas, err := SignTransaction(privKey, txWithZeroGas, privTxParams, chainID)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Println("Signed TxData (Zero Gas Gas):\t", signedTxWithZeroGas)
	
	signedTxWithNonZeroGas, err := SignTransaction(privKey, txWithNonZeroGas, privTxParams, chainID)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Println("Signed TxData (Non-Zero Gas):\t", signedTxWithNonZeroGas)
	
	log.Println("execution completed")
}


