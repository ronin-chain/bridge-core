package utils

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

type SignMethodConfig struct {
	PlainPrivateKey string `json:"plainPrivateKey,omitempty" mapstructure:"plainPrivateKey"`
}

func NewSignMethod(config *SignMethodConfig) (ISign, error) {
	return NewPrivateKeySign(config.PlainPrivateKey)
}

type ISign interface {
	// Sign receives raw message, not hash of message
	Sign(message []byte, dataType string) ([]byte, error)
	GetAddress() common.Address
}

type PrivateKeySign struct {
	privateKey *ecdsa.PrivateKey
}

func NewPrivateKeySign(plainPrivateKey string) (*PrivateKeySign, error) {
	privateKey, err := crypto.HexToECDSA(plainPrivateKey)
	if err != nil {
		log.Error("[NewPrivateKeySign] error while getting plain private key", "err", err)
		return nil, err
	}

	return &PrivateKeySign{
		privateKey: privateKey,
	}, nil
}

type PrivateKeyConfig struct {
	PrivateKey string `json:"privateKey"`
}

func (privateKeySign *PrivateKeySign) Sign(message []byte, dataType string) ([]byte, error) {
	return crypto.Sign(crypto.Keccak256(message), privateKeySign.privateKey)
}

func (privateKeySign *PrivateKeySign) GetAddress() common.Address {
	return crypto.PubkeyToAddress(privateKeySign.privateKey.PublicKey)
}
