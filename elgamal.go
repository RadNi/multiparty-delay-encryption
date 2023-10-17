package main

import (
	"crypto/rand"
	"io"
	"math/big"
)

type PublicKey struct {
	G,
	P,
	Y *big.Int
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

func Encrypt(random io.Reader, pub *PublicKey, msg []byte) (a, b *big.Int, err error) {

	k, err := rand.Int(random, pub.P)
	if err != nil {
		panic(err)
	}

	m := new(big.Int).SetBytes(msg)

	a = new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	b = s.Mul(s, m)
	b.Mod(b, pub.P)

	return
}

func Decrypt(priv *PrivateKey, a, b *big.Int) (msg []byte, err error) {
	s := new(big.Int).Exp(a, priv.X, priv.P)
	s.ModInverse(s, priv.P)
	s.Mul(s, b)
	s.Mod(s, priv.P)
	em := s.Bytes()

	return em, nil
}

