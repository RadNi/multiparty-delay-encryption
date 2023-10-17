package main

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func PadOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}
	if l > size {
		return bb[l-size:]
	}
	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)
	return tmp
}

func ReadPEM(filename string) (*pem.Block, []byte) {
	b, err := os.ReadFile(filename) // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	return pem.Decode(b)
}


func Sample(n *big.Int) (*big.Int, *big.Int) {
	var nBig *big.Int
	one := new(big.Int).SetInt64(1)
	zero := new(big.Int).SetInt64(0)
	x := new(big.Int)
	inv := new(big.Int)
	gcd := new(big.Int)
	for {
		var err error
		nBig, err = rand.Int(rand.Reader, n)
		if err != nil {
			panic(err)
		}
		gcd.GCD(inv, x, nBig, n)
		if one.Cmp(gcd) == 0 {
			break
		}
	}
	two := new(big.Int).SetInt64(2)
	nBig = ModExpWithSquaring(nBig, two, n)
	// nBig = new(big.Int).SetBytes([]byte{0x02, 0x21})
	gcd.GCD(inv, x, nBig, n)
	if inv.Cmp(zero) <= 0 {
		inv.Add(inv, n)
	}
	return nBig, inv
}

func ModExpWithSquaringPow2(gen, t, modulus *big.Int) *big.Int {
	i := new(big.Int).SetInt64(0)
	two := new(big.Int).SetInt64(2)
	one := new(big.Int).SetInt64(1)
	for {
		gen = ModExpWithSquaring(gen, two, modulus)
		i.Add(i, one)
		if i.Cmp(t) == 0 {
			return gen
		}
	}
}

// ModExpWithSquaring calculates modular exponentiation with exponentiation by squaring, O(log exponent).
func ModExpWithSquaring(_base, _exponent, _modulus *big.Int) *big.Int {
	base := new(big.Int).SetBytes(_base.Bytes())
	exponent := new(big.Int).SetBytes(_exponent.Bytes())
	modulus := new(big.Int).SetBytes(_modulus.Bytes())
	zero := new(big.Int)
	one := new(big.Int)
	two := new(big.Int)
	zero.SetInt64(0)
	one.SetInt64(1)
	two.SetInt64(2)
	if exponent.Cmp(one) == 0 {
		ret := new(big.Int).SetBytes(base.Bytes())
		return ret
	}
	newExp := new(big.Int)
	newExp.Div(exponent, two)
	res := new(big.Int)
	res = ModExpWithSquaring(base, newExp, modulus)
	res.Mul(res, res)
	res.Mod(res, modulus)
	and := new(big.Int)
	and.And(exponent, one)
	if and.Cmp(zero) != 0 {
		mod := new(big.Int)
		mod.Mod(base, modulus)
		res.Mul(res, mod)
		res.Mod(res, modulus)
		return res
	}
	res.Mod(res, modulus)
	return res
}

func Inv(x, n *big.Int) *big.Int {
	zero := new(big.Int).SetInt64(0)
	inv := new(big.Int)
	y := new(big.Int)
	gcd := new(big.Int)
	gcd.GCD(inv, y, x, n)
	// fmt.Printf("x: %v n: %v, inv: %v gcd: %v\n", x, n, inv, gcd)
	if inv.Cmp(zero) < 0 {
		inv.Add(inv, n)
		return inv
	}
	return inv
}

func genUV(_s, _r, _n, _g, _t, _h []byte) ([]byte, []byte) {
	s := new(big.Int).SetBytes(_s)
	r := new(big.Int).SetBytes(_r)
	n := new(big.Int).SetBytes(_n)
	g := new(big.Int).SetBytes(_g)
	lambda := n.BitLen()/2 + 1

	//    t := new(big.Int).SetBytes(_t.Bytes())
	h := new(big.Int).SetBytes(_h)
	//fmt.Printf("%v\n", 1)
	one := new(big.Int).SetInt64(1)
	//fmt.Printf("%v\n", 2)
	u := ModExpWithSquaring(g, r, n)
	//rn := new(big.Int).Mul(r, n)
	n2 := new(big.Int).Mul(n, n)
	//fmt.Printf("%v\n", 3)
	hr := ModExpWithSquaring(h, r, n)
	hrn := ModExpWithSquaring(hr, n, n2)
	//fmt.Printf("%v\n", 4)
	n.Add(n, one)
	//fmt.Printf("%v\n", 5)
	v := ModExpWithSquaring(n, s, n2)
	//fmt.Printf("%v\n", 6)
	v = v.Mul(v, hrn)
	v.Mod(v, n2)

	return PadOrTrim(u.Bytes(), 2*lambda/8), PadOrTrim(v.Bytes(), 2*lambda/4)

}

