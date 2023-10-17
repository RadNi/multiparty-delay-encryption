package main


import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"time"
)


func genUV2(_s, _r, _n, _g, _t, _h []byte) UV {
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

	ret := UV{
		U: PadOrTrim(u.Bytes(), 2*lambda/8),
		V: PadOrTrim(v.Bytes(), 2*lambda/4),
	}

	return ret

}

type UV struct {
	U []byte
	V []byte
}

func PuzzleGen2(_n, _g, _time, _h []byte, l int64) ([]byte, []byte, []byte, []byte, []byte, []byte, []byte, []byte, []byte) {
	n := new(big.Int).SetBytes(_n)
	lambda := n.BitLen()/2 + 1
	g := new(big.Int).SetBytes(_g)
	time := new(big.Int).SetBytes(_time)
	h := new(big.Int).SetBytes(_h)
	two := new(big.Int).SetInt64(2)
	n_2 := new(big.Int).Div(n, two)
	n_2l := new(big.Int).Div(n_2, new(big.Int).SetInt64(l))
	n_l := new(big.Int).Div(n, new(big.Int).SetInt64(l))
	//n2 := new(big.Int).Mul(n, n)
	r, err := rand.Int(rand.Reader, n_2l)
	s, err := rand.Int(rand.Reader, n_2l)
	k, err := rand.Int(rand.Reader, n_2)
	n_2n_l := new(big.Int).Add(n_2, n_l)
	twolambda := ModExpWithSquaringPow2(new(big.Int).SetInt64(2), new(big.Int).SetInt64(int64(lambda)), n)
	two2lambda := ModExpWithSquaringPow2(twolambda, new(big.Int).SetInt64(2), n)
	x, err := rand.Int(rand.Reader, new(big.Int).Mul(n_2n_l, two2lambda))
	if err != nil {
		panic(err)
	}
	t, err := rand.Int(rand.Reader, new(big.Int).Mul(n_l, two2lambda))
	if err != nil {
		panic(err)
	}
	rps := new(big.Int).Add(s, r)
	c1 := make(chan UV)
	c2 := make(chan UV)
	c3 := make(chan UV)
	var u, v, y, w, _a, _b []byte
	//u, v := genUV(_s, rps.Bytes(), _n, _g, _time, _h)
	go func() {
		c1 <- genUV2(s.Bytes(), rps.Bytes(), _n, _g, _time, _h)
	}()
	go func() {
		c2 <- genUV2(r.Bytes(), k.Bytes(), _n, _g, _time, _h)
	}()
	go func() {
		c3 <- genUV2(t.Bytes(), x.Bytes(), _n, _g, _time, _h)
	}()

	out := <-c1
	u = out.U
	v = out.V
	out = <-c2
	y = out.U
	w = out.V
	out = <-c3
	_a = out.U
	_b = out.V
	a := new(big.Int).SetBytes(_a)
	b := new(big.Int).SetBytes(_b)

	tau := ModExpWithSquaring(g, t, n)

	sha := sha512.New()
	sha.Write(n.Bytes())
	sha.Write(g.Bytes())
	sha.Write(time.Bytes())
	sha.Write(h.Bytes())
	sha.Write(a.Bytes())
	sha.Write(b.Bytes())
	sha.Write(tau.Bytes())
	hsh := sha.Sum(nil)
	e := new(big.Int).SetBytes(hsh)
	e.Mod(e, n_2)

	alpha := new(big.Int).Add(r, s)
	alpha.Add(alpha, k)
	alpha.Mul(alpha, e)
	alpha.Add(alpha, x)
	// ---------------------------------------------------------

	beta := new(big.Int).Add(r, s)
	beta.Mul(beta, e)
	beta.Add(beta, t)
	return PadOrTrim(u, 2*lambda/8),
		PadOrTrim(v, 2*lambda/4),
		PadOrTrim(y, 2*lambda/8),
		PadOrTrim(w, 2*lambda/4),
		PadOrTrim(a.Bytes(), 2*lambda/8),
		PadOrTrim(b.Bytes(), 2*lambda/4),
		PadOrTrim(alpha.Bytes(), 2*lambda/4+1),
		PadOrTrim(beta.Bytes(), 2*lambda/4),
		PadOrTrim(tau.Bytes(), 2*lambda/8)
}

func PuzzleSolvePrivateKey(_u, _v, _y, _w, _n, _g, _t, _h []byte) []byte {
	u := new(big.Int).SetBytes(_u)
	v := new(big.Int).SetBytes(_v)
	y := new(big.Int).SetBytes(_y)
	w := new(big.Int).SetBytes(_w)
	n := new(big.Int).SetBytes(_n)
	t := new(big.Int).SetBytes(_t)
	lambda := n.BitLen()/2 + 1
	__u, __v, _, _ := PuzzleEval2(u.Bytes(), v.Bytes(), y.Bytes(), w.Bytes(), y.Bytes(), w.Bytes(),
		PadOrTrim(new(big.Int).SetInt64(1).Bytes(), 512), PadOrTrim(new(big.Int).SetInt64(1).Bytes(), 262144), n.Bytes())
	u.SetBytes(__u)
	v.SetBytes(__v)
	one := new(big.Int).SetInt64(1)
	n2 := new(big.Int)
	n2.Mul(n, n)
	x := ModExpWithSquaringPow2(u, t, n)
	// fmt.Printf("w: %v\n", w)
	winv := Inv(x, n)
	winvn := ModExpWithSquaring(winv, n, n2)
	// fmt.Printf("winv: %v winvn: %v\n", winv, winvn)
	s := new(big.Int)
	s = s.Mul(v, winvn)
	s = s.Mod(s, n2)
	s.Sub(s, one)
	s.Div(s, n)
	return PadOrTrim(s.Bytes(), 2*lambda/8)
}

func PuzzleSolve(_u, _v, _n, _g, _t, _h []byte) []byte {
	u := new(big.Int).SetBytes(_u)
	v := new(big.Int).SetBytes(_v)
	n := new(big.Int).SetBytes(_n)
	lambda := n.BitLen()/2 + 1

	fmt.Printf("puzzle started solving in lib: u: %v\n", u.Bytes())
	//h := new(big.Int).SetBytes(_h.Bytes())
	t := new(big.Int).SetBytes(_t)
	one := new(big.Int).SetInt64(1)
	n2 := new(big.Int)
	n2.Mul(n, n)
	w := ModExpWithSquaringPow2(u, t, n)
	// fmt.Printf("w: %v\n", w)
	winv := Inv(w, n)
	winvn := ModExpWithSquaring(winv, n, n2)
	// fmt.Printf("winv: %v winvn: %v\n", winv, winvn)
	s := new(big.Int)
	s = s.Mul(v, winvn)
	s = s.Mod(s, n2)
	s.Sub(s, one)
	s.Div(s, n)
	return PadOrTrim(s.Bytes(), 2*lambda/8)
}

func PuzzleEval2(_u1, _v1, _y1, _w1, _u2, _v2, _y2, _w2, _n []byte) ([]byte, []byte, []byte, []byte) {

	u1 := new(big.Int).SetBytes(_u1)
	v1 := new(big.Int).SetBytes(_v1)
	y1 := new(big.Int).SetBytes(_y1)
	w1 := new(big.Int).SetBytes(_w1)
	u2 := new(big.Int).SetBytes(_u2)
	v2 := new(big.Int).SetBytes(_v2)
	y2 := new(big.Int).SetBytes(_y2)
	w2 := new(big.Int).SetBytes(_w2)
	n := new(big.Int).SetBytes(_n)
	lambda := n.BitLen()/2 + 1

	v := new(big.Int)
	u := new(big.Int)
	y := new(big.Int)
	w := new(big.Int)
	n2 := new(big.Int)

	n2 = n2.Mul(n, n)

	u.Mul(u1, u2)
	u.Mod(u, n)

	v.Mul(v1, v2)
	v.Mod(v, n2)

	y.Mul(y1, y2)
	y.Mod(y, n)

	w.Mul(w1, w2)
	w.Mod(w, n2)

	return PadOrTrim(u.Bytes(), 2*lambda/8),
		PadOrTrim(v.Bytes(), 2*lambda/4),
		PadOrTrim(y.Bytes(), 2*lambda/8),
		PadOrTrim(w.Bytes(), 2*lambda/4)
}

func PuzzleVerify2(_u, _v, _y, _w, _a, _b, _alpha, _beta, _tau, _g, _h, _n, _t []byte) bool {
	// TODO u \in J_n
	// TODO a \in J_N
	// TODO t \in J_n
	// TODO b \in Z_{n^2}^*
	// TODO \alpha \in Z_n
	// TODO \beta \in Z_n
	u := new(big.Int).SetBytes(_u)
	v := new(big.Int).SetBytes(_v)
	y := new(big.Int).SetBytes(_y)
	w := new(big.Int).SetBytes(_w)
	a := new(big.Int).SetBytes(_a)
	b := new(big.Int).SetBytes(_b)
	alpha := new(big.Int).SetBytes(_alpha)
	beta := new(big.Int).SetBytes(_beta)
	tau := new(big.Int).SetBytes(_tau)
	g := new(big.Int).SetBytes(_g)
	h := new(big.Int).SetBytes(_h)
	n := new(big.Int).SetBytes(_n)
	t := new(big.Int).SetBytes(_t)
	n2 := new(big.Int).Mul(n, n)

	two := new(big.Int).SetInt64(2)
	n_2 := new(big.Int).SetBytes(n.Bytes())
	n_2.Div(n_2, two)
	sha := sha512.New()
	sha.Write(n.Bytes())
	sha.Write(g.Bytes())
	sha.Write(t.Bytes())
	sha.Write(h.Bytes())
	sha.Write(a.Bytes())
	sha.Write(b.Bytes())
	sha.Write(tau.Bytes())
	hsh := sha.Sum(nil)
	e := new(big.Int).SetBytes(hsh)
	e.Mod(e, n_2)

	uy := new(big.Int).Mul(u, y)
	uy.Mod(uy, n)

	uye := ModExpWithSquaring(uy, e, n)
	uye.Mod(uye, n)

	uyea := new(big.Int).Mul(uye, a)
	uyea.Mod(uyea, n)

	_galpha, _vagg := genUV(beta.Bytes(), alpha.Bytes(), n.Bytes(), g.Bytes(), t.Bytes(), h.Bytes())
	galpha := new(big.Int).SetBytes(_galpha)
	vagg := new(big.Int).SetBytes(_vagg)
	//galpha := ModExpWithSquaring(g, alpha, n)
	if galpha.Cmp(uyea) != 0 {
		fmt.Printf("false1\ngalpha: %v\nother: %v\n", galpha, uyea)
		return false
	}

	vweb := new(big.Int).Mul(v, w)
	vweb.Mod(vweb, n2)
	vweb = ModExpWithSquaring(vweb, e, n2)
	vweb.Mod(vweb, n2)
	vweb.Mul(vweb, b)
	vweb.Mod(vweb, n2)
	if vweb.Cmp(vagg) != 0 {
		fmt.Printf("false2\n")
		return false
	}

	gbeta := ModExpWithSquaring(g, beta, n)
	uetau := ModExpWithSquaring(u, e, n)
	uetau.Mul(uetau, tau)
	uetau.Mod(uetau, n)

	if gbeta.Cmp(uetau) != 0 {
		fmt.Printf("false3\n")
		return false
	}

	return true
}

func MockGenerator(n, g, h, t *big.Int) ([]byte, []byte, []byte, []byte) {
	u := new(big.Int).SetInt64(1)
	v := new(big.Int).SetInt64(1)
	y := new(big.Int).SetInt64(1)
	w := new(big.Int).SetInt64(1)
	//sum := new(big.Int).SetInt64(0)

	var l int64 = 10
	var generation, eval, ver time.Duration

	for i := 0; i < int(l); i++ {
		//sum.Add(sum, s)
		start := time.Now()
		up, vp, yp, wp, ap, bp, alphap, betap, taup := PuzzleGen2(n.Bytes(), g.Bytes(), t.Bytes(), h.Bytes(), l)
		elapsed := time.Since(start)
		generation += elapsed
		log.Printf("Generation took %s", elapsed)
		start = time.Now()
		fmt.Printf("verify: %d %v\n", i, PuzzleVerify2(up, vp, yp, wp, ap, bp, alphap, betap, taup, g.Bytes(), h.Bytes(), n.Bytes(), t.Bytes()))
		elapsed = time.Since(start)
		ver += elapsed
		//up, vp, _, _, _, _, _, _, _ := PuzzleGen2(s.Bytes(), n.Bytes(), g.Bytes(), time.Bytes(), h.Bytes())
		start = time.Now()
		_u, _v, _y, _w := PuzzleEval2(u.Bytes(), v.Bytes(), y.Bytes(), w.Bytes(), up, vp, yp, wp, n.Bytes())
		elapsed = time.Since(start)
		eval += elapsed
		log.Printf("Eval took %s", elapsed)
		//_u, _v := PuzzleEval(u.Bytes(), v.Bytes(), up, vp, n.Bytes())
		u.SetBytes(_u)
		v.SetBytes(_v)
		y.SetBytes(_y)
		w.SetBytes(_w)
	}
	log.Printf("Generation on average took %s", generation)
	log.Printf("Eval on average took %s", eval)
	log.Printf("Verify on average took %s", ver)
	//fmt.Printf("S: %v\n", sum)
	return u.Bytes(), v.Bytes(), y.Bytes(), w.Bytes()
}

func main() {
	p1 := []byte{00, 0x99, 0x00, 0x0d, 0xd4, 0xc8, 0x77, 0xe9, 0xbe, 0x0a, 0xef, 0x2c, 0x61, 0xa7, 0x25, 0x18, 0x1f, 0xcd, 0xa9, 0x1b, 0x83, 0x70, 0xc3, 0xe6, 0xb0, 0x2d, 0x3e, 0x3b, 0x20, 0xf2, 0x29, 0x9f, 0x2b, 0x9a, 0x91, 0x9b, 0x9d, 0x21, 0xf6, 0xbe, 0xfe, 0x2c, 0xbf, 0xae, 0x38, 0x89, 0x0b, 0xe1, 0x0a, 0x11, 0x17, 0x29, 0x8d, 0xa7, 0x4d, 0x8b, 0x07, 0x35, 0x77, 0x74, 0xa3, 0xcd, 0x04, 0x93, 0x12, 0x09, 0x8a, 0x83, 0xae, 0xeb, 0x01, 0x36, 0x2c, 0x1c, 0xdb, 0x7d, 0x0f, 0x5d, 0x94, 0xc9, 0x6b, 0x99, 0xb8, 0x88, 0xce, 0xbe, 0xfc, 0x69, 0xc2, 0x2d, 0xb0, 0x16, 0xdd, 0xa2, 0x8b, 0x20, 0xef, 0x7b, 0x94, 0xd4, 0x5e, 0x32, 0x4a, 0x88, 0x04, 0x2e, 0x3f, 0xd8, 0xb4, 0x2c, 0x1f, 0x2e, 0xdb, 0x8e, 0x7f, 0x6e, 0x4f, 0xf8, 0x39, 0xee, 0xef, 0x47, 0x92, 0x28, 0xfa, 0x45, 0x9e, 0x37, 0x19, 0xc0, 0x62, 0x5d, 0x95, 0x99, 0xdf, 0xde, 0xa5, 0x57, 0xba, 0x9c, 0x56, 0xf8, 0x1b, 0x1e, 0x7b, 0xcd, 0xdf, 0x9c, 0xd0, 0x3f, 0x21, 0x3c, 0x42, 0xd9, 0xeb, 0xb0, 0x33, 0x64, 0x82, 0xf6, 0xdc, 0xaf, 0x38, 0x2e, 0xbc, 0xed, 0x01, 0x4a, 0xe2, 0x35, 0x88, 0x01, 0x71, 0x3e, 0x6e, 0x4a, 0x96, 0x86, 0x9d, 0x7b, 0x9c, 0xba, 0xe1, 0x78, 0x86, 0x5f, 0x88, 0x15, 0xab, 0x88, 0xa5, 0x2a, 0xa6, 0x34, 0x3f, 0xa0, 0xf7, 0x2d, 0xcb, 0x00, 0xbc, 0x45, 0x9f, 0xb7, 0x4a, 0x9b, 0x49, 0x34, 0x65, 0x46, 0x59, 0xbf, 0x73, 0x37, 0xf5, 0x73, 0xe4, 0xc0, 0x47, 0x76, 0x59, 0x6a, 0x44, 0xad, 0x1b, 0x2d, 0x7e, 0x5a, 0x69, 0x44, 0x27, 0x97, 0xd6, 0xdd, 0xb5, 0xfa, 0xad, 0x4a, 0x7c, 0x56, 0xae, 0x3b, 0x96, 0x01, 0x05, 0x85, 0xfd, 0x6a, 0x47, 0xc3, 0x57, 0x67, 0xdf, 0x60, 0x15, 0xf0, 0x93}
	p2 := []byte{00, 0x97, 0xd7, 0x15, 0x44, 0x90, 0xe9, 0xfb, 0x8f, 0x69, 0xca, 0xf0, 0x7a, 0x6f, 0xbf, 0x9c, 0x79, 0xef, 0x30, 0xb6, 0xf0, 0x17, 0xf5, 0x73, 0xab, 0x92, 0x7b, 0xcb, 0x5a, 0xb8, 0xf2, 0x54, 0x54, 0x4c, 0x60, 0x20, 0x4d, 0x09, 0xb8, 0xa9, 0x5a, 0xdf, 0x3c, 0xb6, 0x2e, 0xb0, 0x6c, 0x51, 0x43, 0xb5, 0xf3, 0x2b, 0x1a, 0xdb, 0x69, 0x4e, 0x29, 0x2b, 0xc5, 0x4d, 0x4b, 0x58, 0x9f, 0x49, 0x2e, 0x13, 0xcc, 0xb4, 0x2c, 0x94, 0xe6, 0x31, 0xb6, 0xc1, 0x38, 0x64, 0x6d, 0x4f, 0x29, 0xd9, 0x14, 0x7b, 0xa0, 0x73, 0x44, 0xed, 0x85, 0xb9, 0xee, 0x33, 0x5d, 0x0f, 0x40, 0x79, 0xc4, 0xd5, 0xd5, 0x20, 0xf5, 0x1d, 0xd1, 0x13, 0xf1, 0x21, 0x59, 0x98, 0x96, 0x27, 0xc9, 0x42, 0x23, 0x1c, 0xb0, 0xd6, 0xb6, 0x44, 0x03, 0x26, 0xf2, 0xe4, 0xf4, 0x54, 0xa5, 0x83, 0x64, 0x2b, 0x56, 0x13, 0xba, 0x20, 0x4c, 0x32, 0xda, 0xee, 0xdd, 0x78, 0x1d, 0x67, 0xe2, 0x8a, 0x59, 0x30, 0x3f, 0xc0, 0x93, 0x10, 0x94, 0xe5, 0xff, 0xfa, 0x9d, 0x44, 0xb7, 0xc7, 0xf7, 0xe8, 0x8c, 0x93, 0xb5, 0x96, 0x2b, 0xb1, 0xc6, 0xce, 0xc1, 0x89, 0x2e, 0xa8, 0x2c, 0x26, 0xca, 0x17, 0xe0, 0xfa, 0x5f, 0x51, 0x29, 0xa7, 0x58, 0xb3, 0xe2, 0xf0, 0x8e, 0xc9, 0x78, 0xec, 0x48, 0xa8, 0x99, 0x16, 0xfc, 0xe9, 0x54, 0x04, 0xba, 0x65, 0x8e, 0xef, 0x0c, 0xcf, 0xce, 0x3a, 0x34, 0x10, 0x21, 0xa3, 0xbb, 0x86, 0x4e, 0x75, 0xf4, 0x44, 0x3f, 0xa5, 0x15, 0xfe, 0xca, 0x17, 0x97, 0x9d, 0x8d, 0xa1, 0x25, 0x77, 0xbc, 0x27, 0xff, 0xff, 0x40, 0xe0, 0x52, 0x79, 0x7f, 0x94, 0x09, 0x32, 0x99, 0x15, 0xb4, 0x42, 0xdc, 0x8a, 0xa7, 0x5f, 0x49, 0x0d, 0x17, 0x93, 0x88, 0xa6, 0xb2, 0xbe, 0x54, 0xbd, 0xed, 0x40, 0x63}
	p1 = []byte{0x9B, 0xB5, 0x76, 0x9E, 0x11, 0xFC, 0x43, 0x1E, 0x25, 0x21, 0xD6, 0x3F,
		0xE9, 0x5A, 0xD7, 0x4C, 0x0F, 0xD6, 0xEC, 0xD5, 0xFD, 0x9B, 0xB2, 0xDA,
		0x01, 0x99, 0x51, 0xA5, 0xA7, 0x82, 0xCB, 0xD6, 0xFD, 0xBA, 0xD6, 0x68,
		0xC6, 0x62, 0x76, 0x30, 0xC6, 0x6A, 0x73, 0x9E, 0x27, 0x47, 0x92, 0x91,
		0xA0, 0xC1, 0x0B, 0xB8, 0x29, 0x8D, 0xB9, 0x5D, 0x65, 0xFB, 0x52, 0xD2,
		0xED, 0xA9, 0x14, 0x03}
	p2 = []byte{0xFF, 0x73, 0xF0, 0x5E, 0x67, 0x7E, 0xC3, 0xCB, 0xA0, 0x29, 0x17, 0x8E,
		0x8C, 0x01, 0xFA, 0x9B, 0x64, 0xB0, 0xF8, 0x76, 0x04, 0x95, 0x60, 0x7A,
		0x6D, 0x7F, 0xAD, 0x7B, 0x79, 0x94, 0x90, 0x62, 0xFF, 0xF8, 0xB2, 0xD7,
		0xA7, 0x4F, 0x13, 0x56, 0x57, 0x9C, 0x9E, 0x5B, 0xEA, 0x88, 0x62, 0xD2,
		0x50, 0xAF, 0xE2, 0x7D, 0x30, 0x5F, 0x63, 0xC4, 0xB8, 0x85, 0x3C, 0xE3,
		0xA9, 0x17, 0x3D, 0xD3}
	// aa := new(big.Int).SetBytes(a)
	// fmt.Printf("%v %v\n", a, aa)
	// b1, _ := readPEM("prime1.pem")
	// p1 = []byte{0x2f}
	// p2 = []byte{0x17}
	prime1 := new(big.Int)
	prime1.SetBytes(p1)

	// b2, _ := readPEM("prime2.pem")
	prime2 := new(big.Int)
	prime2.SetBytes(p2)

	//fmt.Printf("p1: %v\np2: %v\n", prime1, prime2)
	//pp1 := new(big.Int).Div(new(big.Int).Sub(prime1, new(big.Int).SetInt64(1)), new(big.Int).SetInt64(2))
	//pp2 := new(big.Int).Div(new(big.Int).Sub(prime2, new(big.Int).SetInt64(1)), new(big.Int).SetInt64(2))
	//ord := new(big.Int).Mul(new(big.Int).Mul(pp1, pp2), new(big.Int).SetInt64(2))
	n := new(big.Int)
	n.Mul(prime1, prime2)
	fmt.Printf("size: %v\n", n.BitLen())
	// base := new(big.Int).SetInt64(2312412412)
	// exp := new(big.Int).SetInt64(4812984914)
	// gen, _ := sample(n)
	gen := new(big.Int).SetInt64(4)
	//identity := ModExpWithSquaring(gen, ord, n)
	//fmt.Printf("iidentity: %v\n", identity)
	t := new(big.Int).SetBytes([]byte{0x09, 0x32, 0x26})
	fmt.Printf("generating puzzle with t: %v\n", t.Int64())
	// fmt.Printf("gen: %v\nn: %v\n", gen, n)
	gt := ModExpWithSquaringPow2(gen, t, n)
	nt := new(big.Int).Mul(prime1, prime2)
	//fmt.Printf("%v\n", PuzzleSolve(ut.Bytes(), vt.Bytes(), nt.Bytes(), gen.Bytes(), t.Bytes(), gt.Bytes()))
	//st := new(big.Int).SetInt64(24)
	//uu, vv, a, b, alpha, beta, tau := PuzzleGen(st.Bytes(), nt.Bytes(), gen.Bytes(), t.Bytes(), gt.Bytes())
	//uu, vv, _, _, _, _, _, _, _ := PuzzleGen2(st.Bytes(), nt.Bytes(), gen.Bytes(), t.Bytes(), gt.Bytes())
	uu, vv, yy, ww := MockGenerator(nt, gen, gt, t)
	//fmt.Printf("verify: %v\n", PuzzleVerify(uu, vv, a, b, alpha, beta, tau, gen.Bytes(), gt.Bytes(), n.Bytes(), t.Bytes()))
	//sol := PuzzleSolve(uu, vv, n.Bytes(), gen.Bytes(), t.Bytes(), gt.Bytes())
	pk := PublicKey{
		G: gen,
		P: n,
		Y: new(big.Int).SetBytes(uu),
	}
	message := []byte{0x24, 0x12}
	encrypt_time := time.Now()
	u1, u2, _ := Encrypt(rand.Reader, &pk, message)
	log.Printf("Encryption time took %s", time.Since(encrypt_time))
	solving_time := time.Now()
	sol2 := PuzzleSolvePrivateKey(uu, vv, yy, ww, n.Bytes(), gen.Bytes(), t.Bytes(), gt.Bytes())
	log.Printf("Solving time took %s", time.Since(solving_time))
	sol := PuzzleSolve(uu, vv, n.Bytes(), gen.Bytes(), t.Bytes(), gt.Bytes())
	ps := &PrivateKey{
		PublicKey: pk,
		X:         new(big.Int).SetBytes(sol2),
	}
	decrypt_time := time.Now()
	dec, _ := Decrypt(ps, u1, u2)
	log.Printf("Decryption time took %s", time.Since(decrypt_time))
	fmt.Printf("u: %v\nv: %v\n", uu, new(big.Int).SetBytes(vv).String())
	fmt.Printf("t: %v\nn: %v\n", t.String(), n.String())
	fmt.Printf("sol: %v\n", sol)
	fmt.Printf("dec: %v\n", dec)
}


