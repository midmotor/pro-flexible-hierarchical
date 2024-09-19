package bls

import (
	"crypto/sha256"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var msg = "FLEXHI"

type Pf struct {
	c fr.Element
	z fr.Element
}

func PSign(msg []byte, secret fr.Element) bls.G1Jac {

	roMsgAf, _ := bls.HashToG1(msg, []byte("DST"))
	roMsg := *new(bls.G1Jac).FromAffine(&roMsgAf)
	sigma := new(bls.G1Jac).ScalarMultiplication(&roMsg, secret.BigInt(&big.Int{}))
	return *sigma
}

func PVerify(msg []byte, sigma bls.G1Jac, vk bls.G2Affine) bool {

	roMsg, _ := bls.HashToG1(msg, []byte("DST"))
	sigmaAff := *new(bls.G1Affine).FromJacobian(&sigma)
	res, _ := bls.PairingCheck([]bls.G1Affine{roMsg, sigmaAff}, []bls.G2Affine{vk, *new(bls.G2Affine).Neg(&gen2a)})

	return res
}

func getFSChal(val1 []bls.G2Jac, val2 []bls.G1Jac) fr.Element {
	n1 := len(val1)
	n2 := len(val2)
	hMsg := make([]byte, n1*48+n2*96)

	for i, v := range val1 {
		valAff := *new(bls.G2Affine).FromJacobian(&v)
		mBytes := valAff.Bytes()
		copy(hMsg[i*48:(i+1)*48], mBytes[:])
	}

	shift := n1 * 48
	for i, v := range val2 {
		valAff := *new(bls.G1Affine).FromJacobian(&v)
		mBytes := valAff.Bytes()
		copy(hMsg[shift+i*48:shift+(i+1)*48], mBytes[:])
	}

	hFunc := sha256.New()
	hFunc.Reset()
	return *new(fr.Element).SetBytes(hFunc.Sum(hMsg))
}

// Computing the Chaum-Pedersen Sigma protocol
func cpProve(pk bls.G2Jac, roMsg bls.G1Jac, sigma bls.G1Jac, sec fr.Element) Pf {
	var r fr.Element
	r.SetRandom()
	rInt := r.BigInt(&big.Int{})

	gr := *new(bls.G2Jac).ScalarMultiplication(&gen2, rInt)

	hmr := *new(bls.G1Jac).ScalarMultiplication(&roMsg, rInt)

	// c in scalar
	c := getFSChal([]bls.G2Jac{pk, gr}, []bls.G1Jac{roMsg, hmr})

	var z fr.Element

	// z = sk*c + r
	z.Mul(&c, &sec)
	z.Add(&z, &r)

	return Pf{c, z}
}

// Checks the correctness of the Chaum-Pedersen Proof
func cpVerify(pk bls.G2Jac, roMsg bls.G1Jac, sigma bls.G1Jac, pf Pf) bool {

	zInt := pf.z.BigInt(&big.Int{})
	cInt := pf.c.BigInt(&big.Int{})

	pkC := *new(bls.G2Jac).ScalarMultiplication(&pk, cInt)

	sigmaC := *new(bls.G1Jac).ScalarMultiplication(&sigma, cInt)

	// z . G in G1
	gZ := *new(bls.G2Jac).ScalarMultiplication(&gen2, zInt)

	// z. H(m) in G2
	hZ := *new(bls.G1Jac).ScalarMultiplication(&roMsg, zInt)

	// z.G - c.pk
	gZ = *gZ.SubAssign(&pkC)
	// z.H(m) - c.sigma
	hZ = *hZ.SubAssign(&sigmaC)

	cLocal := getFSChal([]bls.G2Jac{pk, gZ}, []bls.G1Jac{roMsg, hZ})

	return pf.c.Equal(&cLocal)
}
