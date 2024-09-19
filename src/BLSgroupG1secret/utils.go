package bls

import (
	"fmt"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	gen1, gen2, _, _ = bls.Generators()
	gen1a            bls.G1Affine
	gen2a            bls.G2Affine
)

type groupP = bls.G1Affine

func IntToSc(t int) fr.Element {

	sc := fr.NewElement(uint64(t))

	return sc
}

func Scalaradd(list []fr.Element) fr.Element {

	acc := fr.NewElement(0)

	for i := 0; i < int(len(list)); i++ {
		acc.Add(&acc, &list[i])
	}

	return acc

}

func Pointadd(list []groupP) groupP {

	acc := list[0]

	for i := 1; i < int(len(list)); i++ {
		acc.Add(&acc, &list[i])
	}

	return acc

}

func Lagrangecoefficient(thresholdIDlist []fr.Element, value fr.Element) []fr.Element {
	n := len(thresholdIDlist)
	lagranges := make([]fr.Element, n)

	for i := 0; i < n; i++ {
		temp := IntToSc(1)

		for j := 0; j < n; j++ {
			if j != i {

				num := new(fr.Element).Sub(&value, &thresholdIDlist[j])

				den := new(fr.Element).Sub(&thresholdIDlist[i], &thresholdIDlist[j])

				invden := new(fr.Element).Inverse(den)

				// suite.G2().Scalar().Mul(num, invden)
				numdivden := new(fr.Element).Mul(num, invden)
				//fmt.Printf(" numdivden %t  \n", numdivden)

				temp.Mul(&temp, numdivden)
				//temp = suite.G2().Scalar().Mul(temp, numdivden)

				//fmt.Printf(" temp %t \n", temp)
			}
		}
		lagranges[i] = temp
	}

	return lagranges
}

func Pointinterpole(rfrom []groupP, thresholdIDlist []fr.Element, t int, value fr.Element) (*groupP, error) {

	if len(rfrom) != len(thresholdIDlist) {

		return nil, fmt.Errorf("the length of the values are incompatible.")

	}

	lagranges := Lagrangecoefficient(thresholdIDlist, value)

	out := new(groupP).ScalarMultiplication(&rfrom[0], lagranges[0].BigInt(&big.Int{}))

	//////////
	for i := 1; i < int(len(rfrom)); i++ {
		out.Add(out, new(groupP).ScalarMultiplication(&rfrom[i], lagranges[i].BigInt(&big.Int{})))

		// out = suite.G2().Point().Add(out, suite.G2().Point().Mul(lagranges[i], rfrom[i]))

	}

	return out, nil
}

func Interpole(rfrom []fr.Element, thresholdIDlist []fr.Element, t int, value fr.Element) (*fr.Element, error) {

	if len(rfrom) != len(thresholdIDlist) {

		return nil, fmt.Errorf("the length of the values are incompatible")

	}

	lagranges := Lagrangecoefficient(thresholdIDlist, value)

	out := new(fr.Element).Mul(&rfrom[0], &lagranges[0])
	//out := suite.G2().Scalar().Mul(lagranges[0], rfrom[0])

	//////////
	for i := 1; i < int(len(rfrom)); i++ {
		out.Add(out, new(fr.Element).Mul(&rfrom[i], &lagranges[i]))
	}

	return out, nil
}

var (
	zero = IntToSc(0)
)

type Polynomial struct {
	Coefficients []fr.Element
	degree       int
}

func CreatePoly(secret fr.Element, degree int) (*Polynomial, error) {

	if secret.Equal(&zero) {
		return nil, fmt.Errorf("secret cannot be 0")
	}

	coefficients := make([]fr.Element, degree+1)
	coefficients[0] = secret
	for i := 1; i < (degree + 1); i++ {
		coefficients[i].SetRandom()
	}
	return &Polynomial{coefficients, degree}, nil
}

func CreatePolyZero(secret fr.Element, degree int) *Polynomial {

	coefficients := make([]fr.Element, degree+1)
	coefficients[0] = secret
	for i := 1; i < (degree + 1); i++ {
		coefficients[i].SetRandom()
	}
	return &Polynomial{coefficients, degree}
}

func CreatePolyNon(degree int) (*Polynomial, error) {
	coefficients := make([]fr.Element, degree+1)

	for i := 0; i < (degree + 1); i++ {
		coefficients[i].SetRandom()
	}

	return &Polynomial{coefficients, degree}, nil
}

func (p Polynomial) Evaluate(x fr.Element) fr.Element {
	// Horner method

	out := p.Coefficients[p.degree]
	for i := p.degree - 1; i >= 0; i-- {
		out.Mul(&out, &x)
		out.Add(&out, &p.Coefficients[i])

	}
	return out
}

func (p Polynomial) Commit() []groupP {
	gen1a.FromJacobian(&gen1)
	polycommit := make([]groupP, p.degree+1)
	for i := 0; i < int(p.degree+1); i++ {
		// polycommit_i = a_i*G
		//polycommit[i].ScalarMultiplication(gen1. , p.Coefficients[i].BigInt(&big.Int{}))
		polycommit[i].ScalarMultiplication(&gen1a, p.Coefficients[i].BigInt(&big.Int{}))
		//polycommit[i] = suite.G2().Point().Mul(p.Coefficients[i], nil)

	}
	//curve.Point.Generator().Mul(p.Coefficients[i])
	return polycommit
}

func (p Polynomial) EvaluateSecret(IDlist []fr.Element) []fr.Element {
	polyouts := make([]fr.Element, len(IDlist))

	for i := 0; i < len(IDlist); i++ {
		polyouts[i] = p.Evaluate(IDlist[i])
	}

	return polyouts
}

func PointinterpoleT(rfrom []bls.G2Affine, thresholdIDlist []fr.Element, t int, value fr.Element) (*bls.G2Affine, error) {

	if len(rfrom) != len(thresholdIDlist) {

		return nil, fmt.Errorf("the length of the values are incompatible.")

	}

	lagranges := Lagrangecoefficient(thresholdIDlist, value)

	out := new(bls.G2Affine).ScalarMultiplication(&rfrom[0], lagranges[0].BigInt(&big.Int{}))

	//////////
	for i := 1; i < int(len(rfrom)); i++ {
		out.Add(out, new(bls.G2Affine).ScalarMultiplication(&rfrom[i], lagranges[i].BigInt(&big.Int{})))

		// out = suite.G2().Point().Add(out, suite.G2().Point().Mul(lagranges[i], rfrom[i]))

	}

	return out, nil
}
