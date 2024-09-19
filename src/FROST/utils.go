package flexhi

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
)

func IntToSc(t int) *edwards25519.Scalar {

	/*
		b = make([]byte, 32)
		scOneBytes := [32]byte{1}
		binary.LittleEndian.PutUint32(b, uint32(t))
		denem = edwards25519.NewScalar()
		x, _ = denem.SetCanonicalBytes(b)

		fmt.Println(b)
		fmt.Println(scOneBytes)
		fmt.Printf("%x", x.Bytes())
	*/

	varsc := [32]byte{uint8(t)}
	sc, _ := new(edwards25519.Scalar).SetCanonicalBytes(varsc[:])
	return sc
}

func CreateRandomScalar() *edwards25519.Scalar {

	var rnd [64]byte
	rand.Read(rnd[:])
	s1, _ := new(edwards25519.Scalar).SetUniformBytes(rnd[:])

	return s1
}

func Scalaradd(list []*edwards25519.Scalar) *edwards25519.Scalar {
	out := zero

	for i := 0; i < int(len(list)); i++ {
		out = new(edwards25519.Scalar).Add(out, list[i])
	}

	return out

}

func Pointadd(list []*edwards25519.Point) *edwards25519.Point {
	out := edwards25519.NewIdentityPoint()

	for i := 0; i < int(len(list)); i++ {
		out = new(edwards25519.Point).Add(out, list[i])
	}

	return out

}

func Lagrangecoefficient(thresholdIDlist []*edwards25519.Scalar, value *edwards25519.Scalar) []*edwards25519.Scalar {
	n := len(thresholdIDlist)
	lagranges := make([]*edwards25519.Scalar, n)

	for i := 0; i < n; i++ {
		temp := one

		for j := 0; j < n; j++ {
			if j != i {

				//fmt.Printf("mod %t \n", ec.Params().N)

				num := new(edwards25519.Scalar).Subtract(value, thresholdIDlist[j])

				//fmt.Printf(" num %t \n", num)

				den := new(edwards25519.Scalar).Subtract(thresholdIDlist[i], thresholdIDlist[j])

				//fmt.Printf(" denn %t \n", den)

				//numdivden, a1 := a.DivMod(num, den, ec.Params().N)
				//fmt.Printf(" a1 %t  \n", a1)
				invden := new(edwards25519.Scalar).Invert(den)
				numdivden := new(edwards25519.Scalar).Multiply(num, invden)
				//fmt.Printf(" numdivden %t  \n", numdivden)
				temp = new(edwards25519.Scalar).Multiply(temp, numdivden)
				//fmt.Printf(" temp %t \n", temp)
			}
		}
		lagranges[i] = temp
	}

	return lagranges
}

func Pointinterpole(rfrom []*edwards25519.Point, thresholdIDlist []*edwards25519.Scalar, t int, value *edwards25519.Scalar) (*edwards25519.Point, error) {

	if len(rfrom) != len(thresholdIDlist) {

		return nil, fmt.Errorf("the length of the values are incompatible.")

	}

	lagranges := Lagrangecoefficient(thresholdIDlist, value)

	out := new(edwards25519.Point).ScalarMult(lagranges[0], rfrom[0])

	//////////
	for i := 1; i < int(len(rfrom)); i++ {

		out = new(edwards25519.Point).Add(out, new(edwards25519.Point).ScalarMult(lagranges[i], rfrom[i]))

	}

	return out, nil
}

func Interpole(rfrom []*edwards25519.Scalar, thresholdIDlist []*edwards25519.Scalar, t int, value *edwards25519.Scalar) (*edwards25519.Scalar, error) {

	if len(rfrom) != len(thresholdIDlist) {

		return nil, fmt.Errorf("the length of the values are incompatible.")

	}

	lagranges := Lagrangecoefficient(thresholdIDlist, value)

	out := new(edwards25519.Scalar).Multiply(lagranges[0], rfrom[0])

	//////////
	for i := 1; i < int(len(rfrom)); i++ {

		out = new(edwards25519.Scalar).Add(out, new(edwards25519.Scalar).Multiply(lagranges[i], rfrom[i]))

	}

	return out, nil
}

var (
	zero  = IntToSc(0)
	one   = IntToSc(1)
	two   = IntToSc(2)
	three = IntToSc(3)
)

type Polynomial struct {
	Coefficients []*edwards25519.Scalar
	degree       int
}

func CreatePoly(secret *edwards25519.Scalar, degree int) (*Polynomial, error) {

	if secret.Equal(zero) == 1 {
		return nil, fmt.Errorf("secret cannot be 0")
	}

	coefficients := make([]*edwards25519.Scalar, degree+1)
	coefficients[0] = secret
	for i := 1; i < (degree + 1); i++ {
		coefficients[i] = CreateRandomScalar()
	}
	return &Polynomial{coefficients, degree}, nil
}

func CreatePolyZero(secret *edwards25519.Scalar, degree int) *Polynomial {

	coefficients := make([]*edwards25519.Scalar, degree+1)
	coefficients[0] = secret
	for i := 1; i < (degree + 1); i++ {
		coefficients[i] = CreateRandomScalar()
	}
	return &Polynomial{coefficients, degree}
}

func CreatePolyNon(degree int) (*Polynomial, error) {

	coefficients := make([]*edwards25519.Scalar, degree+1)

	for i := 0; i < (degree + 1); i++ {
		coefficients[i] = CreateRandomScalar()
	}

	return &Polynomial{coefficients, degree}, nil
}

func (p Polynomial) Evaluate(x *edwards25519.Scalar) *edwards25519.Scalar {
	// Horner method
	out := p.Coefficients[p.degree]
	for i := p.degree - 1; i >= 0; i-- {
		out = new(edwards25519.Scalar).Multiply(out, x)
		out = new(edwards25519.Scalar).Add(out, p.Coefficients[i])
	}
	return out
}

func (p Polynomial) Commit() []*edwards25519.Point {
	polycommit := make([]*edwards25519.Point, p.degree+1)
	for i := 0; i < int(p.degree+1); i++ {
		// polycommit_i = a_i*G
		polycommit[i] = new(edwards25519.Point).ScalarBaseMult(p.Coefficients[i])
	}
	//curve.Point.Generator().Mul(p.Coefficients[i])
	return polycommit
}

func (p Polynomial) EvaluateSecret(IDlist []*edwards25519.Scalar) []*edwards25519.Scalar {
	polyouts := make([]*edwards25519.Scalar, len(IDlist))

	for i := 0; i < len(IDlist); i++ {
		polyouts[i] = p.Evaluate(IDlist[i])
	}

	return polyouts
}

func printEq(a edwards25519.Point, b edwards25519.Point) {

	fmt.Printf("%d", a.Equal(&b))
}
