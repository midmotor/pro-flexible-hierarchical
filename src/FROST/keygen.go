package flexhi

import (
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
)

var str = "FROST"

type schnorr struct {
	value          *edwards25519.Point
	randomexponent *edwards25519.Point
	proof          *edwards25519.Scalar
}

func CreateSch(ID *edwards25519.Scalar, value *edwards25519.Point, secret *edwards25519.Scalar) *schnorr {

	k := CreateRandomScalar()
	randomexponent := new(edwards25519.Point).ScalarBaseMult(k)

	size := 32 + 5 + 32 + 32 + 32 // id.Byte + len(a) +  commit[0].Byte + value.Byte
	inputHash := make([]byte, 0, size)
	//start := time.Now()

	inputHash = append(inputHash, ID.Bytes()...)
	inputHash = append(inputHash, []byte(str)...)
	inputHash = append(inputHash, value.Bytes()...)
	inputHash = append(inputHash, randomexponent.Bytes()...)
	inputHash = append(inputHash, edwards25519.NewGeneratorPoint().Bytes()...)
	//duration := time.Since(start)
	//fmt.Println("dogru size", duration)
	cByte := sha512.Sum512(inputHash)

	c, _ := new(edwards25519.Scalar).SetUniformBytes(cByte[:])

	//proof = k-s*c
	proof := new(edwards25519.Scalar).Subtract(k, new(edwards25519.Scalar).Multiply(secret, c))

	return &schnorr{value, randomexponent, proof}
}

func (s *schnorr) Verify(fromID *edwards25519.Scalar) error {

	size := 32 + 5 + 32 + 32 + 32 // id.Byte + len(a) +  commit[0].Byte + value.Byte + G.Byte
	inputHash := make([]byte, 0, size)
	inputHash = append(inputHash, fromID.Bytes()...)
	inputHash = append(inputHash, []byte(str)...)
	inputHash = append(inputHash, s.value.Bytes()...)
	inputHash = append(inputHash, s.randomexponent.Bytes()...)
	inputHash = append(inputHash, edwards25519.NewGeneratorPoint().Bytes()...)

	cByte := sha512.Sum512(inputHash)

	c, _ := new(edwards25519.Scalar).SetUniformBytes(cByte[:])

	// proof.G + c.(s.G) =? k.G
	lhs1 := new(edwards25519.Point).ScalarBaseMult(s.proof)
	lhs2 := new(edwards25519.Point).ScalarMult(c, s.value)
	lhs := new(edwards25519.Point).Add(lhs1, lhs2)

	if lhs.Equal(s.randomexponent) == 1 {
		return nil
	} else {
		return errors.New("schnorr proof could not be proved.")
	}

}

type KeygenR1 struct {
	Com   []*edwards25519.Point
	Proof schnorr
}

type KeygenR2 struct {
	Secrets []*edwards25519.Scalar
}

type KeygenR3 struct {
	Public *edwards25519.Point
}

// BROADCAST
func CreateKeyGenR1(ownerID *edwards25519.Scalar, poly Polynomial) *KeygenR1 {
	return &KeygenR1{poly.Commit(), *CreateSch(ownerID, poly.Commit()[0], poly.Coefficients[0])}
}

// P2P
func CreateKeyGenR2(poly Polynomial, list []*edwards25519.Scalar) *KeygenR2 {
	return &KeygenR2{poly.EvaluateSecret(list)}
}

// BROADCAST
func CreateKeyGenR3(secret *edwards25519.Scalar) *KeygenR3 {
	return &KeygenR3{new(edwards25519.Point).ScalarBaseMult(secret)}
}

func Sscheck(ownerID *edwards25519.Scalar, sskey *edwards25519.Scalar, com []*edwards25519.Point, t int) error {
	if t != len(com) {
		return errors.New("the length of commitment is not equal to threshold")
	}
	exponent := make([]*edwards25519.Scalar, t)
	exponent[0] = IntToSc(1)

	temp := new(edwards25519.Scalar)
	*temp = *ownerID
	// exp[0] := 1, exp[1] := ID, exp[2] := ID^2, .........
	for i := 1; i < int(t); i++ {
		exponent[i] = edwards25519.NewScalar()
		*exponent[i] = *temp
		temp.Multiply(temp, ownerID)
		//fmt.Printf("%x", exponent[i].Bytes())

	}

	//fmt.Printf("\n")

	//fmt.Printf("EXPONENT")
	for i := 0; i < int(t); i++ {
		//fmt.Printf(" %x", exponent[i].Bytes())
	}

	//fmt.Printf("ownerID %x", ownerID.Bytes())

	out := com[0]
	term := edwards25519.NewIdentityPoint()
	for i := 1; i < int(t); i++ {
		//a_0*G  + a_1.x*G + a_2.x^2*G + .......
		term.ScalarMult(exponent[i], com[i])
		out.Add(out, term)
	}

	lhs := new(edwards25519.Point).ScalarBaseMult(sskey)

	if lhs.Equal(out) == 1 {
		return nil
	} else {
		return errors.New("the secret value sent by the participant and the commitment values did not match.")
	}
}
