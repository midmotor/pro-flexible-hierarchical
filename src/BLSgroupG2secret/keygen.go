package bls

import (
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var str = "flexhi"

type schnorr struct {
	value          groupP
	randomexponent groupP
	proof          fr.Element
}

func CreateSch(ID fr.Element, value groupP, secret fr.Element) *schnorr {

	k, _ := new(fr.Element).SetRandom()
	randomexponent := new(groupP).ScalarMultiplication(&gen2a, k.BigInt(&big.Int{}))

	size := 32 + 6 + 32 + 32 + 32 // id.Byte + len(a) +  commit[0].Byte + value.Byte
	inputHash := make([]byte, 0, size)
	IDm := ID.Bytes()
	valuem := value.Bytes()
	randomexponentm := randomexponent.Bytes()
	gm := gen2a.Bytes()

	inputHash = append(inputHash, IDm[:]...)
	inputHash = append(inputHash, []byte(str)...)
	inputHash = append(inputHash, valuem[:]...)
	inputHash = append(inputHash, randomexponentm[:]...)
	inputHash = append(inputHash, gm[:]...)

	cByte := sha512.Sum512(inputHash)

	c := new(fr.Element).SetBytes(cByte[:])

	//proof = k-s*c
	proof := new(fr.Element).Sub(k, new(fr.Element).Mul(&secret, c))

	return &schnorr{value, *randomexponent, *proof}
}

func (s *schnorr) Verify(fromID fr.Element) error {

	size := 32 + 6 + 32 + 32 + 32 // id.Byte + len(a) +  commit[0].Byte + value.Byte + G.Byte
	inputHash := make([]byte, 0, size)

	IDm := fromID.Bytes()
	valuem := s.value.Bytes()
	randomexponentm := s.randomexponent.Bytes()
	gm := gen2a.Bytes()

	inputHash = append(inputHash, IDm[:]...)
	inputHash = append(inputHash, []byte(str)...)
	inputHash = append(inputHash, valuem[:]...)
	inputHash = append(inputHash, randomexponentm[:]...)
	inputHash = append(inputHash, gm[:]...)

	cByte := sha512.Sum512(inputHash)

	c := new(fr.Element).SetBytes(cByte[:])

	// proof.G + c.(s.G) =? k.G
	lhs1 := new(groupP).ScalarMultiplication(&gen2a, s.proof.BigInt(&big.Int{}))
	lhs2 := new(groupP).ScalarMultiplication(&s.value, c.BigInt(&big.Int{}))
	lhs := new(groupP).Add(lhs1, lhs2)

	if lhs.Equal(&s.randomexponent) {
		return nil
	} else {
		return errors.New("schnorr proof could not be proved.")
	}

}

type KeygenR1 struct {
	Com   []groupP
	Proof schnorr
}

type KeygenR2 struct {
	Secrets []fr.Element
}

type KeygenR3 struct {
	Public groupP
}

// BROADCAST
func CreateKeyGenR1(ownerID fr.Element, poly Polynomial) *KeygenR1 {
	return &KeygenR1{poly.Commit(), *CreateSch(ownerID, poly.Commit()[0], poly.Coefficients[0])}
}

// P2P
func CreateKeyGenR2(poly Polynomial, list []fr.Element) *KeygenR2 {
	return &KeygenR2{poly.EvaluateSecret(list)}
}

// BROADCAST
func CreateKeyGenR3(secret fr.Element) *KeygenR3 {
	// suite.G2().Point().Mul(secret, nil)
	return &KeygenR3{*new(groupP).ScalarMultiplication(&gen2a, secret.BigInt(&big.Int{}))}

}

func Sscheck(ownerID fr.Element, sskey fr.Element, com []groupP, t int) error {

	if t != len(com) {
		return errors.New("the length of commitment is not equal to threshold")
	}
	exponent := make([]fr.Element, t)
	exponent[0] = IntToSc(1)

	temp := ownerID

	// exp[0] := 1, exp[1] := ID, exp[2] := ID^2, .........
	for i := 1; i < int(t); i++ {
		exponent[i] = temp

		temp.Mul(&temp, &ownerID)
		//fmt.Printf("%x", exponent[i].Bytes())

	}

	//fmt.Printf("\n")

	//fmt.Printf("EXPONENT")
	for i := 0; i < int(t); i++ {
		//fmt.Printf(" %x", exponent[i].Bytes())
	}

	//fmt.Printf("ownerID %x", ownerID.Bytes())

	out := com[0]
	term := new(groupP)
	for i := 1; i < int(t); i++ {
		//a_0*G  + a_1.x*G + a_2.x^2*G + .......

		term.ScalarMultiplication(&com[i], exponent[i].BigInt(&big.Int{}))
		//term.Mul(exponent[i], com[i])
		out.Add(&out, term)
	}

	lhs := new(groupP).ScalarMultiplication(&gen2a, sskey.BigInt(&big.Int{}))

	if lhs.Equal(&out) {
		return nil
	} else {
		return errors.New("the secret value sent by the participant and the commitment values did not match.")
	}
}
