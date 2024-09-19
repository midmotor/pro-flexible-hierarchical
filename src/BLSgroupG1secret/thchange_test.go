package bls

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func BenchmarkChange(b *testing.B) {

	testCases := []struct {
		name         string
		n, degree    int
		newthreshold int
	}{

		{"32-2-4", 32, 2, 3},
		{"32-2-8", 32, 2, 7},
		{"32-2-12", 32, 2, 11},
		{"32-2-16", 32, 2, 15},
		{"32-2-20", 32, 2, 19},
		{"32-2-24", 32, 2, 23},
		{"32-2-28", 32, 2, 27},
		{"32-2-32", 32, 2, 31},
	}
	zero := IntToSc(0)

	for _, tc := range testCases {

		threshold := tc.degree + 1

		IDlist := make([]fr.Element, tc.n)
		tList := make([]fr.Element, threshold)

		for i := 0; i < tc.n; i++ {
			IDlist[i] = IntToSc(i + 1)
		}

		for i := 0; i < threshold; i++ {
			tList[i] = IntToSc(i + 1)
		}
		var secrets = make([]fr.Element, tc.n)
		var testPoint = make([]groupP, threshold)
		var masterPub groupP
		var keygenR1s = make([]*KeygenR1, tc.n)
		var keygenR3s = make([]*KeygenR3, tc.n)

		b.Run(tc.name+"-G2-Keygen", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				constants := make([]fr.Element, tc.n)
				polys := make([]*Polynomial, tc.n)
				//keygenR1s := make([]*KeygenR1, tc.n)
				keygenR2s := make([]*KeygenR2, tc.n)
				//secrets := make([]fr.Element, tc.n)
				//testPoint := make([]groupP, threshold)
				collects := make([][]fr.Element, tc.n)

				//keygenR3s := make([]*KeygenR3, tc.n)
				commits := make([]groupP, tc.n)

				for i := range collects {
					collects[i] = make([]fr.Element, tc.n)
				}

				for i := 0; i < tc.n; i++ {
					constants[i].SetRandom()
					polys[i], _ = CreatePoly(constants[i], tc.degree)

					keygenR1s[i] = CreateKeyGenR1(IntToSc(i+1), *polys[i])
				}
				//end R1

				// check Proof, normally each participant check, but we check for just one for simplicity
				for i := 0; i < tc.n; i++ {
					keygenR1s[i].Proof.Verify(IntToSc(i + 1))
					//fmt.Printf("%t", keygenR1s[i].Proof.Verify(basic.IntToSc(i+1)))
				}

				//creates secrets
				for i := 0; i < tc.n; i++ {
					keygenR2s[i] = CreateKeyGenR2(*polys[i], IDlist)
				}
				//end R2

				//collects
				for i := 0; i < tc.n; i++ {
					for j := 0; j < tc.n; j++ {
						collects[i][j] = keygenR2s[j].Secrets[i]
					}
				}

				//check
				for i := 0; i < tc.n; i++ {
					for j := 0; j < tc.n; j++ {
						Sscheck(IntToSc(i+1), collects[i][j], polys[j].Commit(), threshold)
					}
				}

				//calculates secret
				for i := 0; i < tc.n; i++ {
					secrets[i] = Scalaradd(collects[i])
				}

				//calculates partial public keys
				for i := 0; i < tc.n; i++ {
					keygenR3s[i] = CreateKeyGenR3(secrets[i])
				}

				//collect Commit[0]
				for i := 0; i < tc.n; i++ {
					commits[i] = keygenR1s[i].Com[0]

				}
				//calculates partial public keys
				masterPub = Pointadd(commits)

				//testPoint
				for i := 0; i < threshold; i++ {
					testPoint[i] = keygenR3s[i].Public
				}

				masterPubPrime, _ := Pointinterpole(testPoint, tList[:], threshold, zero)
				masterPub.Equal(masterPubPrime)

			}
		})

		b.Run(tc.name+"-G2-ThChange", func(b *testing.B) {
			tList2 := make([]fr.Element, tc.newthreshold)

			for i := 0; i < tc.newthreshold; i++ {
				tList2[i] = IntToSc(i + 1)
			}
			b.ResetTimer()
			testPoint2 := make([]groupP, tc.newthreshold)
			for i := 0; i < b.N; i++ {
				zeroPolys := make([]*Polynomial, tc.n)
				// create polynomials with constant 0
				for i := 0; i < tc.n; i++ {
					zeroPolys[i] = CreatePolyZero(zero, tc.newthreshold)
				}

				updateSecrets := make([][]fr.Element, tc.n)

				for i := range updateSecrets {
					updateSecrets[i] = make([]fr.Element, tc.n)
				}

				for i := 0; i < tc.n; i++ {
					updateSecrets[i] = zeroPolys[i].EvaluateSecret(IDlist)
				}

				// collecting simulation

				newUpdateSecret := make([]fr.Element, tc.n)

				for i := 0; i < tc.n; i++ {
					temp := zero
					for j := 0; j < tc.n; j++ {
						temp.Add(&temp, &updateSecrets[j][i])

					}
					newUpdateSecret[i].Add(&secrets[i], &temp)
				}

				for i := 0; i < tc.newthreshold; i++ {
					testPoint2[i].ScalarMultiplication(&gen1a, newUpdateSecret[i].BigInt(&big.Int{}))

				}

				updatePub, _ := Pointinterpole(testPoint2, tList2[:], tc.newthreshold, zero)
				masterPub.Equal(updatePub)
			}

		})
	}

}
