package bls

import (
	"math"
	"math/big"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func BenchmarkTC(b *testing.B) {

	testCases := []struct {
		name      string
		n, degree int
	}{
		{"32-4", 32, 3},
		{"32-8", 32, 7},
		{"32-12", 32, 11},
		{"32-16", 32, 15},
		{"32-20", 32, 19},
		{"32-24", 32, 23},
		{"32-28", 32, 27},
		{"32-32", 32, 31},
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
		/////////////////////////////////////  update

		b.Run(tc.name+"-G2-Update", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zeroPolys := make([]*Polynomial, tc.n-1)
				// create polynomials with constant 0
				for i := 0; i < tc.n-1; i++ {
					zeroPolys[i] = CreatePolyZero(zero, tc.degree)
				}

				updateSecrets := make([][]fr.Element, tc.n-1)

				for i := range updateSecrets {
					updateSecrets[i] = make([]fr.Element, tc.n-1)
				}

				for i := 0; i < tc.n-1; i++ {
					updateSecrets[i] = zeroPolys[i].EvaluateSecret(IDlist)
				}

				// collecting simulation

				newUpdateSecret := make([]fr.Element, tc.n)

				for i := 0; i < tc.n-1; i++ {
					temp := zero
					for j := 0; j < tc.n-1; j++ {

						temp.Add(&temp, &updateSecrets[j][i])
					}
					newUpdateSecret[i].Add(&secrets[i], &temp)
				}

				for i := 0; i < threshold; i++ {

					testPoint[i].ScalarMultiplication(&gen2a, newUpdateSecret[i].BigInt(&big.Int{}))

				}

				updatePub, _ := Pointinterpole(testPoint, tList[:], threshold, zero)
				_ = updatePub
				masterPub.Equal(updatePub)
			}
		})

		///////////// disenrollment

		b.Run(tc.name+"-G2-Disenrollment", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zeroPolys := make([]*Polynomial, tc.n-1)
				// create polynomials with constant 0
				for i := 0; i < tc.n-1; i++ {
					zeroPolys[i] = CreatePolyZero(zero, tc.degree)
				}

				updateSecrets := make([][]fr.Element, tc.n-1)

				for i := range updateSecrets {
					updateSecrets[i] = make([]fr.Element, tc.n-1)
				}

				for i := 0; i < tc.n-1; i++ {
					updateSecrets[i] = zeroPolys[i].EvaluateSecret(IDlist)
				}

				// collecting simulation

				newUpdateSecret := make([]fr.Element, tc.n)

				for i := 0; i < tc.n-1; i++ {
					temp := zero
					for j := 0; j < tc.n-1; j++ {
						temp.Add(&temp, &updateSecrets[j][i])
					}
					newUpdateSecret[i].Add(&secrets[i], &temp)
				}

				for i := 0; i < threshold; i++ {
					testPoint[i].ScalarMultiplication(&gen2a, newUpdateSecret[i].BigInt(&big.Int{}))
					//testPoint[i] = suite.G2().Point().Mul(newUpdateSecret[i], nil)
				}

				updatePub, _ := Pointinterpole(testPoint, tList[:], threshold, zero)
				masterPub.Equal(updatePub)
			}
		})

		////////////// enrollment without change threshold
		var Lagranges0 = Lagrangecoefficient(tList, zero)
		var LagrangesNew = Lagrangecoefficient(IDlist, IntToSc(tc.n+1))
		b.Run(tc.name+"-G2-Enrollment", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				newPolys := make([]*Polynomial, tc.n)
				newSecretsMulLag := make([]fr.Element, tc.n)
				newKeygenR2s := make([]*KeygenR2, tc.n)
				//newKeygenR3s := make([]*KeygenR3, tc.n)
				newSecrets := make([]fr.Element, tc.n)
				newCollects := make([][]fr.Element, tc.n)
				newCollectsMulLag := make([][]fr.Element, tc.n)

				for i := range newCollects {
					newCollects[i] = make([]fr.Element, tc.n)
					newCollectsMulLag[i] = make([]fr.Element, tc.n)
				}

				//create new poly with newdegree
				for i := 0; i < tc.n; i++ {
					newPolys[i], _ = CreatePoly(secrets[i], tc.degree)
				}

				for i := 0; i < tc.n; i++ {
					newKeygenR2s[i] = CreateKeyGenR2(*newPolys[i], IDlist)
				}
				//end R2

				//collects
				for i := 0; i < tc.n; i++ {
					for j := 0; j < tc.n; j++ {
						newCollects[i][j] = newKeygenR2s[j].Secrets[i]
					}
				}

				exponents := make([][]fr.Element, threshold)
				for i := range exponents {
					exponents[i] = make([]fr.Element, threshold)

				}

				for i := 0; i < threshold; i++ {
					for j := 0; j < threshold; j++ {
						exponents[i][j] = IntToSc(int(math.Pow(float64(i+1), float64(j))))
					}

				}

				coms := make([][]bls.G2Affine, threshold)
				for i := range exponents {
					coms[i] = make([]bls.G2Affine, threshold)

				}

				for i := 0; i < threshold; i++ {
					coms[i] = newPolys[i].Commit()
				}

				for k := 0; k < threshold; k++ {

					for i := 0; i < threshold; i++ {

						temp := coms[i][0]
						for j := 1; j < threshold; j++ {

							temp.Add(&temp, new(bls.G2Affine).ScalarMultiplication(&coms[i][j], exponents[k][j].BigInt(&big.Int{})))

						}
						new(bls.G2Affine).ScalarMultiplication(&gen2a, newCollects[k][i].BigInt(&big.Int{})).Equal(&temp)
					}
				}
				/*

					exponents := make([]fr.Element, threshold)

					for i := 0; i < threshold; i++ {
						exponents[i] = IntToSc(int(math.Pow(float64(1), float64(i))))
					}
					coms := newPolys[0].Commit()

					temp := coms[0]
					for i := 1; i < threshold; i++ {
						temp.Add(&temp, new(bls.G2Affine).ScalarMultiplication(&coms[i], exponents[i].BigInt(&big.Int{})))
					}
					fmt.Printf("%t", new(bls.G2Affine).ScalarMultiplication(&gen2a, newCollects[0][0].BigInt(&big.Int{})).Equal(&temp))

							for i := 0; i < tc.n; i++ {

								new(bls.G2Affine).ScalarMultiplication(&gen2a, newCollects[0][0].BigInt(&big.Int{}))

							}
				*/
				for i := 0; i < threshold; i++ {
					for j := 0; j < threshold; j++ {
						newCollectsMulLag[i][j].Mul(&newCollects[i][j], &LagrangesNew[j])
					}
				}

				for i := 0; i < threshold; i++ {
					newSecrets[i] = Scalaradd(newCollectsMulLag[i])
				}

				for i := 0; i < threshold; i++ {
					newSecretsMulLag[i].Mul(&newSecrets[i], &Lagranges0[i])
				}

				/*
					//calculates partial public keys
					for i := 0; i < tc.n; i++ {
						newKeygenR3s[i] = CreateKeyGenR3(newSecrets[i])
					}
				*/
				// calculates shared value for new participant

				newSecret := Scalaradd(newSecretsMulLag)
				_ = newSecret

			}

		})

		b.Run(tc.name+"-G2-ThChange", func(b *testing.B) {

			b.ResetTimer()
			testPoint2 := make([]groupP, tc.degree)
			for i := 0; i < b.N; i++ {
				zeroPolys := make([]*Polynomial, tc.n)
				// create polynomials with constant 0
				for i := 0; i < tc.n; i++ {
					zeroPolys[i] = CreatePolyZero(zero, tc.degree)
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

				for i := 0; i < tc.degree; i++ {
					testPoint2[i].ScalarMultiplication(&gen2a, newUpdateSecret[i].BigInt(&big.Int{}))

				}

				updatePub, _ := Pointinterpole(testPoint, tList[:], tc.degree, zero)
				masterPub.Equal(updatePub)
			}

		})

		/*
			var sigmas1 = make([]bls.G1Jac, threshold)
			b.Run(tc.name+"-G2-Boldy1-Sign", func(b *testing.B) {

				sigmasAff := make([]bls.G1Affine, threshold)
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					for i := 0; i < len(tList); i++ {
						sigmas1[i] = PSign([]byte(msg), secrets[i])
						sigmasAff[i].FromJacobian(&sigmas1[i])
					}

					sigma, _ := PointinterpoleT(sigmasAff, tList, threshold, zero)
					_ = sigma
				}

			})

			b.Run(tc.name+"-G2-Boldy1-Verify", func(b *testing.B) {

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for i := 0; i < len(tList); i++ {
						PVerify([]byte(msg), sigmas1[i], keygenR3s[i].Public)
					}
				}

			})
		*/
		var sigmas2 = make([]bls.G1Jac, threshold)
		var proofs = make([]Pf, threshold)
		roMsgAf, _ := bls.HashToG1([]byte(msg), []byte("DST"))
		var roMsg = *new(bls.G1Jac).FromAffine(&roMsgAf)
		var sigma = new(bls.G1Affine)
		b.Run(tc.name+"-G2-Boldy2-PSignGen", func(b *testing.B) {
			sigmasAff := make([]bls.G1Affine, threshold)

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for i := 0; i < len(tList); i++ {
					sigmas2[i] = PSign([]byte(msg), secrets[i])
					proofs[i] = cpProve(*new(bls.G2Jac).FromAffine(&keygenR3s[i].Public), roMsg, sigmas2[i], secrets[i])
					sigmasAff[i].FromJacobian(&sigmas2[i])

				}

				sigma, _ := PointinterpoleT(sigmasAff, tList, threshold, zero)
				_ = sigma
			}

		})

		b.Run(tc.name+"-G2-Boldy2-PSignAgg and Sign Agg", func(b *testing.B) {

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for i := 0; i < len(tList); i++ {
					PVerify([]byte(msg), sigmas2[i], keygenR3s[i].Public)
					cpVerify(*new(bls.G2Jac).FromAffine(&keygenR3s[i].Public), roMsg, sigmas2[i], proofs[i])
				}
			}

		})

		b.Run(tc.name+"-G2-Boldy2-Verify", func(b *testing.B) {

			b.ResetTimer()
			PVerify([]byte(msg), *new(bls.G1Jac).FromAffine(sigma), masterPub)

		})
	}

}
