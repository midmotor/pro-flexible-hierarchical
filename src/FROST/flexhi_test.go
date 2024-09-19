package flexhi

import (
	"math"
	"testing"

	"filippo.io/edwards25519"
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
		{"32-32", 32, 30},
	}

	zero := IntToSc(0)

	for _, tc := range testCases {

		threshold := tc.degree + 1

		IDlist := make([]*edwards25519.Scalar, tc.n)
		tList := make([]*edwards25519.Scalar, threshold)

		for i := 0; i < tc.n; i++ {
			IDlist[i] = IntToSc(i + 1)
		}

		for i := 0; i < threshold; i++ {
			tList[i] = IntToSc(i + 1)
		}
		var secrets = make([]*edwards25519.Scalar, tc.n)
		var testPoint = make([]*edwards25519.Point, threshold)
		var masterPub *edwards25519.Point
		var keygenR1s = make([]*KeygenR1, tc.n)
		var keygenR3s = make([]*KeygenR3, tc.n)

		b.Run(tc.name+"-G2-Keygen", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				constants := make([]*edwards25519.Scalar, tc.n)
				polys := make([]*Polynomial, tc.n)
				//keygenR1s := make([]*KeygenR1, tc.n)
				keygenR2s := make([]*KeygenR2, tc.n)
				//secrets := make([]*edwards25519.Scalar, tc.n)
				//testPoint := make([]*edwards25519.Point, threshold)
				collects := make([][]*edwards25519.Scalar, tc.n)

				//keygenR3s := make([]*KeygenR3, tc.n)
				commits := make([]*edwards25519.Point, tc.n)

				for i := range collects {
					collects[i] = make([]*edwards25519.Scalar, tc.n)
				}

				for i := 0; i < tc.n; i++ {
					constants[i] = CreateRandomScalar()
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

				updateSecrets := make([][]*edwards25519.Scalar, tc.n-1)

				for i := range updateSecrets {
					updateSecrets[i] = make([]*edwards25519.Scalar, tc.n-1)
				}

				for i := 0; i < tc.n-1; i++ {
					updateSecrets[i] = zeroPolys[i].EvaluateSecret(IDlist)
				}

				// collecting simulation

				newUpdateSecret := make([]*edwards25519.Scalar, tc.n)

				for i := 0; i < tc.n-1; i++ {
					temp := zero
					for j := 0; j < tc.n-1; j++ {

						temp = new(edwards25519.Scalar).Add(temp, updateSecrets[j][i])
					}

					newUpdateSecret[i] = new(edwards25519.Scalar).Add(secrets[i], temp)
				}

				for i := 0; i < threshold; i++ {

					testPoint[i].ScalarBaseMult(newUpdateSecret[i])

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

				updateSecrets := make([][]*edwards25519.Scalar, tc.n-1)

				for i := range updateSecrets {
					updateSecrets[i] = make([]*edwards25519.Scalar, tc.n-1)
				}

				for i := 0; i < tc.n-1; i++ {
					updateSecrets[i] = zeroPolys[i].EvaluateSecret(IDlist)
				}

				// collecting simulation

				newUpdateSecret := make([]*edwards25519.Scalar, tc.n)

				for i := 0; i < tc.n-1; i++ {
					temp := zero
					for j := 0; j < tc.n-1; j++ {
						temp = new(edwards25519.Scalar).Add(temp, updateSecrets[j][i])
					}
					newUpdateSecret[i] = new(edwards25519.Scalar).Add(secrets[i], temp)
				}

				for i := 0; i < threshold; i++ {
					testPoint[i].ScalarBaseMult(newUpdateSecret[i])

				}

				updatePub, _ := Pointinterpole(testPoint, tList[:], threshold, zero)
				masterPub.Equal(updatePub)
			}
		})

		////////////// enrollment without change threshold
		var Lagranges0 = Lagrangecoefficient(IDlist, zero)
		var LagrangesNew = Lagrangecoefficient(tList, IntToSc(tc.n+1))
		b.Run(tc.name+"-G2-Enrollment", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				newPolys := make([]*Polynomial, tc.n)
				newSecretsMulLag := make([]*edwards25519.Scalar, tc.degree+1)
				newKeygenR2s := make([]*KeygenR2, tc.n)
				//	newKeygenR3s := make([]*KeygenR3, tc.n)
				newSecrets := make([]*edwards25519.Scalar, tc.n)
				newCollects := make([][]*edwards25519.Scalar, tc.n)
				newCollectsMulLag := make([][]*edwards25519.Scalar, tc.degree+1)

				for i := range newCollects {

					newCollects[i] = make([]*edwards25519.Scalar, tc.n)
				}

				for i := range newCollectsMulLag {
					newCollectsMulLag[i] = make([]*edwards25519.Scalar, tc.degree+1)

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
				exponents := make([][]*edwards25519.Scalar, threshold)
				for i := range exponents {
					exponents[i] = make([]*edwards25519.Scalar, threshold)

				}

				for i := 0; i < threshold; i++ {
					for j := 0; j < threshold; j++ {
						exponents[i][j] = IntToSc(int(math.Pow(float64(i+1), float64(j))))
					}

				}

				coms := make([][]*edwards25519.Point, threshold)
				for i := range exponents {
					coms[i] = make([]*edwards25519.Point, threshold)

				}

				for i := 0; i < threshold; i++ {
					coms[i] = newPolys[i].Commit()
				}

				for k := 0; k < threshold; k++ {

					for i := 0; i < threshold; i++ {

						temp := coms[i][0]
						for j := 1; j < threshold; j++ {

							temp.Add(temp, new(edwards25519.Point).ScalarMult(exponents[k][j], coms[i][j]))

						}
						new(edwards25519.Point).ScalarBaseMult(newCollects[k][i]).Equal(temp)
					}
				}

				for i := 0; i < threshold; i++ {
					for j := 0; j < threshold; j++ {
						newCollectsMulLag[i][j] = new(edwards25519.Scalar).Multiply(newCollects[i][j], LagrangesNew[j])
					}
				}

				for i := 0; i < threshold; i++ {
					newSecrets[i] = Scalaradd(newCollectsMulLag[i])
				}

				for i := 0; i < threshold; i++ {
					newSecretsMulLag[i] = new(edwards25519.Scalar).Multiply(newSecrets[i], Lagranges0[i])
				}

				newSecret := Scalaradd(newSecretsMulLag)
				_ = newSecret

			}

		})

		b.Run(tc.name+"-G2-ThChange", func(b *testing.B) {

			b.ResetTimer()
			testPoint2 := make([]*edwards25519.Point, tc.degree)
			for i := 0; i < b.N; i++ {
				zeroPolys := make([]*Polynomial, tc.n)
				// create polynomials with constant 0
				for i := 0; i < tc.n; i++ {
					zeroPolys[i] = CreatePolyZero(zero, tc.degree)
				}

				updateSecrets := make([][]*edwards25519.Scalar, tc.n)

				for i := range updateSecrets {
					updateSecrets[i] = make([]*edwards25519.Scalar, tc.n)
				}

				for i := 0; i < tc.n; i++ {
					updateSecrets[i] = zeroPolys[i].EvaluateSecret(IDlist)
				}

				// collecting simulation

				newUpdateSecret := make([]*edwards25519.Scalar, tc.n)

				for i := 0; i < tc.n; i++ {
					temp := zero
					for j := 0; j < tc.n; j++ {
						temp = new(edwards25519.Scalar).Add(temp, updateSecrets[j][i])

					}
					newUpdateSecret[i] = new(edwards25519.Scalar).Add(secrets[i], temp)
				}

				for i := 0; i < tc.degree; i++ {
					testPoint2[i] = new(edwards25519.Point).ScalarBaseMult(newUpdateSecret[i])
				}

				updatePub, _ := Pointinterpole(testPoint, tList[:], tc.degree, zero)
				masterPub.Equal(updatePub)
			}

		})

	}

}
