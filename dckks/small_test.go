package dckks

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

func TestLite(t *testing.T) {

	var err error

	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.PN14QP438); err != nil {
		t.Fatal(err)
	}

	var tc *testContext
	if tc, err = genTestParams(params); err != nil {
		t.Fatal(err)
	}

	testRefreshDebug(tc, t)
	runtime.GC()

}

func newFixedTestVectorsAtScale(testContext *testContext, encryptor ckks.Encryptor, a, b complex128, scale float64) (values []complex128, plaintext *ckks.Plaintext, ciphertext *ckks.Ciphertext) {

	params := testContext.params

	logSlots := params.LogSlots()

	values = make([]complex128, 1<<logSlots)

	for i := 0; i < 1<<logSlots; i++ {
		values[i] = complex(float64(i), float64(i))
	}

	plaintext = testContext.encoder.EncodeNew(values, params.MaxLevel(), scale, params.LogSlots())

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	return values, plaintext, ciphertext
}

func testRefreshDebug(testCtx *testContext, t *testing.T) {

	encryptorPk0 := testCtx.encryptorPk0
	sk0Shards := testCtx.sk0Shards
	decryptorSk0 := testCtx.decryptorSk0
	params := testCtx.params

	t.Run(testString("Refresh", parties, params), func(t *testing.T) {

		var minLevel, logBound int
		var ok bool
		if minLevel, logBound, ok = GetMinimumLevelForBootstrapping(128, params.DefaultScale(), parties, params.Q()); ok != true || minLevel+1 > params.MaxLevel() {
			t.Skip("Not enough levels to ensure correcness and 128 security")
		}

		fmt.Println("DEBUG 3", minLevel, logBound, ok)

		type Party struct {
			*RefreshProtocol
			s     *rlwe.SecretKey
			share *RefreshShare
		}

		levelIn := minLevel
		levelOut := params.MaxLevel()

		RefreshParties := make([]*Party, parties)
		for i := 0; i < parties; i++ {
			p := new(Party)
			if i == 0 {
				p.RefreshProtocol = NewRefreshProtocol(params, logBound, 3.2)
			} else {
				p.RefreshProtocol = RefreshParties[0].RefreshProtocol.ShallowCopy()
			}

			p.s = sk0Shards[i]
			p.share = p.AllocateShare(levelIn, levelOut)
			RefreshParties[i] = p
		}

		P0 := RefreshParties[0]

		scale := params.DefaultScale()
		t.Run(fmt.Sprintf("atScale=%f", scale), func(t *testing.T) {
			coeffs, _, ciphertext := newFixedTestVectorsAtScale(testCtx, encryptorPk0, -1, 1, scale)

			fmt.Println("DEBUG 2", ciphertext.Value[0].Buff[:3])

			// Brings ciphertext to minLevel + 1
			testCtx.evaluator.DropLevel(ciphertext, ciphertext.Level()-minLevel-1)

			crp := P0.SampleCRP(levelOut, testCtx.crs)

			fmt.Println("DEBUG 4", RefreshParties[0].share.e2sShare.Value.Buff[:3])
			fmt.Println("DEBUG 5", RefreshParties[0].share.s2eShare.Value.Buff[:3])
			fmt.Println("DEBUG 6", crp.Buff[:3], ciphertext.Level())

			for i, p := range RefreshParties {

				fmt.Println(
					"DEBUG 6.5",
					i + 1,
					p.s.Value.Q.Buff[:3],
					p.s.Value.P.Buff[:3],
					p.s.Value.Q.Coeffs[0][:3],
					p.s.Value.P.Coeffs[0][:3],
					logBound,
					params.LogSlots(),
					ciphertext.Value[1].Buff[:3],
					ciphertext.Value[1].Coeffs[0][:3],
					ciphertext.Scale,
					crp.Buff[:3],
					crp.Coeffs[0][:3],
					p.share.e2sShare.Value.Buff[:3],
					p.share.s2eShare.Value.Buff[:3],
					p.share.e2sShare.Value.Coeffs[0][:3],
					p.share.s2eShare.Value.Coeffs[0][:3],
					len(p.share.e2sShare.Value.Coeffs),
					len(p.share.s2eShare.Value.Coeffs))

				p.GenShare(
					p.s,
					logBound,
					params.LogSlots(),
					ciphertext.Value[1],
					ciphertext.Scale,
					crp,
					p.share)

				fmt.Println("DEBUG 7", i + 1, p.share.e2sShare.Value.Buff[:3], p.share.s2eShare.Value.Buff[:3])

				if i > 0 {
					P0.AggregateShare(p.share, P0.share, P0.share)
				}
			}

			fmt.Println("DEBUG 8", P0.share.e2sShare.Value.Buff[:3], P0.share.s2eShare.Value.Buff[:3], len(P0.share.s2eShare.Value.Coeffs), len(P0.share.e2sShare.Value.Coeffs))

			P0.Finalize(ciphertext, params.LogSlots(), crp, P0.share, ciphertext)

			fmt.Println("DEBUG 9", ciphertext.Value[0].Coeffs[0][:3], ciphertext.Level())

			verifyTestVectors(testCtx, decryptorSk0, coeffs, ciphertext, t)
		})

	})
}
