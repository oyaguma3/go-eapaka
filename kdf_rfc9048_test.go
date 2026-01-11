package eapaka

import (
	"bytes"
	"testing"
)

func TestRFC9048Vectors(t *testing.T) {
	vectors := []struct {
		name     string
		identity string
		netName  string
		autn     []byte
		ck       []byte
		ik       []byte
		expCk    []byte
		expIk    []byte
		expKEncr []byte
		expKAut  []byte
		expKRe   []byte
		expMSK   []byte
		expEMSK  []byte
	}{
		{
			name:     "case1",
			identity: "0555444333222111",
			netName:  "WLAN",
			autn:     h("bb52e91c747ac3ab2a5c23d15ee351d5"),
			ik:       h("9744871ad32bf9bbd1dd5ce54e3e2e5a"),
			ck:       h("5349fbe098649f948f5d2e973a81c00f"),
			expCk:    h("0093962d0dd84aa5684b045c9edffa04"),
			expIk:    h("ccfc230ca74fcc96c0a5d61164f5a76c"),
			expKEncr: h("766fa0a6c317174b812d52fbcd11a179"),
			expKAut:  h("0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea"),
			expKRe:   h("cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a"),
			expMSK:   h("67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"),
			expEMSK:  h("f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"),
		},
		{
			name:     "case2",
			identity: "0555444333222111",
			netName:  "HRPD",
			autn:     h("bb52e91c747ac3ab2a5c23d15ee351d5"),
			ik:       h("9744871ad32bf9bbd1dd5ce54e3e2e5a"),
			ck:       h("5349fbe098649f948f5d2e973a81c00f"),
			expCk:    h("3820f0277fa5f77732b1fb1d90c1a0da"),
			expIk:    h("db94a0ab557ef6c9ab48619ca05b9a9f"),
			expKEncr: h("05ad73ac915fce89ac77e1520d82187b"),
			expKAut:  h("5b4acaef62c6ebb8882b2f3d534c4b35277337a00184f20ff25d224c04be2afd"),
			expKRe:   h("3f90bf5c6e5ef325ff04eb5ef6539fa8cca8398194fbd00be425b3f40dba10ac"),
			expMSK:   h("87b321570117cd6c95ab6c436fb5073ff15cf85505d2bc5bb7355fc21ea8a75757e8f86a2b138002e05752913bb43b82f868a96117e91a2d95f526677d572900"),
			expEMSK:  h("c891d5f20f148a1007553e2dea555c9cb672e9675f4a66b4bafa027379f93aee539a5979d0a0042b9d2ae28bed3b17a31dc8ab75072b80bd0c1da612466e402c"),
		},
		{
			name:     "case3",
			identity: "0555444333222111",
			netName:  "WLAN",
			autn:     h("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"),
			ik:       h("b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"),
			ck:       h("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"),
			expCk:    h("cd4c8e5c68f57dd1d7d7dfd0c538e577"),
			expIk:    h("3ece6b705dbbf7dfc459a11280c65524"),
			expKEncr: h("897d302fa2847416488c28e20dcb7be4"),
			expKAut:  h("c40700e7722483ae3dc7139eb0b88bb558cb3081eccd057f9207d1286ee7dd53"),
			expKRe:   h("0a591a22dd8b5b1cf29e3d508c91dbbdb4aee23051892c42b6a2de66ea504473"),
			expMSK:   h("9f7dca9e37bb22029ed986e7cd09d4a70d1ac76d95535c5cac40a7504699bb8961a29ef6f3e90f183de5861ad1bedc81ce9916391b401aa006c98785a5756df7"),
			expEMSK:  h("724de00bdb9e568187be3fe746114557d5018779537ee37f4d3c6c738cb97b9dc651bc19bfadc344ffe2b52ca78bd8316b51dacc5f2b1440cb9515521cc7ba23"),
		},
		{
			name:     "case4",
			identity: "0555444333222111",
			netName:  "HRPD",
			autn:     h("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"),
			ik:       h("b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"),
			ck:       h("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"),
			expCk:    h("8310a71ce6f754889613da8f64d5fb46"),
			expIk:    h("5adf14360ae838192db23f6fcb7f8c76"),
			expKEncr: h("745e7439ba238f50fcac4d15d47cd1d9"),
			expKAut:  h("3e1d2aa4e677025cfd862a4be18361a13a645765571463df833a9759e8099879"),
			expKRe:   h("99da835e2ae82462576fe6516fad1f802f0fa1191655dd0a273da96d04e0fcd3"),
			expMSK:   h("c6d3a6e0ceea951eb20d74f32c3061d0680a04b0b086ee8700ace3e0b95fa02683c287beee44432294ff98af26d2cc783bace75c4b0af7fdfeb5511ba8e4cbd0"),
			expEMSK:  h("7fb56813838adafa99d140c2f198f6dacebfb6afee444961105402b508c7f363352cb2919644b50463e6a69354150147ae09cbc54b8a651d8787a6893ed8536d"),
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			ckPrime, ikPrime, err := DeriveCKPrimeIKPrime(tc.ck, tc.ik, tc.netName, tc.autn)
			if err != nil {
				t.Fatalf("derive CK'/IK' failed: %v", err)
			}
			if !bytes.Equal(ckPrime, tc.expCk) {
				t.Fatalf("CK' mismatch\nGot:  %x\nWant: %x", ckPrime, tc.expCk)
			}
			if !bytes.Equal(ikPrime, tc.expIk) {
				t.Fatalf("IK' mismatch\nGot:  %x\nWant: %x", ikPrime, tc.expIk)
			}

			keys := DeriveKeysAKAPrime(tc.identity, ckPrime, ikPrime)
			if !bytes.Equal(keys.K_encr, tc.expKEncr) {
				t.Fatalf("K_encr mismatch\nGot:  %x\nWant: %x", keys.K_encr, tc.expKEncr)
			}
			if !bytes.Equal(keys.K_aut, tc.expKAut) {
				t.Fatalf("K_aut mismatch\nGot:  %x\nWant: %x", keys.K_aut, tc.expKAut)
			}
			if !bytes.Equal(keys.K_re, tc.expKRe) {
				t.Fatalf("K_re mismatch\nGot:  %x\nWant: %x", keys.K_re, tc.expKRe)
			}
			if !bytes.Equal(keys.MSK, tc.expMSK) {
				t.Fatalf("MSK mismatch\nGot:  %x\nWant: %x", keys.MSK, tc.expMSK)
			}
			if !bytes.Equal(keys.EMSK, tc.expEMSK) {
				t.Fatalf("EMSK mismatch\nGot:  %x\nWant: %x", keys.EMSK, tc.expEMSK)
			}
		})
	}
}
