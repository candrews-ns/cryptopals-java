package com.cryptopals;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

public class Set6Challenge43 {

    private DSA fixedParamsDSA() {
        BigInteger p = new BigInteger(
                "800000000000000089e1855218a0e7dac38136ffafa72eda7" +
                "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
                "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
                "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
                "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87" +
                "1a584471bb1",
                16
        );

        BigInteger q = new BigInteger("f4f47f05794b256174bba6e9b396a7707e563c5b", 16);

        BigInteger g = new BigInteger(
                "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119" +
                "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5" +
                "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047" +
                "0f5b64c36b625a097f1651fe775323556fe00b3608c887892" +
                "878480e99041be601a62166ca6894bdd41a7054ec89f756ba" +
                "9fc95302291",
                16
        );

        return new DSA(p, q, g);
    }

    @Test
    public void testDSA() {
        DSA dsa = fixedParamsDSA();
        CryptoBuffer m = new CryptoBuffer("hi mom");

        DSA.Keypair keypair = dsa.keygen();
        DSA.Signature sig = dsa.sign(m, keypair);
        assert(dsa.verify(m, keypair, sig));

        Random r = new Random();
        DSA.Signature badSig = new DSA.Signature(
                new BigInteger(dsa.N, r),
                new BigInteger(dsa.N, r)
        );
        assert(!dsa.verify(m, keypair, badSig));
    }

    @Test
    public void bruteForceKey() throws Exception {
        BigInteger y = new BigInteger(
                "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
                "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
                "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
                "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
                "bb283e6633451e535c45513b2d33c99ea17",
                16
        );
        DSA dsa = fixedParamsDSA();
        DSA.Signature sig = new DSA.Signature(
                new BigInteger("548099063082341131477253921760299949438196259240", 16),
                new BigInteger("857042759984254168557880549501802188789837994940", 16)
        );
        CryptoBuffer m = new CryptoBuffer(
                "For those that envy a MC it can be hazardous to your health\n" +
                "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
        );

        Assert.assertEquals(
                CryptoBuffer.fromHex("d2d0714f014a9784047eaeccf956520045c45265"),
                m.sha1()
        );

        CryptoBuffer keySha = CryptoBuffer.fromHex("0954edd5e0afe5542a4adf012611a91912a3ec16");

        BigInteger foundX = null;
        for (int k = 0; k < 2<<16; k++) {
            BigInteger x = recoverPrivateKey(dsa, sig, m, BigInteger.valueOf(k));
            CryptoBuffer SHAx = new CryptoBuffer(new CryptoBuffer(x.toByteArray()).toHex()).sha1();
            if (keySha.equals(SHAx)) {
                foundX = x;
                break;
            }
        }

        Assert.assertNotNull(foundX);
    }

    private BigInteger recoverPrivateKey(DSA dsa, DSA.Signature sig, CryptoBuffer m, BigInteger k) {

//          (s * k) - H(msg)
//      x = ----------------  mod q
//                  r

        BigInteger Hm = new BigInteger(m.sha1().toHex(), 16);
        return sig.s.multiply(k).subtract(Hm).divide(sig.r).mod(dsa.q);
    }
}
