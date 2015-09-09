package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class Set5Challenge39 {

    @Test
    public void testRSA() {
        KeyPair k = KeyPair.generate(3);

        BigInteger m = new BigInteger("42");
        BigInteger c = m.modPow(k.getE(), k.getN());
        BigInteger m2 = c.modPow(k.getD(), k.getN());
        assertEquals(m, m2);
    }

    @Test
    public void testRSAWithString() {
        KeyPair k = KeyPair.generate(3);

        CryptoBuffer m = new CryptoBuffer("this is my message");
        BigInteger c = new BigInteger(m.toHex(), 16).modPow(k.getE(), k.getN());
        CryptoBuffer m2 = new CryptoBuffer(c.modPow(k.getD(), k.getN()).toByteArray());
        assertEquals(m, m2);
    }

    private static class KeyPair {
        private final BigInteger n;
        private final BigInteger e;
        private final BigInteger d;

        public static KeyPair generate(long long_e) {
            Random r = new Random();
            BigInteger n = null, d = null;
            BigInteger e = BigInteger.valueOf(long_e);

            boolean tryAgain = true;
            while (tryAgain) {
                tryAgain = false;
                try {
                    BigInteger p = BigInteger.probablePrime(1024, r);
                    BigInteger q = BigInteger.probablePrime(1024, r);
                    n = p.multiply(q);
                    BigInteger p1 = p.subtract(BigInteger.ONE);
                    BigInteger q1 = q.subtract(BigInteger.ONE);
                    BigInteger et = p1.multiply(q1);
                    d = e.modInverse(et);
                } catch (ArithmeticException ignored) {
                    tryAgain = true;
                }
            }

            return new KeyPair(n, e, d);
        }

        public KeyPair(BigInteger n, BigInteger e, BigInteger d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }

        public BigInteger getN() {
            return n;
        }

        public BigInteger getE() {
            return e;
        }

        public BigInteger getD() {
            return d;
        }
    }
}
