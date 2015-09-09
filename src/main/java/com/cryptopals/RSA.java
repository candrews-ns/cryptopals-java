package com.cryptopals;

import java.math.BigInteger;
import java.util.Random;

public class RSA {

    public static KeyPair generateKeyPair(int bits, int e) {
        return KeyPair.generate(bits, e);
    }

    public static CryptoBuffer encrypt(KeyPair k, CryptoBuffer plaintext) {
        BigInteger c = new BigInteger(plaintext.toHex(), 16).modPow(k.getE(), k.getN());
        return new CryptoBuffer(c.toByteArray());
    }

    public static CryptoBuffer decrypt(KeyPair k, CryptoBuffer ciphertext) {
        BigInteger c = new BigInteger(ciphertext.toHex(), 16);
        return new CryptoBuffer(c.modPow(k.getD(), k.getN()).toByteArray());
    }

    public static class KeyPair {
        private final BigInteger n;
        private final BigInteger e;
        private final BigInteger d;

        public static KeyPair generate(int bits, int int_e) {
            Random r = new Random();
            BigInteger n = null, d = null;
            BigInteger e = BigInteger.valueOf(int_e);

            boolean tryAgain = true;
            while (tryAgain) {
                tryAgain = false;
                try {
                    BigInteger p = BigInteger.probablePrime(bits, r);
                    BigInteger q = BigInteger.probablePrime(bits, r);
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
