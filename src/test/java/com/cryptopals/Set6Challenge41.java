package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class Set6Challenge41 {

    @Test
    public void testServer() {
        Server s = new Server();
        CryptoBuffer plaintext = new CryptoBuffer("this is my message");

        CryptoBuffer ciphertext = s.encrypt(plaintext);
        CryptoBuffer plaintext2 = s.decrypt(ciphertext);
        assertEquals(plaintext, plaintext2);

        CryptoBuffer plaintext3 = s.decrypt(ciphertext);
        assertNull(plaintext3);
    }

    @Test
    public void unpaddedMessageRecoveryOracle() {
        Server s = new Server();
        CryptoBuffer plaintext = new CryptoBuffer("this is my message");

        // encrypt and decrypt the message, leaving a ciphertext the server will not decrypt
        CryptoBuffer ciphertext = s.encrypt(plaintext);
        s.decrypt(ciphertext);

        RSA.PublicKey pub = s.getPublicKey();
        BigInteger N = pub.getN();
        BigInteger E = pub.getE();

        // just choose "random" S to be 2
        BigInteger S = BigInteger.valueOf(2);

        // C' = ((S**E mod N) C) mod N
        BigInteger C = new BigInteger(ciphertext.toHex(), 16);
        BigInteger Cprime = S.modPow(E, N).multiply(C).mod(N);

        // decrypt C'
        CryptoBuffer plaintext2 = s.decrypt(new CryptoBuffer(Cprime.toByteArray()));
        BigInteger Pprime = new BigInteger(plaintext2.toHex(), 16);

        // P = P' / S mod N
        BigInteger P = Pprime.multiply(S.modInverse(N)).mod(N);
        CryptoBuffer plaintext3 = new CryptoBuffer(P.toByteArray());

        assertEquals(plaintext, plaintext3);
    }

    static class Server {
        private final RSA.KeyPair key;
        private final Set<CryptoBuffer> seen;

        public Server() {
            seen = new HashSet<>();
            key = RSA.generateKeyPair(512, 3);
        }

        public CryptoBuffer encrypt(CryptoBuffer plaintext) {
            return RSA.encrypt(key, plaintext);
        }

        public CryptoBuffer decrypt(CryptoBuffer ciphertext) {
            CryptoBuffer hash = ciphertext.sha256();
            if (this.seen.contains(hash)) {
                return null;
            }
            this.seen.add(hash);
            return RSA.decrypt(key, ciphertext);
        }

        public RSA.PublicKey getPublicKey() {
            return key.getPublicKey();
        }
    }
}
