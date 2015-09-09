package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class Set5Challenge39 {

    @Test
    public void testRawRSA() {
        RSA.KeyPair k = RSA.generateKeyPair(1024, 3);

        BigInteger m = new BigInteger("42");
        BigInteger c = m.modPow(k.getE(), k.getN());
        BigInteger m2 = c.modPow(k.getD(), k.getN());
        assertEquals(m, m2);
    }

    @Test
    public void testRSAWithString() {
        RSA.KeyPair k = RSA.generateKeyPair(1024, 3);

        CryptoBuffer m = new CryptoBuffer("this is my message");
        CryptoBuffer c = RSA.encrypt(k, m);
        CryptoBuffer m2 = RSA.decrypt(k, c);
        assertEquals(m, m2);
    }
}
