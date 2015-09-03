package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 02/09/15.
 */
public class Set5Challenge33 {

    @Test
    public void testDH() {
        Random r = new Random();
        DH.Params params = new DH.Params();

        BigInteger a = DH.generatePrivateKey(512, r);
        BigInteger A = DH.derivePublicKey(params.p, params.g, a);

        BigInteger b = DH.generatePrivateKey(512, r);
        BigInteger B = DH.derivePublicKey(params.p, params.g, b);

        BigInteger s1 = DH.deriveSessionKey(params.p, a, B);
        BigInteger s2 = DH.deriveSessionKey(params.p, b, A);
        assertEquals(s1, s2);
    }

    @Test
    public void testDHFixated() {
        Random r = new Random();
        DH.Params params = new DH.Params();

        BigInteger a = DH.generatePrivateKey(512, r);
        BigInteger A = DH.derivePublicKey(params.p, params.g, a);

        BigInteger b = DH.generatePrivateKey(512, r);
        BigInteger B = DH.derivePublicKey(params.p, params.g, b);

        // fixation by injection of p in place of public key
        BigInteger s1 = DH.deriveSessionKey(params.p, a, params.p);
        BigInteger s2 = DH.deriveSessionKey(params.p, b, params.p);

        assertEquals(BigInteger.ZERO, s1);
        assertEquals(BigInteger.ZERO, s2);
    }
}
