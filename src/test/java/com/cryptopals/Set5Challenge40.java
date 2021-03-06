package com.cryptopals;

import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class Set5Challenge40 {

    @Test
    public void testCubeRoot() {
        BigInteger i = new BigInteger("27");
        assertEquals(new BigInteger("3"), Utils.cubeRoot(i));
    }

    @Test
    public void breakE3RSA() {

        // create a plaintext and 3 RSA keypairs
        CryptoBuffer plaintext = Utils.bufferOfLength((byte) 'A', 128);
        RSA.KeyPair[] keys = {
                RSA.generateKeyPair(1024, 3),
                RSA.generateKeyPair(1024, 3),
                RSA.generateKeyPair(1024, 3)
        };

        // capture some things
        ArrayList<CryptoBuffer> ciphertexts = new ArrayList<>(3);
        ArrayList<BigInteger> publicKeys = new ArrayList<>(3);

        // encrypt the same plaintexts under the 3 different keys
        for (RSA.KeyPair key : keys) {
            ciphertexts.add(RSA.encrypt(key, plaintext));
            publicKeys.add(key.getN());
        }

        CryptoBuffer decrypt = runDecrypt(ciphertexts, publicKeys);
        assertEquals(plaintext, decrypt);
    }

    private CryptoBuffer runDecrypt(ArrayList<CryptoBuffer> ciphertexts, ArrayList<BigInteger> n) {

        // convert the ciphertexts back to BigInts
        ArrayList<BigInteger> c = new ArrayList<>(3);
        for (CryptoBuffer ciphertext : ciphertexts) {
            c.add(new BigInteger(ciphertext.toHex(), 16));
        }

        BigInteger ms0 = n.get(1).multiply(n.get(2));
        BigInteger ms1 = n.get(0).multiply(n.get(2));
        BigInteger ms2 = n.get(0).multiply(n.get(1));

        BigInteger result = BigInteger.ZERO;
        result = result.add(c.get(0).multiply(ms0).multiply(ms0.modInverse(n.get(0))));
        result = result.add(c.get(1).multiply(ms1).multiply(ms1.modInverse(n.get(1))));
        result = result.add(c.get(2).multiply(ms2).multiply(ms2.modInverse(n.get(2))));
        result = result.mod(n.get(0).multiply(n.get(1)).multiply(n.get(2)));
        result = Utils.cubeRoot(result);

        return new CryptoBuffer(result.toByteArray());
    }
}

