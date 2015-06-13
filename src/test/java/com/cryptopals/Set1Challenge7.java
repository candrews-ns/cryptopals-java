package com.cryptopals;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * Created by candrews on 13/06/15.
 */
public class Set1Challenge7 {

    @Test
    public void decryptAes() throws Exception {
        CryptoBuffer ciphertext = CryptoBuffer.fromBase64(Utils.readFromClasspath("set1challenge7.txt"));
        CryptoBuffer key = new CryptoBuffer("YELLOW SUBMARINE");
        CryptoBuffer plaintext = ciphertext.decryptAesEcb(key);
        System.out.println(plaintext);
    }
}
