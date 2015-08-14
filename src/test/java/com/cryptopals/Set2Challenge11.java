package com.cryptopals;

import org.junit.Test;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

import static org.junit.Assert.assertEquals;

/**
 * Created by candrews on 14/08/15.
 */
public class Set2Challenge11 {

    private final static Random r = new Random();
    private static int ecbs = 0;

    @Test
    public void cbcEcbOracle() throws Exception {
        CryptoBuffer text = new CryptoBuffer("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        int ecbs_found = 0;
        for (int i = 0; i < 1000; i++) {
            CryptoBuffer ciphertext = encryptWithRandomKey(text);

            ArrayList<CryptoBuffer> chunks = ciphertext.chunked(16);
            HashMap<String, Boolean> chunkmap = new HashMap<>();

            for (CryptoBuffer chunk : chunks) {
                if (chunkmap.containsKey(chunk.toString())) {
                    ecbs_found++;
                    break;
                } else {
                    chunkmap.put(chunk.toString(), true);
                }
            }
        }
        assertEquals(ecbs, ecbs_found);
    }

    private CryptoBuffer encryptWithRandomKey(CryptoBuffer plaintext) {
        CryptoBuffer prepend = new CryptoBuffer("XXXXX").append(Utils.randomKey(r.nextInt(5)));
        CryptoBuffer append = new CryptoBuffer("YYYYY").append(Utils.randomKey(r.nextInt(5)));

        CryptoBuffer key = Utils.randomKey(16);
        CryptoBuffer text = prepend.append(plaintext).append(append);

        Cipher aes = Ciphers.aesCipher();
        SecretKey skey = key.asSecretKey("AES");
        try {
            aes.init(Cipher.ENCRYPT_MODE, skey);
        } catch (InvalidKeyException ignored) { }

        CryptoBuffer ciphertext = new CryptoBuffer();
        try {
            if (r.nextDouble() >= 0.5) {
                CryptoBuffer iv = new CryptoBuffer(new byte[16]);
                ciphertext = Modes.cbcEncrypt(aes, text, iv);
            } else {
                ecbs++;
                ciphertext = Modes.ecb(aes, text);
            }
        } catch (BadPaddingException | IllegalBlockSizeException ignored) { }

        return ciphertext;
    }

}
